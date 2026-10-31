package com.zifang.z.security.web;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.zifang.z.security.core.domain.SecurityPolicy;
import com.zifang.z.security.core.mapper.SecurityPolicyMapper;
import com.zifang.z.security.core.service.PersistentPolicyStore;
import com.zifang.z.security.core.service.PolicyLedgerService;
import com.zifang.z.security.core.service.SecurityPolicyRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 策略台账端点验收（**真起 Spring 上下文 + H2 真落库**）。
 *
 * <p>核心验收项：
 * <ul>
 *   <li>发布 ⇒ 落库 + **热改立即生效**（不用发版，策略就变了）；</li>
 *   <li>回滚 ⇒ 以新版本号重新发布老内容，**历史一条不丢**；</li>
 *   <li>操作人 / 变更原因为空 ⇒ **服务端直接拒绝**（不靠调用方自觉）。</li>
 * </ul>
 *
 * @author zifang
 */
@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {
                "z.base.db.security.url=jdbc:h2:mem:zsec_policy_e2e;MODE=MySQL;DB_CLOSE_DELAY=-1",
                "z.base.db.security.username=sa",
                "z.base.db.security.password="
        })
class PolicyLedgerApiE2ETest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Autowired
    private TestRestTemplate rest;

    @Autowired
    private DataSource dataSourceSecurity;

    @Autowired
    private SecurityPolicyMapper policyMapper;

    @BeforeEach
    void applySchema() throws Exception {
        SecurityTestSchema.apply(dataSourceSecurity);
    }

    @Test
    @DisplayName("发布：★ 落库 + 热改立即生效（不用发版策略就变了）")
    void publishPersistsAndTakesEffect() throws Exception {
        ResponseEntity<String> r = publish("P_E2E", "E2E_SCENE", "L3", "op-1", "首次发布");

        assertTrue(r.getStatusCode().is2xxSuccessful(), "状态码：" + r.getStatusCode());
        JsonNode node = MAPPER.readTree(r.getBody());
        assertTrue(node.get("ok").asBoolean());
        assertTrue(node.get("applied").asBoolean(), "应已热改生效");

        // 落库核验
        assertEquals(1, countRows("SELECT COUNT(*) FROM z_security_policy "
                + "WHERE policy_id = 'P_E2E'"));

        // 生效核验：跑流水线看策略 ID
        ResponseEntity<String> policies = rest.getForEntity(
                "/z-team/api/security/policies?scene=E2E_SCENE", String.class);
        JsonNode p = MAPPER.readTree(policies.getBody()).get("policy");
        assertEquals("P_E2E", p.get("policyId").asText(), "应查得到新发布的策略");
        assertEquals("L3", p.get("blockThreshold").asText());
    }

    @Test
    @DisplayName("发布：★ 操作人为空 ⇒ 400 拒绝（不落库）")
    void publishRequiresOperator() throws Exception {
        ResponseEntity<String> r = publish("P_NOOP", "NOOP_SCENE", "L3", "", "理由");

        assertEquals(400, r.getStatusCode().value());
        JsonNode node = MAPPER.readTree(r.getBody());
        assertFalse(node.get("ok").asBoolean());
        assertTrue(node.get("message").asText().contains("操作人"));
        assertEquals(0, countRows("SELECT COUNT(*) FROM z_security_policy "
                + "WHERE policy_id = 'P_NOOP'"), "被拒的发布不应落库");
    }

    @Test
    @DisplayName("发布：★ 变更原因为空 ⇒ 400 拒绝")
    void publishRequiresReason() throws Exception {
        ResponseEntity<String> r = publish("P_NORSN", "NORSN_SCENE", "L3", "op-1", "");

        assertEquals(400, r.getStatusCode().value());
        assertEquals(0, countRows("SELECT COUNT(*) FROM z_security_policy "
                + "WHERE policy_id = 'P_NORSN'"));
    }

    @Test
    @DisplayName("发布：★ 同一场景一版生效（旧版自动 SUPERSEDED）")
    void publishSupersedesPrevious() throws Exception {
        publish("P_SUP", "SUP_SCENE", "L4", "op-1", "v1");
        publish("P_SUP", "SUP_SCENE", "L3", "op-2", "v2 收紧");

        assertEquals(1, countRows("SELECT COUNT(*) FROM z_security_policy "
                + "WHERE policy_id = 'P_SUP' AND status = 'PUBLISHED'"),
                "同一场景只能有一版 PUBLISHED");
        assertEquals(2, countRows("SELECT COUNT(*) FROM z_security_policy "
                + "WHERE policy_id = 'P_SUP'"), "两版历史都在");
    }

    @Test
    @DisplayName("回滚：★ 以新版本号重新发布老内容（版本号不倒流、历史不丢）")
    void rollbackCreatesNewRevision() throws Exception {
        publish("P_RB", "RB_SCENE", "L4", "op-1", "v1");
        publish("P_RB", "RB_SCENE", "L3", "op-2", "v2");

        ResponseEntity<String> r = rest.exchange(
                "/z-team/api/security/policy/rollback?policyId=P_RB&revision=1"
                        + "&operator=op-3&reason=%E6%94%B9%E9%94%99%E4%BA%86",
                HttpMethod.POST, null, String.class);

        assertTrue(r.getStatusCode().is2xxSuccessful(), "状态码：" + r.getStatusCode());
        JsonNode node = MAPPER.readTree(r.getBody());
        assertTrue(node.get("ok").asBoolean());

        // ★ 版本号 3（不是倒回 1）
        assertEquals(3, countRows("SELECT COUNT(*) FROM z_security_policy "
                + "WHERE policy_id = 'P_RB'"), "三版都在");
        assertEquals(1, countRows("SELECT COUNT(*) FROM z_security_policy "
                + "WHERE policy_id = 'P_RB' AND revision = 3 AND status = 'PUBLISHED'"));
        // 生效内容回到 rev1 的 L4
        ResponseEntity<String> policies = rest.getForEntity(
                "/z-team/api/security/policies?scene=RB_SCENE", String.class);
        JsonNode p = MAPPER.readTree(policies.getBody()).get("policy");
        assertEquals("L4", p.get("blockThreshold").asText());
    }

    @Test
    @DisplayName("台账查询：★ 全量版本可见（含变更原因与操作人）")
    void ledgerListsAllRevisions() throws Exception {
        publish("P_LED", "LED_SCENE", "L3", "op-1", "首版");

        ResponseEntity<String> r = rest.getForEntity(
                "/z-team/api/security/policy/ledger?policyId=P_LED", String.class);

        assertTrue(r.getStatusCode().is2xxSuccessful());
        JsonNode node = MAPPER.readTree(r.getBody());
        assertTrue(node.get("ok").asBoolean());
        assertEquals(1, node.get("total").asInt());
        JsonNode rev = node.get("revisions").get(0);
        assertEquals("P_LED", rev.get("policyId").asText());
        assertEquals("PUBLISHED", rev.get("status").asText());
        assertEquals("op-1", rev.get("operatorId").asText());
        assertEquals("首版", rev.get("changeReason").asText());
    }

    @Test
    @DisplayName("停用：★ 该场景不再有生效策略 ⇒ 走兜底")
    void disableRemovesPublishedPolicy() throws Exception {
        publish("P_DIS", "DIS_SCENE", "L3", "op-1", "发布");

        ResponseEntity<String> r = rest.exchange(
                "/z-team/api/security/policy/disable?policyId=P_DIS"
                        + "&operator=op-2&reason=%E4%B8%8B%E7%BA%BF",
                HttpMethod.POST, null, String.class);

        assertTrue(r.getStatusCode().is2xxSuccessful());
        assertEquals(0, countRows("SELECT COUNT(*) FROM z_security_policy "
                + "WHERE policy_id = 'P_DIS' AND status = 'PUBLISHED'"));
    }

    @Test
    @DisplayName("DDL 幂等：建三遍不报错")
    void ddlIsIdempotent() throws Exception {
        SecurityTestSchema.apply(dataSourceSecurity);
        SecurityTestSchema.apply(dataSourceSecurity);
        SecurityTestSchema.apply(dataSourceSecurity);
    }

    @Test
    @DisplayName("★ 启动装载：★ 改完策略重启 ⇒ 策略不丢（台账是唯一权威源）")
    void policySurvivesRestart() throws Exception {
        publish("P_RESTART", "RESTART_SCENE", "L4", "op-1", "改成 L4");

        // 模拟重启：**新建**台账服务与注册表（走同一张真表）⇒ 走一遍启动装载
        SecurityPolicyRegistry restarted =
                new SecurityPolicyRegistry(SecurityPolicyRegistry.builtinDefault());
        new PolicyLedgerService(new PersistentPolicyStore(policyMapper)).bootstrap(restarted);

        // ★ 重启后读到的是台账里的 L4，不是内置默认值
        SecurityPolicy effective = restarted.resolve("RESTART_SCENE");
        assertNotNull(effective, "重启后应从台账读到策略");
        assertEquals("L4", effective.getBlockThreshold(), "重启后应读到台账里的 L4");
    }

    @Test
    @DisplayName("★ 启动装载：台账为空 ⇒ 播种内置策略（5 个场景）")
    void bootstrapSeedsBuiltinPolicies() throws Exception {
        SecurityPolicyRegistry registry =
                new SecurityPolicyRegistry(SecurityPolicyRegistry.builtinDefault());

        int n = new PolicyLedgerService(new PersistentPolicyStore(policyMapper))
                .bootstrap(registry);

        assertEquals(5, n, "内置 5 场景应被播种");
        assertEquals(5, countRows("SELECT COUNT(*) FROM z_security_policy "
                + "WHERE status = 'PUBLISHED'"));
    }

    // ---------------- 工具 ----------------

    /** 发布一版策略。 */
    private ResponseEntity<String> publish(String policyId, String scene, String threshold,
                                           String operator, String reason) throws Exception {
        String body = "{\"policyId\":\"" + policyId + "\",\"scene\":\"" + scene + "\","
                + "\"stages\":[\"SENSE\",\"MASK\",\"WATERMARK\",\"AUDIT\"],"
                + "\"watermarkType\":\"VISIBLE_TEXT\","
                + "\"blockThreshold\":\"" + threshold + "\","
                + "\"operatorId\":\"" + operator + "\","
                + "\"changeReason\":\"" + reason + "\"}";
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        return rest.exchange("/z-team/api/security/policy/publish", HttpMethod.POST,
                new HttpEntity<>(body, headers), String.class);
    }

    /** 统计行数。 */
    private int countRows(String sql) throws Exception {
        try (Connection conn = dataSourceSecurity.getConnection();
             Statement st = conn.createStatement();
             ResultSet rs = st.executeQuery(sql)) {
            return rs.next() ? rs.getInt(1) : 0;
        }
    }
}
