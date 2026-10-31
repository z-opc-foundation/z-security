package com.zifang.z.security.web;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 安全流水线端点验收（**真起 Spring 上下文**）。
 *
 * <p>验证「业务方只报场景码 ⇒ 本域按策略处理」这条对外契约：
 * <ol>
 *   <li>{@code CONTRACT_VIEW} ⇒ 只脱敏，不拦不水印；</li>
 *   <li>{@code CONTRACT_EXPORT} ⇒ 脱敏 + 显式水印 + L3 起拦；</li>
 *   <li>命中 L3/L4 ⇒ HTTP 403（业务方据此拒绝出域）；</li>
 *   <li>策略查询端点能报出内置场景。</li>
 * </ol>
 *
 * @author zifang
 */
@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {
                "z.base.db.security.url=jdbc:h2:mem:zsec_e2e;MODE=MySQL;DB_CLOSE_DELAY=-1",
                "z.base.db.security.username=sa",
                "z.base.db.security.password="
        })
class SecurityPipelineApiE2ETest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** 校验位通过的身份证（L3）。 */
    private static final String ID_CARD = "110101199003078515";
    /** Luhn 通过的银行卡（L4）。 */
    private static final String BANK_CARD = "6222020200011122336";

    @Autowired
    private TestRestTemplate rest;

    @Test
    @DisplayName("内部查看场景：只脱敏 ⇒ 敏感内容被遮蔽、无水印、不拦")
    void contractViewOnlyMasks() throws Exception {
        ResponseEntity<String> r = process("CONTRACT_VIEW", "客户身份证 " + ID_CARD, "op-1");

        assertTrue(r.getStatusCode().is2xxSuccessful(), "状态码：" + r.getStatusCode());
        JsonNode node = MAPPER.readTree(r.getBody());
        String content = node.get("result").get("content").asText();
        assertFalse(content.contains(ID_CARD), "身份证应被遮蔽：" + content);
        assertFalse(content.contains("【水印："), "查看场景不该加水印：" + content);
        assertEquals("MASKED", node.get("result").get("status").asText());
    }

    @Test
    @DisplayName("导出场景：脱敏 + 显式水印（用 L2 数据，避免被 L3 阈值拦）")
    void contractExportMasksAndWatermarks() throws Exception {
        // ⚠ 导出场景阈值 = L3 ⇒ 身份证（L3）会被拦。
        //    这里用 **L2 详细地址** 验证「脱敏 + 水印」两件事同时生效。
        ResponseEntity<String> r = process("CONTRACT_EXPORT", "收货地址 北京市朝阳区建国路88号 合同正文", "op-1");

        assertTrue(r.getStatusCode().is2xxSuccessful(), "状态码：" + r.getStatusCode());
        JsonNode node = MAPPER.readTree(r.getBody());
        String content = node.get("result").get("content").asText();
        assertFalse(content.contains("建国路88号"), "地址应被遮蔽：" + content);
        assertTrue(content.contains("【水印："), "导出场景应加显式水印：" + content);
    }

    @Test
    @DisplayName("导出场景：命中 L3 ⇒ HTTP 403 且不外泄原文")
    void contractExportBlocksL3() throws Exception {
        ResponseEntity<String> r = process("CONTRACT_EXPORT", "客户身份证 " + ID_CARD, "op-1");

        assertEquals(403, r.getStatusCode().value(), "命中 L3 应被拦");
        JsonNode node = MAPPER.readTree(r.getBody());
        assertEquals("BLOCKED", node.get("result").get("status").asText());
        assertFalse(r.getBody().contains(ID_CARD), "拦截时不得外泄原文");
    }

    @Test
    @DisplayName("导出场景：命中 L4（银行卡）⇒ 也被拦")
    void contractExportBlocksL4() throws Exception {
        ResponseEntity<String> r = process("CONTRACT_EXPORT", "银行卡号 " + BANK_CARD, "op-1");

        assertEquals(403, r.getStatusCode().value());
    }

    @Test
    @DisplayName("未登记场景 ⇒ 走兜底策略（全流水线 + L4 拦截）")
    void unknownSceneFallsBack() throws Exception {
        ResponseEntity<String> r = process("不存在的场景", "普通文本", "op-1");

        assertTrue(r.getStatusCode().is2xxSuccessful());
        JsonNode node = MAPPER.readTree(r.getBody());
        assertEquals("DEFAULT", node.get("policyId").asText());
    }

    @Test
    @DisplayName("策略查询端点：报出内置场景与阈值")
    void policiesEndpoint() throws Exception {
        ResponseEntity<String> r = rest.getForEntity(
                "/z-team/api/security/policies?scene=CONTRACT_EXPORT", String.class);

        assertTrue(r.getStatusCode().is2xxSuccessful());
        JsonNode node = MAPPER.readTree(r.getBody());
        assertEquals("P_EXPORT", node.get("policy").get("policyId").asText());
        assertEquals("L3", node.get("policy").get("blockThreshold").asText());
        assertTrue(node.get("scenes").size() >= 5, "内置场景应有 5 个");
    }

    @Test
    @DisplayName("场景列表端点：内置 5 个场景")
    void scenesEndpoint() throws Exception {
        ResponseEntity<String> r = rest.getForEntity("/z-team/api/security/scenes", String.class);

        assertTrue(r.getStatusCode().is2xxSuccessful());
        JsonNode node = MAPPER.readTree(r.getBody());
        assertEquals(5, node.get("scenes").size());
    }

    @Test
    @DisplayName("健康检查可路由")
    void healthEndpoint() {
        // ⚠ 健康检查走 {@code /api/security/health}（**无 /z-team 前缀**）——
        //    探活路径不带业务前缀，与业务端点分开。
        ResponseEntity<String> r = rest.getForEntity("/api/security/health", String.class);

        assertTrue(r.getStatusCode().is2xxSuccessful(), "状态码：" + r.getStatusCode());
    }

    // ---------------- 辅助 ----------------

    private ResponseEntity<String> process(String scene, String text, String operatorId) {
        String body = "{\"scene\":\"" + scene + "\",\"text\":\"" + text
                + "\",\"operatorId\":\"" + operatorId + "\",\"tenantId\":\"t-9\","
                + "\"bizNo\":\"B-1\",\"traceId\":\"trace-1\",\"timestamp\":1767225600000}";
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        return rest.exchange("/z-team/api/security/process", HttpMethod.POST,
                new HttpEntity<>(body, headers), String.class);
    }
}
