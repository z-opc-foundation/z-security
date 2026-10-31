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
import org.junit.jupiter.api.BeforeEach;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ★★ 编排层溯源闭环验收（**真起 Spring 上下文 + H2 真落库**，M2 #22）。
 *
 * <p><b>覆盖五个验收项</b>：
 * <ol>
 *   <li>跑一次导出场景 ⇒ 台账里<b>真有两条行</b>：水印溯源行（{@code WM:}）
 *       与处理审计行（{@code SEC:}）⇒ 不重复记账、也不漏留痕；</li>
 *   <li>★ <b>水印溯源行不再是缺口</b>（早先恒为「未配置溯源台账出口」）；</li>
 *   <li>按追踪码反查 ⇒ 200，查得到操作人 / 租户 / 单号；</li>
 *   <li>★ 反查响应含 {@code trace} 单条视图（跨域契约）；</li>
 *   <li>查不到 ⇒ 404（合规缺口，不是 503）。</li>
 * </ol>
 *
 * @author zifang
 */
@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {
                "z.base.db.security.url=jdbc:h2:mem:zsec_trace_e2e;MODE=MySQL;DB_CLOSE_DELAY=-1",
                "z.base.db.security.username=sa",
                "z.base.db.security.password="
        })
class SecurityTraceClosureE2ETest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** 详情地址（L2）—— 避免被 L3 阈值拦。 */
    private static final String ADDRESS = "收货地址 北京市朝阳区建国路88号 合同正文";

    @Autowired
    private TestRestTemplate rest;

    @Autowired
    private DataSource dataSourceSecurity;

    @BeforeEach
    void applySchema() throws Exception {
        // ⚠ 建表口径与其它 E2E 一致：读生产 DDL（含 z_audit_event 副本）
        //    —— 编排层跑完流水线要写水印溯源行，没这张表就「打了水印没留痕」。
        SecurityTestSchema.apply(dataSourceSecurity);
    }

    // ---------------- 两条行都在 ----------------

    @Test
    @DisplayName("★ 导出场景 ⇒ 台账里**两条行都在**：水印溯源行 WM: + 处理审计行 SEC:")
    void bothRowsArePersisted() throws Exception {
        String traceId = processExport("trace-both-1");

        try (Connection conn = dataSourceSecurity.getConnection();
             Statement st = conn.createStatement()) {
            try (ResultSet rs = st.executeQuery(
                    "SELECT event_id FROM z_audit_event WHERE trace_id = 'trace-both-1'")) {
                int wm = 0;
                int sec = 0;
                while (rs.next()) {
                    String eventId = rs.getString("event_id");
                    if (eventId != null && eventId.startsWith("WM:")) {
                        wm++;
                    } else if (eventId != null && eventId.startsWith("SEC:")) {
                        sec++;
                    }
                }
                assertEquals(1, wm, "★ 水印溯源行必须落台账（否则打了水印没留痕）");
                assertEquals(1, sec, "处理审计行也必须在");
            }
        }
        assertNotNull(traceId);
    }

    @Test
    @DisplayName("★ 水印溯源行：单号 / 操作人 / 租户都落进去")
    void watermarkRowCarriesContext() throws Exception {
        processExport("trace-ctx-1");

        try (Connection conn = dataSourceSecurity.getConnection();
             Statement st = conn.createStatement()) {
            try (ResultSet rs = st.executeQuery(
                    "SELECT target_id, operator_id, tenant_id, target_type FROM z_audit_event "
                            + "WHERE event_id = 'WM:trace-ctx-1'")) {
                assertTrue(rs.next(), "应有一条水印溯源行");
                assertEquals("B-1", rs.getString("target_id"), "单号应落 target_id");
                assertEquals("op-1", rs.getString("operator_id"));
                assertEquals("t-9", rs.getString("tenant_id"));
                assertNotNull(rs.getString("target_type"), "水印类型应落 target_type");
            }
        }
    }

    @Test
    @DisplayName("★ 溯源缺口：响应里 **traceError 应为空**（台账真的写成了）")
    void noTraceGapReported() throws Exception {
        ResponseEntity<String> r = postExport("trace-nogap-1");

        JsonNode node = MAPPER.readTree(r.getBody());
        JsonNode result = node.get("result");
        JsonNode traceError = result.get("traceError");
        assertTrue(traceError == null || traceError.isNull(),
                "★ 不应有溯源缺口（早先恒为「未配置溯源台账出口」）："
                        + (traceError == null ? "null" : traceError.asText()));
    }

    // ---------------- 反查 ----------------

    @Test
    @DisplayName("★ 反查：查得到 ⇒ 200 + 操作人 / 租户 / 单号 + **trace 单条视图**")
    void traceLookupFindsBothRows() throws Exception {
        processExport("trace-lookup-1");

        ResponseEntity<String> r = rest.getForEntity(
                "/z-team/api/security/trace/trace-lookup-1", String.class);

        assertTrue(r.getStatusCode().is2xxSuccessful(), "状态码：" + r.getStatusCode());
        JsonNode node = MAPPER.readTree(r.getBody());
        assertTrue(node.get("found").asBoolean());
        assertFalse(node.get("unavailable").asBoolean());
        assertEquals(2, node.get("total").asInt(), "★ 两条行都要在（WM + SEC）");

        JsonNode summary = node.get("summary");
        assertTrue(summary.get("operatorIds").toString().contains("op-1"), summary.toString());
        assertTrue(summary.get("tenantIds").toString().contains("t-9"), summary.toString());
        assertTrue(summary.get("targetIds").toString().contains("B-1"), summary.toString());

        // ★ 跨域契约：单条视图（水印域 HTTP 客户端读的就是它）
        JsonNode trace = node.get("trace");
        assertNotNull(trace, "★ 响应必须含 trace 单条视图");
        assertEquals("trace-lookup-1", trace.get("traceId").asText());
        assertEquals("B-1", trace.get("bizNo").asText(), "★ 单号字段名必须是 bizNo");
        assertEquals("WM:trace-lookup-1", trace.get("eventId").asText(),
                "★ 单条视图应优先取水印溯源行");
    }

    @Test
    @DisplayName("★ 反查：台账里没有 ⇒ **404**（合规缺口，不是 503）")
    void traceLookupNotFoundReturns404() throws Exception {
        ResponseEntity<String> r = rest.getForEntity(
                "/z-team/api/security/trace/trace-never-existed", String.class);

        assertEquals(404, r.getStatusCode().value(),
                "★「台账里没有」必须是 404（要报警的合规缺口），不是 503");
        JsonNode node = MAPPER.readTree(r.getBody());
        assertFalse(node.get("found").asBoolean());
        assertFalse(node.get("unavailable").asBoolean());
    }

    // ---------------- 辅助 ----------------

    /** 跑一次导出场景，返回追踪码。 */
    private String processExport(String traceId) throws Exception {
        ResponseEntity<String> r = postExport(traceId);
        assertTrue(r.getStatusCode().is2xxSuccessful(),
                "状态码：" + r.getStatusCode() + "，body=" + r.getBody());
        return MAPPER.readTree(r.getBody()).get("traceId").asText();
    }

    /** 跑一次导出场景。 */
    private ResponseEntity<String> postExport(String traceId) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("scene", "CONTRACT_EXPORT");
        body.put("text", ADDRESS);
        body.put("operatorId", "op-1");
        body.put("tenantId", "t-9");
        body.put("bizNo", "B-1");
        body.put("traceId", traceId);
        body.put("timestamp", 1767225600000L);
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        try {
            return rest.exchange("/z-team/api/security/process", HttpMethod.POST,
                    new HttpEntity<>(MAPPER.writeValueAsString(body), headers), String.class);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
