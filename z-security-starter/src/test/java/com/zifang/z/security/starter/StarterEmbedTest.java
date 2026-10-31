package com.zifang.z.security.starter;

import com.example.embedhost.StarterHostTestApplication;
import com.zifang.z.audit.core.domain.AuditEvent;
import com.zifang.z.audit.core.domain.AuditTraceResult;
import com.zifang.z.audit.core.service.AuditService;
import com.zifang.z.audit.core.service.AuditTraceService;
import com.zifang.z.security.core.domain.SecurityPolicy;
import com.zifang.z.security.core.domain.SecurityResult;
import com.zifang.z.security.core.service.PolicyLedgerService;
import com.zifang.z.security.core.service.SecurityPipeline;
import com.zifang.z.security.core.service.SecurityPolicyRegistry;
import com.zifang.z.security.starter.config.PolicyBootstrap;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import javax.sql.DataSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * z-security starter <b>嵌入式装配</b>验收（M2 #23）。
 *
 * <p>宿主模拟应用放 {@code com.example.embedhost} 无关包树 ⇒ 组件扫描不可能兜底，
 * 装配只能走 {@code AutoConfiguration.imports}。本仓 starter 是**自足版**
 * （编排引擎 + 本域数据源 + 双包 {@code @MapperScan} 同生共死）⇒ 验收必须真跑流水线、
 * 真落台账、可反查，不是只断言 bean 存在。
 *
 * @author zifang
 */
@SpringBootTest(
        classes = StarterHostTestApplication.class,
        webEnvironment = SpringBootTest.WebEnvironment.NONE,
        properties = {
                "z.base.db.security.url=jdbc:h2:mem:zsec_starter_embed;MODE=MySQL;DB_CLOSE_DELAY=-1",
                "z.base.db.security.username=sa",
                "z.base.db.security.password="
        })
class StarterEmbedTest {

    /** 校验位通过的身份证（L3）。 */
    private static final String ID_CARD = "110101199003078515";

    @Autowired
    private SecurityPipeline securityPipeline;

    @Autowired
    private SecurityPolicyRegistry securityPolicyRegistry;

    @Autowired
    private PolicyLedgerService policyLedgerService;

    @Autowired
    private PolicyBootstrap policyBootstrap;

    @Autowired
    private AuditService auditService;

    @Autowired
    private AuditTraceService auditTraceService;

    @Autowired
    private DataSource dataSourceSecurity;

    @Test
    @DisplayName("★ 宿主只放 starter jar ⇒ 编排引擎全家（含数据源）自动装配齐备")
    void hostEmbeddingStarterGetsFullEngine() {
        assertNotNull(securityPipeline, "★ 安全流水线必须仅靠 AutoConfiguration.imports 装配出来");
        assertNotNull(securityPolicyRegistry, "★ 策略注册表必须自动装配");
        assertNotNull(policyLedgerService, "★ 策略台账服务必须自动装配（Mapper 注入不能哑火）");
        assertNotNull(policyBootstrap, "★ 策略启动装载器必须自动装配（热改不能只活到下次重启前）");
        assertNotNull(auditService, "★ 审计服务必须自动装配（落库版）");
        assertNotNull(auditTraceService, "★ 溯源反查服务必须自动装配");
        assertNotNull(dataSourceSecurity, "★ 本域数据源必须自动装配（starter 自足带走）");
    }

    @Test
    @DisplayName("★ 嵌入的流水线真能跑：识别→脱敏生效 + 编排层直写台账可反查")
    void embeddedPipelineReallyRunsAndAudits() throws Exception {
        SecurityTestSchema.apply(dataSourceSecurity);

        // ① 内部查看场景：脱敏生效（身份证被遮蔽、不拦）。
        SecurityPolicy policy = securityPolicyRegistry.resolve("CONTRACT_VIEW");
        assertNotNull(policy, "★ 内置场景 CONTRACT_VIEW 必须在注册表里");

        SecurityResult result = securityPipeline.run("客户身份证 " + ID_CARD, policy);
        assertNotNull(result, "★ 流水线不能返回 null");
        assertEquals(SecurityResult.STATUS_MASKED, result.getStatus(),
                "★ 查看场景命中 L3 应脱敏，实际状态：" + result.getStatus());
        assertFalse(result.getContent().contains(ID_CARD),
                "★ 脱敏后不得含身份证原文，实际输出：" + result.getContent());

        // ② 编排层直写审计台账：记一条带追踪码的事件 ⇒ 反查必须到
        //（验的是本域数据源把 z-audit Mapper 绑上本域 sqlSessionFactory 的通路）。
        AuditEvent event = new AuditEvent();
        event.setTraceId("trace-abc-123");
        event.setOperatorId("op-001");
        AuditEvent stored = auditService.record(event);
        assertNotNull(stored.getHash(), "★ 编排层落的台账事件必须带链哈希");

        AuditTraceResult trace = auditTraceService.lookup("trace-abc-123");
        assertTrue(trace.isFound(), "★ 编排层直写的事件必须能反查到，实际：" + trace.getMessage());
    }
}
