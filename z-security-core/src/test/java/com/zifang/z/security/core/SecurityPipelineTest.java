package com.zifang.z.security.core;

import com.zifang.z.audit.core.service.AuditService;
import com.zifang.z.audit.core.support.InMemoryAuditStore;
import com.zifang.z.security.core.domain.SecurityPolicy;
import com.zifang.z.security.core.domain.SecurityResult;
import com.zifang.z.security.core.domain.SecurityStage;
import com.zifang.z.security.core.service.SecurityPipeline;
import com.zifang.z.security.core.service.SecurityPolicyRegistry;
import com.zifang.z.security.core.support.BuiltinSecurityPolicies;
import com.zifang.z.mask.core.service.MaskService;
import com.zifang.z.mask.core.support.DefaultPolicies;
import com.zifang.z.sense.core.service.SenseService;
import com.zifang.z.watermark.core.domain.WatermarkPayload;
import com.zifang.z.watermark.core.service.WatermarkService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 安全流水线单测（**编排层**）。
 *
 * @author zifang
 */
class SecurityPipelineTest {

    private final InMemoryAuditStore auditStore = new InMemoryAuditStore();
    private final AuditService auditService = new AuditService(auditStore);
    private final SenseService senseService = new SenseService();
    private final MaskService maskService = new MaskService(senseService, DefaultPolicies.policies());
    private final WatermarkService watermarkService = new WatermarkService();
    private final SecurityPipeline pipeline =
            new SecurityPipeline(senseService, maskService, watermarkService, auditService);

    /** 真实身份证号（**校验位通过 GB 11643** ⇒ 引擎会真的命中）。 */
    private static final String ID_CARD = "110101199003078515";
    /** 真实手机号（号段合法）。 */
    private static final String PHONE = "13912345678";
    /** Luhn 通过的银行卡号。 */
    private static final String BANK_CARD = "6222020200011122336";

    private WatermarkPayload payload() {
        return new WatermarkPayload("op-001", "tenant-9", "C-1", "trace-abc-123", 1767225600000L);
    }

    // ---------------- 识别 + 脱敏 ----------------

    @Test
    @DisplayName("流水线：识别 + 脱敏 ⇒ 敏感内容被遮蔽")
    void senseAndMask() {
        SecurityPolicy policy = new SecurityPolicy("P1", "TEST");
        policy.setStages(new ArrayList<>(Arrays.asList(SecurityStage.SENSE, SecurityStage.MASK)));
        policy.setBlockThreshold(null);

        SecurityResult r = pipeline.run("身份证 " + ID_CARD + " 手机 " + PHONE, policy);

        assertNotNull(r.getContent());
        assertFalse(r.getContent().contains(ID_CARD), "身份证应被遮蔽：" + r.getContent());
        assertFalse(r.getContent().contains(PHONE), "手机号应被遮蔽：" + r.getContent());
        assertTrue(r.getMaskedCount() > 0);
        assertEquals(SecurityResult.STATUS_MASKED, r.getStatus());
    }

    @Test
    @DisplayName("流水线：普通文本 ⇒ 原样返回、零脱敏")
    void plainTextUntouched() {
        SecurityPolicy policy = new SecurityPolicy("P1", "TEST");
        policy.setStages(new ArrayList<>(Arrays.asList(SecurityStage.SENSE, SecurityStage.MASK)));
        policy.setBlockThreshold(null);

        String text = "今天天气不错，适合去公园散步。";
        SecurityResult r = pipeline.run(text, policy);

        assertEquals(text, r.getContent());
        assertEquals(0, r.getMaskedCount());
        assertEquals(SecurityResult.STATUS_PASS, r.getStatus());
    }

    @Test
    @DisplayName("流水线：null 文本 ⇒ 空内容不抛异常")
    void nullTextSafe() {
        SecurityPolicy policy = SecurityPolicy.full("P1", "TEST");

        SecurityResult r = pipeline.run(null, policy);

        assertNotNull(r);
        assertEquals("", r.getContent());
    }

    @Test
    @DisplayName("流水线：禁用策略 ⇒ 原样返回")
    void disabledPolicyPassesThrough() {
        SecurityPolicy policy = SecurityPolicy.full("P1", "TEST");
        policy.setEnabled(false);

        String text = "身份证 " + ID_CARD;
        SecurityResult r = pipeline.run(text, policy);

        assertEquals(text, r.getContent());
        assertEquals(SecurityResult.STATUS_PASS, r.getStatus());
    }

    // ---------------- 拦截 ----------------

    @Test
    @DisplayName("流水线：命中级别 ≥ 阈值 ⇒ 拦截（不出域）")
    void blocksAboveThreshold() {
        SecurityPolicy policy = SecurityPolicy.strict("P1", "TEST");
        policy.setStages(new ArrayList<>(Arrays.asList(SecurityStage.SENSE, SecurityStage.MASK)));
        // ⚠ 引擎口径：**身份证 = L3**（敏感），**银行卡 / 凭据 = L4**（核心）。
        //    阈值设 L3 ⇒ 身份证这类个人敏感信息就拦。
        policy.setBlockThreshold("L3");

        SecurityResult r = pipeline.run("身份证 " + ID_CARD, policy);

        assertTrue(r.isBlocked(), "L3 身份证应被 L3 阈值拦截");
        assertEquals(SecurityResult.STATUS_BLOCKED, r.getStatus());
        assertNotNull(r.getBlockReason());
        assertTrue(r.getBlockReason().contains("L3"));
    }

    @Test
    @DisplayName("流水线：L4 阈值 ⇒ L3 数据放行，L4 数据拦截")
    void thresholdDistinguishesLevels() {
        SecurityPolicy policy = SecurityPolicy.full("P1", "TEST");
        policy.setStages(new ArrayList<>(Arrays.asList(SecurityStage.SENSE, SecurityStage.MASK)));
        policy.setBlockThreshold("L4");

        // L3（身份证）不拦
        SecurityResult l3 = pipeline.run("身份证 " + ID_CARD, policy);
        assertFalse(l3.isBlocked(), "L3 不该被 L4 阈值拦");

        // L4（银行卡）拦
        SecurityResult l4 = pipeline.run("银行卡 " + BANK_CARD, policy);
        assertTrue(l4.isBlocked(), "L4 应被 L4 阈值拦");
    }

    @Test
    @DisplayName("流水线：命中级别 < 阈值 ⇒ 放行（脱敏后返回）")
    void passesBelowThreshold() {
        SecurityPolicy policy = SecurityPolicy.full("P1", "TEST");
        policy.setStages(new ArrayList<>(Arrays.asList(SecurityStage.SENSE, SecurityStage.MASK)));
        policy.setBlockThreshold("L4");

        // 邮箱是 L3 ⇒ 不该被 L4 阈值拦住
        SecurityResult r = pipeline.run("邮箱 zhang@example.com", policy);

        assertFalse(r.isBlocked(), "L3 不该被 L4 阈值拦");
        assertEquals(SecurityResult.STATUS_MASKED, r.getStatus());
    }

    @Test
    @DisplayName("流水线：阈值 null ⇒ 永不拦截")
    void nullThresholdNeverBlocks() {
        SecurityPolicy policy = SecurityPolicy.full("P1", "TEST");
        policy.setStages(new ArrayList<>(Arrays.asList(SecurityStage.SENSE, SecurityStage.MASK)));
        policy.setBlockThreshold(null);

        SecurityResult r = pipeline.run("身份证 " + ID_CARD + " 银行卡 " + BANK_CARD, policy);

        assertFalse(r.isBlocked());
        assertTrue(r.getMaskedCount() > 0);
    }

    @Test
    @DisplayName("流水线：拦截时内容不外泄（不返回原文）")
    void blockedContentNotLeaked() {
        SecurityPolicy policy = SecurityPolicy.strict("P1", "TEST");
        policy.setBlockThreshold("L3");

        SecurityResult r = pipeline.run("身份证 " + ID_CARD, policy);

        assertTrue(r.isBlocked());
        assertFalse(String.valueOf(r.getContent()).contains(ID_CARD),
                "拦截时不得把原文带出来");
    }

    // ---------------- 水印 ----------------

    @Test
    @DisplayName("流水线：跑水印阶段 ⇒ 内容带水印标记")
    void watermarkStageAddsMark() {
        SecurityPolicy policy = SecurityPolicy.full("P1", "TEST");
        policy.setStages(new ArrayList<>(Arrays.asList(SecurityStage.WATERMARK)));
        policy.setBlockThreshold(null);

        SecurityResult r = pipeline.run("合同正文", policy, payload(), "op-1");

        assertTrue(r.getContent().contains("【水印："), "应带显式水印：" + r.getContent());
        assertNotNull(r.getWatermarkPayload());
    }

    @Test
    @DisplayName("流水线：不跑水印阶段 ⇒ 内容无水印标记")
    void noWatermarkStageNoMark() {
        SecurityPolicy policy = SecurityPolicy.full("P1", "TEST");
        policy.setStages(new ArrayList<>(Arrays.asList(SecurityStage.SENSE, SecurityStage.MASK)));
        policy.setBlockThreshold(null);

        SecurityResult r = pipeline.run("合同正文", policy, payload(), "op-1");

        assertFalse(r.getContent().contains("【水印："));
    }

    @Test
    @DisplayName("流水线：脱敏 + 水印同时跑 ⇒ 先脱敏再打水印")
    void maskThenWatermark() {
        SecurityPolicy policy = SecurityPolicy.full("P1", "TEST");
        policy.setStages(new ArrayList<>(Arrays.asList(SecurityStage.SENSE, SecurityStage.MASK,
                SecurityStage.WATERMARK)));
        policy.setBlockThreshold(null);

        SecurityResult r = pipeline.run("身份证 " + ID_CARD + " 合同正文", policy, payload(), "op-1");

        assertFalse(r.getContent().contains(ID_CARD), "身份证应已被遮蔽");
        assertTrue(r.getContent().contains("【水印："), "水印应已加上");
    }

    // ---------------- 审计 ----------------

    @Test
    @DisplayName("流水线：跑审计阶段 ⇒ 审计台账有记录")
    void auditStageRecords() {
        SecurityPolicy policy = SecurityPolicy.full("P1", "TEST");
        policy.setBlockThreshold(null);

        pipeline.run("身份证 " + ID_CARD, policy, payload(), "op-1");

        assertEquals(1, auditStore.size(), "应留一条审计");
        assertEquals("op-1", auditStore.all().get(0).getOperatorId());
    }

    @Test
    @DisplayName("流水线：不跑审计阶段 ⇒ 审计台账为空")
    void noAuditStageNoRecord() {
        SecurityPolicy policy = SecurityPolicy.full("P1", "TEST");
        policy.setStages(new ArrayList<>(Arrays.asList(SecurityStage.SENSE, SecurityStage.MASK)));
        policy.setBlockThreshold(null);

        pipeline.run("身份证 " + ID_CARD, policy, payload(), "op-1");

        assertEquals(0, auditStore.size());
    }

    @Test
    @DisplayName("流水线：拦截时也留痕（结果 = DENIED）")
    void blockedStillAudited() {
        SecurityPolicy policy = SecurityPolicy.full("P1", "TEST");
        policy.setBlockThreshold("L3");

        pipeline.run("身份证 " + ID_CARD, policy, payload(), "op-1");

        assertEquals(1, auditStore.size(), "拦截也必须留痕");
        assertEquals(com.zifang.z.audit.core.domain.AuditResult.DENIED,
                auditStore.all().get(0).getResult());
    }

    // ---------------- 策略注册表 ----------------

    @Test
    @DisplayName("策略注册表：按场景查；没登记 ⇒ 兜底")
    void registryResolve() {
        SecurityPolicyRegistry registry = new SecurityPolicyRegistry(SecurityPolicyRegistry.builtinDefault());
        for (SecurityPolicy p : BuiltinSecurityPolicies.all()) {
            registry.register(p);
        }

        SecurityPolicy export = registry.resolve(BuiltinSecurityPolicies.SCENE_CONTRACT_EXPORT);
        assertEquals("P_EXPORT", export.getPolicyId());
        assertEquals("L3", export.getBlockThreshold());

        SecurityPolicy unknown = registry.resolve("不存在的场景");
        assertNotNull(unknown, "未登记场景应给兜底策略");
        assertEquals("DEFAULT", unknown.getPolicyId());
    }

    @Test
    @DisplayName("策略注册表：内置场景集齐 5 个")
    void builtinScenes() {
        List<SecurityPolicy> all = BuiltinSecurityPolicies.all();

        assertEquals(5, all.size());
        List<String> scenes = new ArrayList<>();
        for (SecurityPolicy p : all) {
            scenes.add(p.getScene());
        }
        assertTrue(scenes.contains(BuiltinSecurityPolicies.SCENE_CONTRACT_VIEW));
        assertTrue(scenes.contains(BuiltinSecurityPolicies.SCENE_CONTRACT_EXPORT));
        assertTrue(scenes.contains(BuiltinSecurityPolicies.SCENE_INTERNAL_REPORT));
        assertTrue(scenes.contains(BuiltinSecurityPolicies.SCENE_PUBLIC_SHARE));
        assertTrue(scenes.contains(BuiltinSecurityPolicies.SCENE_IMAGE_ASSET));
    }

    @Test
    @DisplayName("内置策略：内部查看场景不拦（水印与审计都不跑）")
    void viewScenePolicy() {
        SecurityPolicy view = null;
        for (SecurityPolicy p : BuiltinSecurityPolicies.all()) {
            if (BuiltinSecurityPolicies.SCENE_CONTRACT_VIEW.equals(p.getScene())) {
                view = p;
            }
        }
        assertNotNull(view);
        assertFalse(view.runs(SecurityStage.WATERMARK));
        assertFalse(view.runs(SecurityStage.AUDIT));
        assertTrue(view.runs(SecurityStage.SENSE));
        assertTrue(view.runs(SecurityStage.MASK));
    }

    // ---------------- 阶段枚举 ----------------

    @Test
    @DisplayName("阶段解析：大小写不敏感；未知 ⇒ null")
    void stageFromCode() {
        assertEquals(SecurityStage.SENSE, SecurityStage.fromCode("sense"));
        assertEquals(SecurityStage.MASK, SecurityStage.fromCode("  MASK "));
        assertNull(SecurityStage.fromCode("不存在"));
        assertNull(SecurityStage.fromCode(null));
    }

    @Test
    @DisplayName("默认阶段顺序：识别 → 脱敏 → 水印 → 审计")
    void defaultStageOrder() {
        assertEquals(Arrays.asList(SecurityStage.SENSE, SecurityStage.MASK,
                        SecurityStage.WATERMARK, SecurityStage.AUDIT),
                SecurityStage.defaultOrder());
    }

    @Test
    @DisplayName("结果视图：含状态 / 脱敏数 / 命中数")
    void resultView() {
        SecurityPolicy policy = SecurityPolicy.full("P1", "TEST");
        policy.setBlockThreshold(null);

        SecurityResult r = pipeline.run("身份证 " + ID_CARD, policy);

        assertNotNull(r.toView());
        assertEquals(SecurityResult.STATUS_MASKED, r.toView().get("status"));
        assertTrue((Integer) r.toView().get("hitCount") > 0);
        assertTrue(r.getElapsedMillis() >= 0);
        assertNotNull(r.getTraceId());
    }
}
