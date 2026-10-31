package com.zifang.z.security.core;

import com.zifang.z.audit.core.service.AuditService;
import com.zifang.z.audit.core.support.InMemoryAuditStore;
import com.zifang.z.security.core.domain.SecurityPolicy;
import com.zifang.z.security.core.domain.SecurityResult;
import com.zifang.z.security.core.domain.SecurityStage;
import com.zifang.z.security.core.service.SecurityPipeline;
import com.zifang.z.mask.core.service.MaskService;
import com.zifang.z.mask.core.support.DefaultPolicies;
import com.zifang.z.sense.core.domain.SenseResult;
import com.zifang.z.sense.core.spi.SensitiveDetector;
import com.zifang.z.sense.core.service.SenseService;
import com.zifang.z.watermark.core.service.WatermarkService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 流水线「**识别一次 → 脱敏一次**」单测（M2）。
 *
 * <p>验证口径：全文只跑一次识别（SENSE 阶段那次），MASK 阶段**复用**命中列表。
 * 判据是**计数识别器被调用的次数** —— 这是唯一不会被「结果恰好一样」蒙混过去的口径。
 *
 * @author zifang
 */
class SecurityPipelineSingleSenseTest {

    /** 真实身份证号（校验位通过 GB 11643）。 */
    private static final String ID_CARD = "110101199003078515";
    /** 真实手机号（号段合法）。 */
    private static final String PHONE = "13912345678";

    /** 计数识别器 —— 记录被调用的次数。 */
    private static class CountingDetector implements SensitiveDetector {

        private int calls;

        @Override
        public SenseResult detect(String text) {
            calls++;
            return new SenseService().detect(text);
        }

        @Override
        public String name() {
            return "counting";
        }
    }

    private SecurityPolicy senseAndMaskPolicy() {
        SecurityPolicy policy = new SecurityPolicy("P1", "TEST");
        policy.setStages(new ArrayList<>(Arrays.asList(SecurityStage.SENSE, SecurityStage.MASK)));
        policy.setBlockThreshold(null);
        return policy;
    }

    @Test
    @DisplayName("流水线：识别 + 脱敏 ⇒ 全文只识别一次")
    void detectsOnlyOnce() {
        CountingDetector detector = new CountingDetector();
        SenseService senseService = new SenseService(detector);
        MaskService maskService = new MaskService(senseService, DefaultPolicies.policies());
        SecurityPipeline pipeline = new SecurityPipeline(senseService, maskService,
                new WatermarkService(), null);

        SecurityResult r = pipeline.run("身份证 " + ID_CARD + " 手机 " + PHONE,
                senseAndMaskPolicy());

        assertEquals(1, detector.calls, "全文应只识别一次（M1 口径是两次）");
        assertTrue(r.getMaskedCount() > 0, "脱敏应生效");
        assertFalse(r.getContent().contains(ID_CARD), "身份证应被遮蔽");
        assertFalse(r.getContent().contains(PHONE), "手机号应被遮蔽");
    }

    @Test
    @DisplayName("流水线：只跑 SENSE 不跑 MASK ⇒ 仍只识别一次")
    void senseOnlyDetectsOnce() {
        CountingDetector detector = new CountingDetector();
        SenseService senseService = new SenseService(detector);
        MaskService maskService = new MaskService(senseService, DefaultPolicies.policies());
        SecurityPipeline pipeline = new SecurityPipeline(senseService, maskService,
                new WatermarkService(), null);

        SecurityPolicy policy = new SecurityPolicy("P1", "TEST");
        policy.setStages(new ArrayList<>(List.of(SecurityStage.SENSE)));
        policy.setBlockThreshold(null);

        pipeline.run("身份证 " + ID_CARD, policy);

        assertEquals(1, detector.calls);
    }

    @Test
    @DisplayName("流水线：只跑 MASK 不跑 SENSE ⇒ 退回自识别一次（不是零次）")
    void maskOnlyFallsBackToSelfDetect() {
        CountingDetector detector = new CountingDetector();
        SenseService senseService = new SenseService(detector);
        MaskService maskService = new MaskService(senseService, DefaultPolicies.policies());
        SecurityPipeline pipeline = new SecurityPipeline(senseService, maskService,
                new WatermarkService(), null);

        SecurityPolicy policy = new SecurityPolicy("P1", "TEST");
        policy.setStages(new ArrayList<>(List.of(SecurityStage.MASK)));
        policy.setBlockThreshold(null);

        SecurityResult r = pipeline.run("身份证 " + ID_CARD, policy);

        assertEquals(1, detector.calls, "没跑 SENSE ⇒ 退回自识别一次");
        assertTrue(r.getMaskedCount() > 0, "脱敏仍应生效（不能因为没跑 SENSE 就漏遮）");
        assertFalse(r.getContent().contains(ID_CARD));
    }

    @Test
    @DisplayName("流水线：★ 识别规则中途变化 ⇒ 拦截判定与脱敏结果仍一致（同一份命中）")
    void blockAndMaskUseSameHitSet() {
        // 计数器识别器：第一次调用返回真结果，第二次（若发生）返回**空结果**。
        // 若流水线跑两次识别，第二次（MASK 阶段）会拿到空命中 ⇒ 脱敏失效 ⇒ 原文泄露。
        // ⇒ 这条用例能直接抓到「偷偷识别第二次」的实现。
        int[] calls = {0};
        SensitiveDetector flaky = new SensitiveDetector() {
            @Override
            public SenseResult detect(String text) {
                calls[0]++;
                if (calls[0] == 1) {
                    return new SenseService().detect(text);
                }
                // 第二次调用 ⇒ 假装规则集变了，识别不到任何东西
                return new SenseResult(text == null ? 0 : text.length());
            }

            @Override
            public String name() {
                return "flaky";
            }
        };
        SenseService senseService = new SenseService(flaky);
        MaskService maskService = new MaskService(senseService, DefaultPolicies.policies());
        SecurityPipeline pipeline = new SecurityPipeline(senseService, maskService,
                new WatermarkService(), null);

        SecurityResult r = pipeline.run("身份证 " + ID_CARD, senseAndMaskPolicy());

        assertEquals(1, calls[0], "只应识别一次");
        assertTrue(r.getMaskedCount() > 0, "脱敏应基于第一份命中生效");
        assertFalse(r.getContent().contains(ID_CARD), "原文不得泄露");
    }

    @Test
    @DisplayName("流水线：拦截判定与脱敏共用同一份命中（拦截时命中数一致）")
    void blockedResultCarriesSameHitSet() {
        InMemoryAuditStore auditStore = new InMemoryAuditStore();
        SenseService senseService = new SenseService();
        MaskService maskService = new MaskService(senseService, DefaultPolicies.policies());
        SecurityPipeline pipeline = new SecurityPipeline(senseService, maskService,
                new WatermarkService(), new AuditService(auditStore));

        SecurityPolicy policy = new SecurityPolicy("P1", "TEST");
        policy.setStages(new ArrayList<>(Arrays.asList(SecurityStage.SENSE, SecurityStage.MASK)));
        policy.setBlockThreshold("L3");

        SecurityResult r = pipeline.run("身份证 " + ID_CARD + " 手机 " + PHONE, policy);

        assertTrue(r.isBlocked());
        assertNotNullHits(r);
        // 拦截后不得有任何脱敏内容（不出域）
        assertEquals(0, r.getMaskedCount(), "拦截时不应脱敏");
        assertFalse(String.valueOf(r.getContent()).contains(ID_CARD));
    }

    /** 断言识别结果非空。 */
    private static void assertNotNullHits(SecurityResult r) {
        assertTrue(r.getSenseResult() != null, "识别结果不应为空");
        assertTrue(r.getSenseResult().getHitCount() > 0, "应有命中");
    }
}
