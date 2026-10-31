package com.zifang.z.security.core;

import com.zifang.z.audit.core.domain.AuditEvent;
import com.zifang.z.audit.core.service.AuditService;
import com.zifang.z.audit.core.support.InMemoryAuditStore;
import com.zifang.z.security.core.domain.SecurityPolicy;
import com.zifang.z.security.core.domain.SecurityResult;
import com.zifang.z.security.core.domain.SecurityStage;
import com.zifang.z.security.core.service.SecurityPipeline;
import com.zifang.z.mask.core.service.MaskService;
import com.zifang.z.mask.core.support.DefaultPolicies;
import com.zifang.z.sense.core.service.SenseService;
import com.zifang.z.watermark.core.domain.WatermarkPayload;
import com.zifang.z.watermark.core.domain.WatermarkTrace;
import com.zifang.z.watermark.core.service.WatermarkService;
import com.zifang.z.watermark.core.spi.WatermarkTraceQuery;
import com.zifang.z.watermark.core.spi.WatermarkTraceRecorder;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ★ 溯源闭环单测（编排层，M2 #22）。
 *
 * <p><b>核心判据</b>：追踪码**单一来源** ——
 * 流水线结果 traceId ≡ 水印载荷 traceId ≡ 审计事件 traceId ≡ 台账记录 traceId。
 *
 * <p>⚠ 这条判据是 #22 的真正价值所在：早先实现里流水线自己生成 UUID、
 * 水印用调用方的 traceId ⇒ **两个不同的值** ⇒
 * 拿水印里的码去反查审计台账**永远查不到** ⇒ 溯源闭环是断的，
 * 而且**从功能上完全看不出来**（打水印成功、审计也成功，只有反查时才暴露）。
 *
 * @author zifang
 */
class SecurityPipelineTraceIdTest {

    /** 内存台账。 */
    private static class MemoryLedger implements WatermarkTraceRecorder, WatermarkTraceQuery {

        private final List<WatermarkTrace> traces = new ArrayList<>();

        @Override
        public boolean record(WatermarkTrace trace) {
            traces.add(trace);
            return true;
        }

        @Override
        public WatermarkTrace find(String traceId) {
            for (WatermarkTrace t : traces) {
                if (t.getTraceId().equals(traceId)) {
                    return t;
                }
            }
            return null;
        }

        @Override
        public String name() {
            return "memory-ledger";
        }
    }

    private final InMemoryAuditStore auditStore = new InMemoryAuditStore();
    private final MemoryLedger ledger = new MemoryLedger();

    private SecurityPipeline pipeline() {
        SenseService senseService = new SenseService();
        MaskService maskService = new MaskService(senseService, DefaultPolicies.policies());
        WatermarkService watermarkService = new WatermarkService();
        watermarkService.setTraceRecorder(ledger);
        watermarkService.setTraceQuery(ledger);
        AuditService auditService = new AuditService(auditStore);
        auditService.setQuery(auditStore);
        return new SecurityPipeline(senseService, maskService, watermarkService, auditService);
    }

    private SecurityPolicy fullPolicy() {
        SecurityPolicy policy = new SecurityPolicy("P1", "CONTRACT_EXPORT");
        policy.setStages(new ArrayList<>(Arrays.asList(SecurityStage.SENSE, SecurityStage.MASK,
                SecurityStage.WATERMARK, SecurityStage.AUDIT)));
        policy.setBlockThreshold(null);
        return policy;
    }

    // ---------------- 追踪码单一来源 ----------------

    @Test
    @DisplayName("★ 追踪码单一来源：载荷没给码 ⇒ 流水线补一个并回写载荷")
    void pipelineGeneratesTraceIdAndWritesBack() {
        WatermarkPayload payload = new WatermarkPayload("op-1", "tenant-9", "C-1", null, 0L);

        SecurityResult r = pipeline().run("合同正文", fullPolicy(), payload, "op-1");

        assertNotNull(r.getTraceId());
        assertEquals(r.getTraceId(), payload.getTraceId(),
                "★ 载荷必须被回写（否则水印里的码与结果里的码不是同一个）");
    }

    @Test
    @DisplayName("★ 追踪码单一来源：★ 结果 / 载荷 / 审计事件 / 台账四处**完全一致**")
    void allFourTraceIdsAreIdentical() {
        WatermarkPayload payload = new WatermarkPayload("op-1", "tenant-9", "C-1", null, 0L);

        SecurityResult r = pipeline().run("合同正文", fullPolicy(), payload, "op-1");

        String traceId = r.getTraceId();
        assertNotNull(traceId);
        assertEquals(traceId, payload.getTraceId(), "载荷的码");
        assertEquals(1, ledger.traces.size(), "台账应有一条溯源记录");
        assertEquals(traceId, ledger.traces.get(0).getTraceId(), "台账的码");
        assertEquals(1, auditStore.size(), "审计台账应有一条处理记录");
        assertEquals(traceId, auditStore.all().get(0).getTraceId(), "审计事件的码");
    }

    @Test
    @DisplayName("★ 追踪码单一来源：调用方给了码 ⇒ 全链路都用这个码")
    void callerProvidedTraceIdIsUsedEverywhere() {
        WatermarkPayload payload =
                new WatermarkPayload("op-1", "tenant-9", "C-1", "trace-caller-1", 1767225600000L);

        SecurityResult r = pipeline().run("合同正文", fullPolicy(), payload, "op-1");

        assertEquals("trace-caller-1", r.getTraceId());
        assertEquals("trace-caller-1", payload.getTraceId());
        assertEquals("trace-caller-1", ledger.traces.get(0).getTraceId());
        assertEquals("trace-caller-1", auditStore.all().get(0).getTraceId());
    }

    @Test
    @DisplayName("★ 追踪码单一来源：★ 水印里提取出来的码 ⇒ 能反查到审计记录")
    void extractedTraceIdFindsAuditRecord() {
        WatermarkPayload payload = new WatermarkPayload("op-1", "tenant-9", "C-1", null, 0L);
        SecurityPipeline pipeline = pipeline();

        SecurityResult r = pipeline.run("合同正文", fullPolicy(), payload, "op-1");

        // 从带水印的内容里提取码（模拟泄密后拿到文件）
        WatermarkPayload extracted =
                new WatermarkService().extract(
                        com.zifang.z.watermark.core.domain.WatermarkType.VISIBLE_TEXT, r.getContent());
        assertNotNull(extracted, "应能提取出水印");
        assertEquals(r.getTraceId(), extracted.getTraceId(), "★ 水印里的码必须与结果的码一致");

        // 拿这个码反查审计台账 ⇒ 必须查得到
        boolean found = false;
        for (AuditEvent e : auditStore.all()) {
            if (extracted.getTraceId().equals(e.getTraceId())) {
                found = true;
                assertEquals("op-1", e.getOperatorId());
                break;
            }
        }
        assertTrue(found, "★ 拿水印里的码必须能反查到审计记录（否则闭环是断的）");
    }

    // ---------------- 不重复记账 ----------------

    @Test
    @DisplayName("★ 不重复记账：水印台账一条 + 处理审计一条（eventId 前缀不同 ⇒ 不撞行）")
    void watermarkAndAuditRecordsAreDistinct() {
        WatermarkPayload payload = new WatermarkPayload("op-1", "tenant-9", "C-1", null, 0L);

        pipeline().run("合同正文", fullPolicy(), payload, "op-1");

        assertEquals(1, ledger.traces.size(), "水印台账一条");
        assertEquals(1, auditStore.size(), "处理审计一条");
        String watermarkEventId = ledger.traces.get(0).getEventId();
        String auditEventId = auditStore.all().get(0).getEventId();
        assertEquals("WM:" + payload.getTraceId(), watermarkEventId);
        assertEquals("SEC:" + payload.getTraceId(), auditEventId);
        assertFalse(watermarkEventId.equals(auditEventId), "★ 两条记录不能是同一行");
    }

    @Test
    @DisplayName("★ 不重复记账：同一 traceId 跑两次 ⇒ 审计台账只留一条（幂等键生效）")
    void repeatedRunDoesNotDuplicateAuditRecord() {
        WatermarkPayload payload = new WatermarkPayload("op-1", "tenant-9", "C-1", "trace-same", 0L);
        SecurityPipeline pipeline = pipeline();

        pipeline.run("合同正文", fullPolicy(), payload, "op-1");
        pipeline.run("合同正文", fullPolicy(), payload, "op-1");

        assertEquals(1, auditStore.size(), "★ 幂等键 SEC:<traceId> 应只留一条");
    }

    // ---------------- 上下文补全 ----------------

    @Test
    @DisplayName("审计事件补全上下文：租户 / 单号 / 操作人都要落进去")
    void auditEventCarriesFullContext() {
        WatermarkPayload payload = new WatermarkPayload("op-001", "tenant-9", "C-2026-001", null, 0L);

        pipeline().run("合同正文", fullPolicy(), payload, "op-001");

        AuditEvent event = auditStore.all().get(0);
        assertEquals("op-001", event.getOperatorId());
        assertEquals("tenant-9", event.getTenantId(), "租户要落进审计事件");
        assertEquals("C-2026-001", event.getTargetId(), "★ targetId 应是业务单号（溯源要看单子）");
        assertEquals("CONTRACT_EXPORT", event.getTargetType(), "场景码落在 targetType");
    }

    @Test
    @DisplayName("★ 台账写失败 ⇒ 流水线标出缺口（result.traceError 非空），但不阻断")
    void traceErrorSurfacedInResult() {
        SenseService senseService = new SenseService();
        MaskService maskService = new MaskService(senseService, DefaultPolicies.policies());
        WatermarkService watermarkService = new WatermarkService();
        watermarkService.setTraceRecorder(new WatermarkTraceRecorder() {
            @Override
            public boolean record(WatermarkTrace trace) {
                throw new IllegalStateException("台账炸了");
            }

            @Override
            public String name() {
                return "broken";
            }
        });
        AuditService auditService = new AuditService(auditStore);
        SecurityPipeline pipeline =
                new SecurityPipeline(senseService, maskService, watermarkService, auditService);
        WatermarkPayload payload = new WatermarkPayload("op-1", "tenant-9", "C-1", null, 0L);

        SecurityResult r = pipeline.run("合同正文", fullPolicy(), payload, "op-1");

        assertNotNull(r.getTraceError(), "★ 合规缺口必须能上报（不能静默）");
        assertTrue(r.getContent().contains("【水印："), "水印本身仍应生效（主链路不拖垮）");
    }

    @Test
    @DisplayName("流水线：无水印阶段 ⇒ 不写溯源台账（不产生多余记录）")
    void noWatermarkStageNoTraceRecord() {
        SecurityPolicy policy = new SecurityPolicy("P1", "CONTRACT_VIEW");
        policy.setStages(new ArrayList<>(Arrays.asList(SecurityStage.SENSE, SecurityStage.MASK)));
        policy.setBlockThreshold(null);
        WatermarkPayload payload = new WatermarkPayload("op-1", "tenant-9", "C-1", null, 0L);

        pipeline().run("合同正文", policy, payload, "op-1");

        assertEquals(0, ledger.traces.size(), "没跑水印阶段就不该有溯源记录");
    }
}
