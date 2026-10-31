package com.zifang.z.security.core;

import com.zifang.z.audit.core.domain.AuditEvent;
import com.zifang.z.audit.core.service.AuditService;
import com.zifang.z.audit.core.service.AuditTraceService;
import com.zifang.z.audit.core.support.InMemoryAuditStore;
import com.zifang.z.security.core.service.LocalAuditTraceAdapter;
import com.zifang.z.watermark.core.domain.WatermarkTrace;
import com.zifang.z.watermark.core.spi.WatermarkTraceUnavailableException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ★ 编排层溯源台账适配器单测（M2 #22）。
 *
 * <p><b>核心判据</b>：编排层的「水印溯源行」必须<b>真的落进台账</b>。
 * 早先实现里 {@code embedTraced} 因未挂出口而永远标「未配置溯源台账出口」，
 * 而 AUDIT 阶段只写 {@code SEC:} 处理行 ⇒
 * <b>「打了水印却没留痕」且没人知道</b>。
 *
 * @author zifang
 */
class LocalAuditTraceAdapterTest {

    private final InMemoryAuditStore store = new InMemoryAuditStore();

    private LocalAuditTraceAdapter adapter() {
        AuditService service = new AuditService(store);
        service.setQuery(store);
        return new LocalAuditTraceAdapter(service, new AuditTraceService(store));
    }

    private static WatermarkTrace trace(String traceId) {
        WatermarkTrace trace = new WatermarkTrace();
        trace.setTraceId(traceId);
        trace.setEventId(WatermarkTrace.defaultEventId(traceId));
        trace.setOperatorId("op-001");
        trace.setTenantId("tenant-9");
        trace.setBizNo("C-2026-001");
        trace.setWatermarkType("VISIBLE_TEXT");
        trace.setRemark("导出合同");
        trace.setOccurredAt(1767225600000L);
        return trace;
    }

    @Test
    @DisplayName("★ 写侧：水印溯源行**真的落进台账**（不再是「未配置出口」的缺口）")
    void recordPersistsIntoLedger() {
        LocalAuditTraceAdapter adapter = adapter();

        assertTrue(adapter.record(trace("trace-1")), "应写成");

        assertEquals(1, store.size(), "★ 台账里必须有一条");
        AuditEvent event = store.all().get(0);
        assertEquals("WM:trace-1", event.getEventId(), "★ 幂等键口径");
        assertEquals("trace-1", event.getTraceId());
        assertEquals("op-001", event.getOperatorId());
        assertEquals("tenant-9", event.getTenantId());
        assertEquals("C-2026-001", event.getTargetId(), "★ 单号落 targetId");
        assertEquals("VISIBLE_TEXT", event.getTargetType(), "水印类型落 targetType");
    }

    @Test
    @DisplayName("★ 写侧：同一追踪码重放 ⇒ 只留一条（幂等键生效）")
    void recordIsIdempotent() {
        LocalAuditTraceAdapter adapter = adapter();

        adapter.record(trace("trace-1"));
        adapter.record(trace("trace-1"));

        assertEquals(1, store.size(), "★ 幂等键应保证只有一条");
    }

    @Test
    @DisplayName("★ 写侧：追踪码为空 ⇒ 返回 false（不写脏行）")
    void recordRejectsEmptyTraceId() {
        assertFalse(adapter().record(trace("")));
        assertEquals(0, store.size());
    }

    @Test
    @DisplayName("★ 读侧：反查命中 ⇒ 拿到水印视角的上下文")
    void findReturnsWatermarkContext() {
        LocalAuditTraceAdapter adapter = adapter();
        adapter.record(trace("trace-1"));

        WatermarkTrace found = adapter.find("trace-1");

        assertNotNull(found, "★ 应查到");
        assertEquals("trace-1", found.getTraceId());
        assertEquals("op-001", found.getOperatorId());
        assertEquals("C-2026-001", found.getBizNo());
        assertEquals("VISIBLE_TEXT", found.getWatermarkType());
    }

    @Test
    @DisplayName("★ 读侧：台账里没有 ⇒ 返回 null（**不是**抛异常）")
    void findReturnsNullWhenAbsent() {
        assertNull(adapter().find("trace-never"), "★ 查不到 ⇒ null");
    }

    @Test
    @DisplayName("★ 读侧：台账不可用 ⇒ 抛「查不了」（与查不到严格区分）")
    void findThrowsWhenUnavailable() {
        // 没有反查服务 ⇒ 能力缺失 ⇒ 判「查不了」
        AuditService service = new AuditService(store);
        LocalAuditTraceAdapter adapter = new LocalAuditTraceAdapter(service, null);

        assertThrows(WatermarkTraceUnavailableException.class, () -> adapter.find("trace-1"),
                "★ 查不了必须抛异常，不能当成查不到（否则运维会误判成没记录）");
    }

    @Test
    @DisplayName("★ 读侧：同一追踪码下有 WM 行与 SEC 行 ⇒ 反查优先取 WM 行")
    void findPrefersWatermarkRow() {
        LocalAuditTraceAdapter adapter = adapter();
        adapter.record(trace("trace-1"));
        // 再补一条处理审计行（SEC 前缀）
        AuditEvent sec = new AuditEvent();
        sec.setEventId("SEC:trace-1");
        sec.setTraceId("trace-1");
        sec.setOperatorId("op-002");
        sec.setTargetId("B-999");
        sec.setTargetType("CONTRACT_EXPORT");
        store.accept(sec);

        WatermarkTrace found = adapter.find("trace-1");

        assertNotNull(found);
        assertEquals("WM:trace-1", found.getEventId(), "★ 应优先取水印溯源行");
        assertEquals("C-2026-001", found.getBizNo());
    }

    @Test
    @DisplayName("★ 写侧：台账写失败（出口抛异常）⇒ 返回 false（**不外抛**）")
    void recordFailureDoesNotThrow() {
        // ⚠ AuditSink 有两个抽象方法（accept / name）⇒ 不能用 lambda ⇒ 匿名内部类
        AuditService service = new AuditService(new com.zifang.z.audit.core.spi.AuditSink() {
            @Override
            public boolean accept(AuditEvent event) {
                throw new IllegalStateException("库炸了");
            }

            @Override
            public String name() {
                return "broken";
            }
        });
        LocalAuditTraceAdapter adapter = new LocalAuditTraceAdapter(service, null);

        assertFalse(adapter.record(trace("trace-1")), "★ 写失败应返回 false");
    }

    @Test
    @DisplayName("★ 事件列表：反查结果按时间正序（溯源人按时间线看）")
    void lookupEventsAreOrdered() {
        LocalAuditTraceAdapter adapter = adapter();
        adapter.record(trace("trace-1"));
        AuditEvent sec = new AuditEvent();
        sec.setEventId("SEC:trace-1");
        sec.setTraceId("trace-1");
        sec.setOccurredAt(1767225601000L);
        store.accept(sec);

        List<AuditEvent> events = new AuditTraceService(store).lookup("trace-1").getEvents();

        assertEquals(2, events.size());
        assertTrue(events.get(0).getOccurredAt() <= events.get(1).getOccurredAt(),
                "应按时间正序");
    }
}
