package com.zifang.z.security.core.service;

import com.zifang.z.audit.core.domain.AuditAction;
import com.zifang.z.audit.core.domain.AuditEvent;
import com.zifang.z.audit.core.domain.AuditResult;
import com.zifang.z.audit.core.domain.AuditTraceResult;
import com.zifang.z.audit.core.service.AuditService;
import com.zifang.z.audit.core.service.AuditTraceService;
import com.zifang.z.watermark.core.domain.WatermarkTrace;
import com.zifang.z.watermark.core.spi.WatermarkTraceQuery;
import com.zifang.z.watermark.core.spi.WatermarkTraceRecorder;

import java.util.List;

/**
 * ★ 编排层的溯源台账适配器（M2 #22）。
 *
 * <p><b>解决什么</b>：编排层跑完流水线后有<b>两条</b>留痕需求 ——
 * <ol>
 *   <li><b>水印溯源行</b>（{@code eventId = WM:<traceId>}）：
 *       「这份内容被打了水印，追踪码是 X，操作人是 Y，单号是 Z」；
 *   <li><b>处理审计行</b>（{@code eventId = SEC:<traceId>}）：
 *       「这次安全处理发生过，脱敏了几处，命中没命中」。</li>
 * </ol>
 * 早先实现里，编排层只写第 2 条；第 1 条依赖水印域的出口 ——
 * 但水印域是**独立服务**（走 HTTP 交给 z-audit 写）⇒
 * 编排层若不自己写，第 1 条在「编排层与审计域同进程部署」下就<b>永远缺位</b>，
 * 而 {@code embedTraced} 只会标一句「未配置溯源台账出口」⇒
 * <b>打了水印却没留痕，且没人知道</b>。
 *
 * <p><b>★ 本适配器就是补这一条</b>：把水印域的 {@link WatermarkTrace}
 * 转成审计域的 {@link AuditEvent}，交给**同一个** {@link AuditService} 写 ——
 * 于是两条行共享同一条哈希链的链尾 ⇒ 链不分叉。
 *
 * <p><b>★ 单写者口径</b>：{@code z_audit_event} 表的**唯一权威写者是 z-audit 服务**。
 * 本适配器直写同一张表，适用于「<b>编排层与审计域同进程部署</b>」；
 * 若两者分进程部署，编排层必须改走 HTTP 交给 z-audit 写
 * （否则两个进程各持链尾 ⇒ 两条链分叉 ⇒ 链校验必然报断）。
 *
 * <p><b>幂等</b>：事件 ID 固定 {@code WM:<traceId>} ⇒ 同一追踪码重放只留一条。
 *
 * @author zifang
 */
public class LocalAuditTraceAdapter implements WatermarkTraceRecorder, WatermarkTraceQuery {

    /** 审计门面（写侧）。 */
    private final AuditService auditService;

    /** 反查服务（读侧）。 */
    private final AuditTraceService traceService;

    /**
     * 构造。
     *
     * @param auditService  审计门面（**不可为 null**）
     * @param traceService  反查服务（可空 ⇒ 无反查能力）
     */
    public LocalAuditTraceAdapter(AuditService auditService, AuditTraceService traceService) {
        this.auditService = auditService;
        this.traceService = traceService;
    }

    /**
     * ★ 写一条水印溯源行。
     *
     * <p>⚠️ 写失败**返回 false 而不抛异常**（SPI 契约）：台账是辅链路，
     * 流水线主链路不能因为台账炸了而中断。
     *
     * @param trace 溯源记录
     * @return 是否写成
     */
    @Override
    public boolean record(WatermarkTrace trace) {
        if (trace == null || trace.getTraceId() == null || trace.getTraceId().isEmpty()) {
            return false;
        }
        if (auditService == null) {
            return false;
        }
        try {
            AuditEvent event = new AuditEvent();
            event.setEventId(trace.getEventId() == null || trace.getEventId().isEmpty()
                    ? WatermarkTrace.defaultEventId(trace.getTraceId())
                    : trace.getEventId());
            event.setTraceId(trace.getTraceId());
            event.setOperatorId(trace.getOperatorId());
            event.setTenantId(trace.getTenantId());
            event.setAction(AuditAction.WATERMARK);
            event.setResult(AuditResult.SUCCESS);
            // ★ targetType 记水印类型（溯源时能看出是哪种水印），
            //    targetId 记业务单号（溯源时能看出是哪份单子）。
            event.setTargetType(trace.getWatermarkType() == null
                    ? "WATERMARK" : trace.getWatermarkType());
            event.setTargetId(trace.getBizNo());
            event.setDetail(trace.getRemark());
            if (trace.getOccurredAt() > 0) {
                event.setOccurredAt(trace.getOccurredAt());
            }
            // ★ 用 recordWithOutcome：**「有没有真落库」必须如实反映**。
            //    早先用 record(event) ⇒ 台账炸了也返回非 null ⇒ 适配器报「已留痕」
            //    ⇒ 合规缺口被静默掩盖（「打了水印却没留痕」没人知道）。
            AuditService.AuditOutcome outcome = auditService.recordWithOutcome(event);
            if (outcome == null) {
                return false;
            }
            if (!outcome.isAccepted()) {
                // ★ 出口拒收有**两种**含义，必须区分：
                //   - **幂等命中**：这条记录**已经在台账里**了 ⇒ 留痕在 ⇒ **不算缺口**；
                //   - **落库失败**：台账里真没有 ⇒ **合规缺口**（打了水印却没留痕）。
                // 出口的 accept() 返回 false 时**不告诉你是哪一种** ⇒ 只能回查台账。
                if (alreadyRecorded(trace.getTraceId())) {
                    return true;
                }
                System.err.println("[z-security] 水印溯源行未落台账（traceId="
                        + trace.getTraceId() + "，落库失败）");
                return false;
            }
            return true;
        } catch (RuntimeException e) {
            System.err.println("[z-security] 水印溯源行写入失败（traceId=" + trace.getTraceId()
                    + "）：" + e.getMessage());
            return false;
        }
    }

    /**
     * ★ 这条追踪码**是否已经在台账里**（用于区分「幂等命中」与「落库失败」）。
     *
     * <p>出口的 {@code accept()} 返回 false 时不告诉你是哪一种 ⇒ 只能回查。
     * 查不到 ⇒ 判成落库失败 ⇒ 如实报缺口（不静默）。
     *
     * @param traceId 追踪码
     * @return true = 台账里已有
     */
    private boolean alreadyRecorded(String traceId) {
        if (traceService == null) {
            return false;
        }
        try {
            AuditTraceResult result = traceService.lookup(traceId);
            return result.isFound();
        } catch (RuntimeException e) {
            return false;
        }
    }

    /**
     * ★ 按追踪码反查（取水印溯源那条）。
     *
     * <p>⚠️ **「查不到」与「查不了」必须区分**：
     * <ul>
     *   <li>台账里没有 ⇒ 返回 {@code null}（合规缺口）；</li>
     *   <li>台账不可用 ⇒ 抛
     *       {@link com.zifang.z.watermark.core.spi.WatermarkTraceUnavailableException}
     *       （基础设施故障）。</li>
     * </ul>
     *
     * @param traceId 追踪码
     * @return 溯源记录；查不到返回 null
     */
    @Override
    public WatermarkTrace find(String traceId) {
        if (traceId == null || traceId.isEmpty()) {
            return null;
        }
        if (traceService == null) {
            throw new com.zifang.z.watermark.core.spi.WatermarkTraceUnavailableException(
                    "未配置溯源台账查询出口");
        }
        AuditTraceResult result = traceService.lookup(traceId);
        if (result.isUnavailable()) {
            throw new com.zifang.z.watermark.core.spi.WatermarkTraceUnavailableException(
                    result.getMessage());
        }
        if (!result.isFound()) {
            return null;
        }
        return toWatermarkTrace(result.getEvents(), traceId);
    }

    @Override
    public String name() {
        return "local-audit-ledger";
    }

    /**
     * 审计事件列表 → 水印溯源记录。
     *
     * <p>⚠️ 同一追踪码下可能有**两条**行（水印溯源行 {@code WM:} + 处理审计行 {@code SEC:}）
     * ⇒ 这里<b>优先取水印行</b>（eventId 以 {@code WM:} 开头），
     * 取不到再退回第一条 —— 保证反查给出的是「水印」视角的上下文。
     *
     * @param events  审计事件（正序）
     * @param traceId 追踪码
     * @return 溯源记录
     */
    private static WatermarkTrace toWatermarkTrace(List<AuditEvent> events, String traceId) {
        if (events == null || events.isEmpty()) {
            return null;
        }
        AuditEvent picked = null;
        for (AuditEvent e : events) {
            if (e.getEventId() != null && e.getEventId().startsWith("WM:")) {
                picked = e;
                break;
            }
        }
        if (picked == null) {
            picked = events.get(0);
        }
        WatermarkTrace trace = new WatermarkTrace();
        trace.setTraceId(traceId);
        trace.setEventId(picked.getEventId());
        trace.setOperatorId(picked.getOperatorId());
        trace.setTenantId(picked.getTenantId());
        trace.setBizNo(picked.getTargetId());
        trace.setWatermarkType(picked.getTargetType());
        trace.setOccurredAt(picked.getOccurredAt());
        trace.setRemark(picked.getDetail());
        return trace;
    }
}
