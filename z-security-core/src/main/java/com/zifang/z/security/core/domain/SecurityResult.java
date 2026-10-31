package com.zifang.z.security.core.domain;

import com.zifang.z.sense.core.domain.SenseResult;
import com.zifang.z.watermark.core.domain.WatermarkPayload;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 安全流水线结果。
 *
 * <p>把四段的产出汇总成一个对象返回给业务方：
 * <ul>
 *   <li>{@link #getMaskedText()} —— 脱敏后的内容（**这是业务方真正要用的**）；</li>
 *   <li>{@link #getSenseResult()} —— 识别明细（命中位置 / 分级 / 类别）；</li>
 *   <li>{@link #getWatermarkPayload()} —— 打上的水印载荷（溯源用）；</li>
 *   <li>{@link #isBlocked()} + {@link #getBlockReason()} —— 是否被拦截。</li>
 * </ul>
 *
 * @author zifang
 */
public class SecurityResult {

    /** 状态：放行。 */
    public static final String STATUS_PASS = "PASS";
    /** 状态：脱敏后放行。 */
    public static final String STATUS_MASKED = "MASKED";
    /** 状态：已拦截。 */
    public static final String STATUS_BLOCKED = "BLOCKED";

    /** 处理后的内容（脱敏 + 水印后的最终文本）。 */
    private String content;
    /** 状态。 */
    private String status = STATUS_PASS;
    /** 拦截原因。 */
    private String blockReason;
    /** 识别明细（可为 null —— 没跑 SENSE 阶段）。 */
    private SenseResult senseResult;
    /** 水印载荷（可为 null —— 没跑 WATERMARK 阶段）。 */
    private WatermarkPayload watermarkPayload;
    /** 脱敏条数。 */
    private int maskedCount;
    /** 命中最高级别（码，如 {@code L3}；无命中为 null）。 */
    private String maxLevel;    /** 耗时（毫秒）。 */
    private long elapsedMillis;
    /** 追踪 ID（审计用）。 */
    private String traceId;
    /**
     * ★ 溯源台账错误（M2 #22）。
     *
     * <p><b>为什么要有这个字段</b>：水印打上了但**台账没写成** ⇒
     * 这份内容「有水印、无留痕」⇒ 泄密后拿水印里的追踪码**查不到任何东西**
     * ⇒ 这是**合规缺口**，不是正常流程。
     *
     * <p>⚠ 不能静默吞掉：缺口必须能上报给调用方（否则合规告警永远不会响）。
     * 注意它**不阻断主链路** —— 内容照常返回，只是把缺口标出来。
     */
    private String traceError;

    public String getContent() {
        return content;
    }

    public void setContent(String content) {
        this.content = content;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getBlockReason() {
        return blockReason;
    }

    public void setBlockReason(String blockReason) {
        this.blockReason = blockReason;
    }

    public SenseResult getSenseResult() {
        return senseResult;
    }

    public void setSenseResult(SenseResult senseResult) {
        this.senseResult = senseResult;
    }

    public WatermarkPayload getWatermarkPayload() {
        return watermarkPayload;
    }

    public void setWatermarkPayload(WatermarkPayload watermarkPayload) {
        this.watermarkPayload = watermarkPayload;
    }

    public int getMaskedCount() {
        return maskedCount;
    }

    public void setMaskedCount(int maskedCount) {
        this.maskedCount = maskedCount;
    }

    public String getMaxLevel() {
        return maxLevel;
    }

    public void setMaxLevel(String maxLevel) {
        this.maxLevel = maxLevel;
    }

    public long getElapsedMillis() {
        return elapsedMillis;
    }

    public void setElapsedMillis(long elapsedMillis) {
        this.elapsedMillis = elapsedMillis;
    }

    public String getTraceId() {
        return traceId;
    }

    public void setTraceId(String traceId) {
        this.traceId = traceId;
    }

    public String getTraceError() {
        return traceError;
    }

    public void setTraceError(String traceError) {
        this.traceError = traceError;
    }

    /**
     * 是否被拦截。
     *
     * @return true = 拦截
     */
    public boolean isBlocked() {
        return STATUS_BLOCKED.equals(status);
    }

    /**
     * 汇总视图。
     *
     * @return 键值视图
     */
    public Map<String, Object> toView() {
        Map<String, Object> view = new LinkedHashMap<>();
        view.put("status", status);
        view.put("content", content);
        view.put("traceId", traceId);
        view.put("maskedCount", maskedCount);
        view.put("maxLevel", maxLevel);
        view.put("blockReason", blockReason);
        view.put("elapsedMillis", elapsedMillis);
        view.put("traceError", traceError);
        if (senseResult != null) {
            view.put("hitCount", senseResult.getHits() == null ? 0 : senseResult.getHits().size());
            view.put("categoryCounts", senseResult.getCategoryCounts());
        } else {
            view.put("hitCount", 0);
        }
        return view;
    }
}
