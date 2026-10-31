package com.zifang.z.security.core.domain;

import com.zifang.z.watermark.core.domain.WatermarkType;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * 安全策略（一条编排配置）。
 *
 * <p><b>策略即数据</b>：一条策略说清楚「哪个业务场景（{@code scene}）下，
 * 跑哪几段流水线（{@link #stages}）、用哪种水印（{@link #watermarkType}）、
 * 命中什么级别才拦（{@link #blockThreshold}）」。
 *
 * <p><b>为什么要有 blockThreshold</b>：识别出来的敏感数据不一定都要拦。
 * 例：L2 内部信息只脱敏不拦（照常返回给有权限的人），
 * L4 核心数据（身份证 / 银行卡）直接拒绝返回（{@code SENSITIVE_BLOCKED}）。
 * 一个阈值把「脱敏」和「拦截」分开，避免一刀切。
 *
 * @author zifang
 */
public class SecurityPolicy {

    /** 策略 ID。 */
    private String policyId;
    /** 业务场景码（如 {@code CONTRACT_EXPORT}）。 */
    private String scene;
    /** 执行的阶段序列（**顺序即执行顺序**）。 */
    private List<SecurityStage> stages = SecurityStage.defaultOrder();
    /** 水印类型（跑 WATERMARK 阶段时用）。 */
    private WatermarkType watermarkType = WatermarkType.VISIBLE_TEXT;
    /** 拦截阈值（命中级别 ≥ 该值 ⇒ 拦下不让出域）。 */
    private String blockThreshold = "L4";
    /** 脱敏策略集 ID（跑 MASK 阶段时用；对应 z-mask 的策略集）。 */
    private String maskPolicySetId;
    /** 是否启用。 */
    private boolean enabled = true;
    /** 备注。 */
    private String remark;

    public SecurityPolicy() {
    }

    /**
     * 构造。
     *
     * @param policyId 策略 ID
     * @param scene    场景码
     */
    public SecurityPolicy(String policyId, String scene) {
        this.policyId = policyId;
        this.scene = scene;
    }

    /**
     * 取「只脱敏不拦」的宽松策略（默认档）。
     *
     * @param policyId 策略 ID
     * @param scene    场景码
     * @return 策略
     */
    public static SecurityPolicy lenient(String policyId, String scene) {
        SecurityPolicy p = new SecurityPolicy(policyId, scene);
        p.setBlockThreshold("L4");
        return p;
    }

    /**
     * 取「严格拦截」策略（L3 及以上就拦）。
     *
     * @param policyId 策略 ID
     * @param scene    场景码
     * @return 策略
     */
    public static SecurityPolicy strict(String policyId, String scene) {
        SecurityPolicy p = new SecurityPolicy(policyId, scene);
        p.setBlockThreshold("L3");
        return p;
    }

    /**
     * 是否跑某阶段。
     *
     * @param stage 阶段
     * @return true = 跑
     */
    public boolean runs(SecurityStage stage) {
        return enabled && stages != null && stages.contains(stage);
    }

    /**
     * 阶段序列（只读）。
     *
     * @return 阶段列表
     */
    public List<SecurityStage> getStages() {
        return stages == null ? Collections.emptyList() : Collections.unmodifiableList(stages);
    }

    /**
     * 设阶段序列。
     *
     * @param stages 阶段列表（空 ⇒ 不跑任何阶段）
     */
    public void setStages(List<SecurityStage> stages) {
        this.stages = stages == null ? new ArrayList<>() : new ArrayList<>(stages);
    }

    public String getPolicyId() {
        return policyId;
    }

    public void setPolicyId(String policyId) {
        this.policyId = policyId;
    }

    public String getScene() {
        return scene;
    }

    public void setScene(String scene) {
        this.scene = scene;
    }

    public WatermarkType getWatermarkType() {
        return watermarkType;
    }

    public void setWatermarkType(WatermarkType watermarkType) {
        this.watermarkType = watermarkType;
    }

    public String getBlockThreshold() {
        return blockThreshold;
    }

    /**
     * 设拦截阈值（级别码，如 {@code L3}）。
     *
     * @param blockThreshold 阈值（空 ⇒ 不拦）
     */
    public void setBlockThreshold(String blockThreshold) {
        this.blockThreshold = blockThreshold;
    }

    public String getMaskPolicySetId() {
        return maskPolicySetId;
    }

    public void setMaskPolicySetId(String maskPolicySetId) {
        this.maskPolicySetId = maskPolicySetId;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getRemark() {
        return remark;
    }

    public void setRemark(String remark) {
        this.remark = remark;
    }

    @Override
    public String toString() {
        return "SecurityPolicy{" + policyId + " scene=" + scene + " stages=" + stages
                + " watermark=" + watermarkType + " blockAt=" + blockThreshold + "}";
    }

    /**
     * 构造器便捷方法（供测试与代码内组装）。
     *
     * @param policyId      策略 ID
     * @param scene         场景码
     * @param stages        阶段序列
     * @param watermarkType 水印类型
     * @param blockAt       拦截阈值
     * @return 策略
     */
    public static SecurityPolicy of(String policyId, String scene, List<SecurityStage> stages,
                                    WatermarkType watermarkType, String blockAt) {
        SecurityPolicy p = new SecurityPolicy(policyId, scene);
        p.setStages(new ArrayList<>(stages));
        p.setWatermarkType(watermarkType);
        p.setBlockThreshold(blockAt);
        return p;
    }

    /**
     * 默认阶段序列的快捷构造（跑全四段）。
     *
     * @param policyId 策略 ID
     * @param scene    场景码
     * @return 策略
     */
    public static SecurityPolicy full(String policyId, String scene) {
        return new SecurityPolicy(policyId, scene);
    }

    /**
     * 常用阶段序列：只识别 + 脱敏（不水印不审计）。
     *
     * @return 阶段序列
     */
    public static List<SecurityStage> senseMaskOnly() {
        return Arrays.asList(SecurityStage.SENSE, SecurityStage.MASK);
    }
}
