package com.zifang.z.security.core.domain;

import com.zifang.z.watermark.core.domain.WatermarkType;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * 策略版本（**台账的一行**）。
 *
 * <p><b>为什么策略版本与 {@link SecurityPolicy} 分开</b>：
 * {@link SecurityPolicy} 是「运行时的策略对象」（只关心当前生效的配置），
 * 本类是「台账的版本记录」（关心**谁在什么时候改了什么、能不能回滚**）。
 * 混在一起 ⇒ 运行时对象里塞满审计字段 ⇒ 每个消费方都要理解台账语义。
 *
 * <p><b>不可变</b>：版本一旦写入台账就不再改（要改就发新版本）。
 * 这让「当前生效的是哪一版」永远有唯一答案，也让回滚 = 「把老版本重新发布」。
 *
 * @author zifang
 */
public class PolicyRevision {

    /** 策略 ID（同一策略的多版本共享同一个 ID）。 */
    private String policyId;
    /** 业务场景码。 */
    private String scene;
    /** 版本号（**从 1 递增**）。 */
    private int revision;
    /** 状态。 */
    private PolicyStatus status = PolicyStatus.DRAFT;
    /** 阶段序列（**顺序即执行顺序**，逗号分隔存储）。 */
    private String stages;
    /** 水印类型。 */
    private String watermarkType;
    /** 拦截阈值（级别码；空 ⇒ 不拦）。 */
    private String blockThreshold;
    /** 脱敏策略集 ID。 */
    private String maskPolicySetId;
    /** 是否启用。 */
    private boolean enabled = true;
    /** 备注。 */
    private String remark;
    /** 变更原因（**审计要求**：为什么改）。 */
    private String changeReason;
    /** 操作人。 */
    private String operatorId;
    /** 创建时刻（epoch 毫秒）。 */
    private long createdAt;

    public PolicyRevision() {
    }

    /**
     * 构造（版本号从 1 起）。
     *
     * @param policyId 策略 ID
     * @param scene    场景码
     * @param revision 版本号
     */
    public PolicyRevision(String policyId, String scene, int revision) {
        this.policyId = policyId;
        this.scene = scene;
        this.revision = revision;
    }

    /**
     * 从运行时策略构造版本记录。
     *
     * @param policy   运行时策略
     * @param revision 版本号
     * @param status   状态
     * @param operator 操作人
     * @param reason   变更原因
     * @return 版本记录
     */
    public static PolicyRevision from(SecurityPolicy policy, int revision, PolicyStatus status,
                                      String operator, String reason) {
        PolicyRevision r = new PolicyRevision(policy.getPolicyId(), policy.getScene(), revision);
        r.setStatus(status);
        r.setStages(joinStages(policy.getStages()));
        r.setWatermarkType(policy.getWatermarkType() == null
                ? null : policy.getWatermarkType().name());
        r.setBlockThreshold(policy.getBlockThreshold());
        r.setMaskPolicySetId(policy.getMaskPolicySetId());
        r.setEnabled(policy.isEnabled());
        r.setRemark(policy.getRemark());
        r.setOperatorId(operator);
        r.setChangeReason(reason);
        r.setCreatedAt(System.currentTimeMillis());
        return r;
    }

    /**
     * 版本记录 → 运行时策略。
     *
     * <p><b>★ 阶段解析失败 ⇒ 整条策略不生效</b>（不静默丢阶段）：
     * 静默丢一个阶段会让「本该跑审计的场景不审计」⇒ 合规留痕缺失且无人察觉。
     * 宁可让这条策略解析失败（调用方拿不到 ⇒ 走兜底）。
     *
     * @return 运行时策略；解析失败返回 {@code null}
     */
    public SecurityPolicy toPolicy() {
        SecurityPolicy p = new SecurityPolicy(policyId, scene);
        List<SecurityStage> parsed = parseStages(stages);
        if (parsed == null) {
            return null;
        }
        p.setStages(parsed);
        WatermarkType wt = WatermarkType.fromCode(watermarkType);
        if (wt == null) {
            wt = WatermarkType.VISIBLE_TEXT;
        }
        p.setWatermarkType(wt);
        p.setBlockThreshold(blockThreshold);
        p.setMaskPolicySetId(maskPolicySetId);
        p.setEnabled(enabled);
        p.setRemark(remark);
        return p;
    }

    /**
     * 阶段序列 → 逗号分隔字符串。
     *
     * @param stages 阶段列表
     * @return 字符串
     */
    public static String joinStages(List<SecurityStage> stages) {
        if (stages == null || stages.isEmpty()) {
            return "";
        }
        List<String> names = new ArrayList<>();
        for (SecurityStage s : stages) {
            if (s != null) {
                names.add(s.name());
            }
        }
        return String.join(",", names);
    }

    /**
     * 逗号分隔字符串 → 阶段列表。
     *
     * @param stages 字符串（可空 ⇒ 空列表）
     * @return 阶段列表；**含无法识别的阶段 ⇒ 返回 {@code null}**（整条策略不生效）
     */
    public static List<SecurityStage> parseStages(String stages) {
        List<SecurityStage> list = new ArrayList<>();
        if (stages == null || stages.trim().isEmpty()) {
            return list;
        }
        for (String part : stages.split(",")) {
            String t = part.trim();
            if (t.isEmpty()) {
                continue;
            }
            SecurityStage s = SecurityStage.fromCode(t);
            if (s == null) {
                // ⚠ 未知阶段 ⇒ 整条策略不生效（不静默丢）
                return null;
            }
            list.add(s);
        }
        return Collections.unmodifiableList(list);
    }

    /** 是否为当前生效版本。 */
    public boolean isPublished() {
        return status == PolicyStatus.PUBLISHED;
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

    public int getRevision() {
        return revision;
    }

    public void setRevision(int revision) {
        this.revision = revision;
    }

    public PolicyStatus getStatus() {
        return status;
    }

    public void setStatus(PolicyStatus status) {
        this.status = status;
    }

    public String getStages() {
        return stages;
    }

    public void setStages(String stages) {
        this.stages = stages;
    }

    public String getWatermarkType() {
        return watermarkType;
    }

    public void setWatermarkType(String watermarkType) {
        this.watermarkType = watermarkType;
    }

    public String getBlockThreshold() {
        return blockThreshold;
    }

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

    public String getChangeReason() {
        return changeReason;
    }

    public void setChangeReason(String changeReason) {
        this.changeReason = changeReason;
    }

    public String getOperatorId() {
        return operatorId;
    }

    public void setOperatorId(String operatorId) {
        this.operatorId = operatorId;
    }

    public long getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(long createdAt) {
        this.createdAt = createdAt;
    }

    @Override
    public String toString() {
        return "PolicyRevision{" + policyId + " scene=" + scene + " rev=" + revision
                + " status=" + status + "}";
    }
}
