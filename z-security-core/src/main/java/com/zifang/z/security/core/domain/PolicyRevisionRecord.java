package com.zifang.z.security.core.domain;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableField;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import com.zifang.z.meta.api.annotation.BizField;
import com.zifang.z.meta.api.annotation.BizModel;

/**
 * 策略版本落库实体（表 {@code z_security_policy}）。
 *
 * <p><b>实体与领域对象分离</b>：{@link PolicyRevision} 是领域模型，
 * 本类是持久化载体（只管字段映射）⇒ 领域模型不被 ORM 注解污染。
 *
 * <p>⚠️ **不能用 {@code Map<String,Object>}**：H2 在 {@code MODE=MySQL} 下会把未加引号的
 * 别名转成大写（{@code AS tenantId} ⇒ {@code TENANTID}），
 * MyBatis 映射成 Map 时直接用原始列标签做 key ⇒ 取不到值；映射成实体则正常。
 *
 * @author zifang
 */
@BizModel(name = "策略版本落库实体（表 z_security_policy）", module = "z-security", description = "策略版本落库实体（表 z_security_policy）。 实体与领域对象分离 ：PolicyRevision 是领域模型， 本类是持久化载体（只管字段映射）⇒ 领域模型不被 ORM 注解污染。 ⚠️ 不能用 Map ：H2 在 MODE=MySQL 下会把未加引号的 别名转成大写（AS tenantId ⇒ TENANTID）， MyBatis 映射成 Map 时直接用原始列标签做 key ⇒ 取不到值；映射成实体则正常。")
@TableName("z_security_policy")
public class PolicyRevisionRecord {

    /** 主键。 */
    @TableId(type = IdType.AUTO)
    @BizField(name = "主键", type = BizField.FieldType.INTEGER)
    private Long id;
    /** 策略 ID。 */
    @BizField(name = "策略 ID", type = BizField.FieldType.STRING)
    private String policyId;
    /** 场景码。 */
    @BizField(name = "场景码", type = BizField.FieldType.STRING)
    private String scene;
    /** 版本号。 */
    @BizField(name = "版本号", type = BizField.FieldType.INTEGER)
    private Integer revision;
    /** 状态码。 */
    @BizField(name = "状态码", type = BizField.FieldType.STRING)
    private String status;
    /** 阶段序列（逗号分隔）。 */
    @BizField(name = "阶段序列（逗号分隔）", type = BizField.FieldType.STRING)
    private String stages;
    /** 水印类型。 */
    @BizField(name = "水印类型", type = BizField.FieldType.STRING)
    private String watermarkType;
    /** 拦截阈值。 */
    @BizField(name = "拦截阈值", type = BizField.FieldType.STRING)
    private String blockThreshold;
    /** 脱敏策略集 ID。 */
    @BizField(name = "脱敏策略集 ID", type = BizField.FieldType.STRING)
    private String maskPolicySetId;
    /** 是否启用。 */
    @BizField(name = "是否启用", type = BizField.FieldType.BOOLEAN)
    private Boolean enabled;
    /** 备注。 */
    @BizField(name = "备注", type = BizField.FieldType.STRING)
    private String remark;
    /** 变更原因。 */
    @BizField(name = "变更原因", type = BizField.FieldType.STRING)
    private String changeReason;
    /** 操作人。 */
    @BizField(name = "操作人", type = BizField.FieldType.STRING)
    private String operatorId;
    /** 创建时刻（epoch 毫秒）。 */
    @BizField(name = "创建时刻（epoch 毫秒）", type = BizField.FieldType.INTEGER)
    private Long createdAt;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
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

    public Integer getRevision() {
        return revision;
    }

    public void setRevision(Integer revision) {
        this.revision = revision;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
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

    public Boolean getEnabled() {
        return enabled;
    }

    public void setEnabled(Boolean enabled) {
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

    public Long getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Long createdAt) {
        this.createdAt = createdAt;
    }
}



