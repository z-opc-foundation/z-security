package com.zifang.z.security.core.service;

import com.zifang.z.security.core.domain.PolicyRevision;
import com.zifang.z.security.core.domain.PolicyRevisionRecord;
import com.zifang.z.security.core.domain.PolicyStatus;
import com.zifang.z.security.core.mapper.SecurityPolicyMapper;
import com.zifang.z.security.core.spi.PolicyStore;

import java.util.ArrayList;
import java.util.List;

/**
 * 落库版策略台账存储。
 *
 * <p><b>不抛异常</b>：策略台账是辅链路，读写失败不外抛（退回内置策略继续跑）。
 *
 * @author zifang
 */
public class PersistentPolicyStore implements PolicyStore {

    /** Mapper。 */
    private final SecurityPolicyMapper mapper;

    /**
     * 构造。
     *
     * @param mapper Mapper（**不可为 null**）
     */
    public PersistentPolicyStore(SecurityPolicyMapper mapper) {
        this.mapper = mapper;
    }

    @Override
    public boolean save(PolicyRevision revision) {
        if (revision == null || revision.getPolicyId() == null
                || revision.getPolicyId().isEmpty()) {
            return false;
        }
        try {
            mapper.insert(toRecord(revision));
            return true;
        } catch (RuntimeException e) {
            System.err.println("[z-security] 写策略版本失败（policyId="
                    + revision.getPolicyId() + "）：" + e.getMessage());
            return false;
        }
    }

    @Override
    public PolicyRevision findPublished(String scene) {
        if (scene == null || scene.isEmpty()) {
            return null;
        }
        try {
            PolicyRevisionRecord record = mapper.selectPublished(scene);
            return record == null ? null : toDomain(record);
        } catch (RuntimeException e) {
            System.err.println("[z-security] 读生效策略失败（scene=" + scene
                    + "）：" + e.getMessage());
            return null;
        }
    }

    @Override
    public PolicyRevision findRevision(String policyId, int revision) {
        if (policyId == null || policyId.isEmpty()) {
            return null;
        }
        try {
            PolicyRevisionRecord record = mapper.selectByRevision(policyId, revision);
            return record == null ? null : toDomain(record);
        } catch (RuntimeException e) {
            System.err.println("[z-security] 读策略版本失败（policyId=" + policyId
                    + " rev=" + revision + "）：" + e.getMessage());
            return null;
        }
    }

    @Override
    public List<PolicyRevision> listByPolicy(String policyId) {
        try {
            List<PolicyRevisionRecord> records = mapper.selectByPolicy(policyId);
            List<PolicyRevision> out = new ArrayList<>();
            if (records != null) {
                for (PolicyRevisionRecord r : records) {
                    out.add(toDomain(r));
                }
            }
            return out;
        } catch (RuntimeException e) {
            System.err.println("[z-security] 列策略版本失败：" + e.getMessage());
            return new ArrayList<>();
        }
    }

    @Override
    public List<PolicyRevision> listPublished() {
        try {
            List<PolicyRevisionRecord> records = mapper.selectAllPublished();
            List<PolicyRevision> out = new ArrayList<>();
            if (records != null) {
                for (PolicyRevisionRecord r : records) {
                    out.add(toDomain(r));
                }
            }
            return out;
        } catch (RuntimeException e) {
            System.err.println("[z-security] 列生效策略失败：" + e.getMessage());
            return new ArrayList<>();
        }
    }

    @Override
    public List<PolicyRevision> listAll() {
        try {
            List<PolicyRevisionRecord> records = mapper.selectAll();
            List<PolicyRevision> out = new ArrayList<>();
            if (records != null) {
                for (PolicyRevisionRecord r : records) {
                    out.add(toDomain(r));
                }
            }
            return out;
        } catch (RuntimeException e) {
            System.err.println("[z-security] 列策略台账失败：" + e.getMessage());
            return new ArrayList<>();
        }
    }

    @Override
    public int maxRevision(String policyId) {
        if (policyId == null || policyId.isEmpty()) {
            return 0;
        }
        try {
            return mapper.maxRevision(policyId);
        } catch (RuntimeException e) {
            System.err.println("[z-security] 取最大版本号失败：" + e.getMessage());
            return 0;
        }
    }

    @Override
    public int supersedePublished(String scene) {
        if (scene == null || scene.isEmpty()) {
            return 0;
        }
        try {
            return mapper.supersedePublished(scene);
        } catch (RuntimeException e) {
            System.err.println("[z-security] 取代旧版本失败（scene=" + scene
                    + "）：" + e.getMessage());
            return 0;
        }
    }

    @Override
    public int updateStatus(String policyId, int revision, String status) {
        if (policyId == null || policyId.isEmpty() || status == null) {
            return 0;
        }
        try {
            return mapper.updateStatus(policyId, revision, status);
        } catch (RuntimeException e) {
            System.err.println("[z-security] 改策略状态失败：" + e.getMessage());
            return 0;
        }
    }

    @Override
    public int delete(String policyId, int revision) {
        if (policyId == null || policyId.isEmpty()) {
            return 0;
        }
        try {
            return mapper.delete(policyId, revision);
        } catch (RuntimeException e) {
            System.err.println("[z-security] 删策略版本失败：" + e.getMessage());
            return 0;
        }
    }

    /** 领域对象 → 落库实体。 */
    private static PolicyRevisionRecord toRecord(PolicyRevision r) {
        PolicyRevisionRecord rec = new PolicyRevisionRecord();
        rec.setPolicyId(r.getPolicyId());
        rec.setScene(r.getScene());
        rec.setRevision(r.getRevision());
        rec.setStatus(r.getStatus() == null ? null : r.getStatus().name());
        rec.setStages(r.getStages());
        rec.setWatermarkType(r.getWatermarkType());
        rec.setBlockThreshold(r.getBlockThreshold());
        rec.setMaskPolicySetId(r.getMaskPolicySetId());
        rec.setEnabled(r.isEnabled());
        rec.setRemark(r.getRemark());
        rec.setChangeReason(r.getChangeReason());
        rec.setOperatorId(r.getOperatorId());
        rec.setCreatedAt(r.getCreatedAt() <= 0 ? System.currentTimeMillis() : r.getCreatedAt());
        return rec;
    }

    /** 落库实体 → 领域对象。 */
    private static PolicyRevision toDomain(PolicyRevisionRecord rec) {
        PolicyRevision r = new PolicyRevision(rec.getPolicyId(), rec.getScene(),
                rec.getRevision() == null ? 0 : rec.getRevision());
        PolicyStatus status = PolicyStatus.fromCode(rec.getStatus());
        r.setStatus(status == null ? PolicyStatus.DRAFT : status);
        r.setStages(rec.getStages());
        r.setWatermarkType(rec.getWatermarkType());
        r.setBlockThreshold(rec.getBlockThreshold());
        r.setMaskPolicySetId(rec.getMaskPolicySetId());
        r.setEnabled(rec.getEnabled() == null || rec.getEnabled());
        r.setRemark(rec.getRemark());
        r.setChangeReason(rec.getChangeReason());
        r.setOperatorId(rec.getOperatorId());
        r.setCreatedAt(rec.getCreatedAt() == null ? 0L : rec.getCreatedAt());
        return r;
    }
}
