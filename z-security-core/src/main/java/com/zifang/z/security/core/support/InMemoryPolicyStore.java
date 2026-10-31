package com.zifang.z.security.core.support;

import com.zifang.z.security.core.domain.PolicyRevision;
import com.zifang.z.security.core.domain.PolicyStatus;
import com.zifang.z.security.core.spi.PolicyStore;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 内存版策略台账存储（**测试 / 轻量场景**）。
 *
 * <p><b>★ 读回返回副本</b>：不把内部对象直接交出去 ⇒ 调用方改了返回对象
 * 不会污染台账（M1 的 {@code InMemoryAuditStore} 踩过「删副本没删到真数据」的坑，
 * 这里从一开始就把副本语义做对）。
 *
 * @author zifang
 */
public class InMemoryPolicyStore implements PolicyStore {

    /** 策略 ID → 版本号 → 版本记录。 */
    private final Map<String, Map<Integer, PolicyRevision>> byPolicy = new ConcurrentHashMap<>();

    @Override
    public boolean save(PolicyRevision revision) {
        if (revision == null || revision.getPolicyId() == null
                || revision.getPolicyId().isEmpty()) {
            return false;
        }
        byPolicy.computeIfAbsent(revision.getPolicyId(), k -> new ConcurrentHashMap<>())
                .put(revision.getRevision(), copy(revision));
        return true;
    }

    @Override
    public PolicyRevision findPublished(String scene) {
        if (scene == null || scene.isEmpty()) {
            return null;
        }
        PolicyRevision best = null;
        for (Map<Integer, PolicyRevision> versions : byPolicy.values()) {
            for (PolicyRevision r : versions.values()) {
                if (r.getStatus() != PolicyStatus.PUBLISHED) {
                    continue;
                }
                if (!scene.equals(r.getScene())) {
                    continue;
                }
                if (best == null || r.getRevision() > best.getRevision()) {
                    best = r;
                }
            }
        }
        return best == null ? null : copy(best);
    }

    @Override
    public PolicyRevision findRevision(String policyId, int revision) {
        if (policyId == null || policyId.isEmpty()) {
            return null;
        }
        Map<Integer, PolicyRevision> versions = byPolicy.get(policyId);
        if (versions == null) {
            return null;
        }
        PolicyRevision r = versions.get(revision);
        return r == null ? null : copy(r);
    }

    @Override
    public List<PolicyRevision> listByPolicy(String policyId) {
        List<PolicyRevision> out = new ArrayList<>();
        Map<Integer, PolicyRevision> versions = byPolicy.get(policyId);
        if (versions == null) {
            return out;
        }
        for (PolicyRevision r : versions.values()) {
            out.add(copy(r));
        }
        out.sort((a, b) -> Integer.compare(b.getRevision(), a.getRevision()));
        return out;
    }

    @Override
    public List<PolicyRevision> listPublished() {
        List<PolicyRevision> out = new ArrayList<>();
        for (Map<Integer, PolicyRevision> versions : byPolicy.values()) {
            for (PolicyRevision r : versions.values()) {
                if (r.getStatus() == PolicyStatus.PUBLISHED) {
                    out.add(copy(r));
                }
            }
        }
        out.sort((a, b) -> a.getScene().compareTo(b.getScene()));
        return out;
    }

    @Override
    public List<PolicyRevision> listAll() {
        List<PolicyRevision> out = new ArrayList<>();
        for (Map<Integer, PolicyRevision> versions : byPolicy.values()) {
            for (PolicyRevision r : versions.values()) {
                out.add(copy(r));
            }
        }
        out.sort((a, b) -> {
            int c = a.getPolicyId().compareTo(b.getPolicyId());
            return c != 0 ? c : Integer.compare(b.getRevision(), a.getRevision());
        });
        return out;
    }

    @Override
    public int maxRevision(String policyId) {
        if (policyId == null || policyId.isEmpty()) {
            return 0;
        }
        Map<Integer, PolicyRevision> versions = byPolicy.get(policyId);
        if (versions == null || versions.isEmpty()) {
            return 0;
        }
        int max = 0;
        for (Integer rev : versions.keySet()) {
            if (rev > max) {
                max = rev;
            }
        }
        return max;
    }

    @Override
    public int supersedePublished(String scene) {
        if (scene == null || scene.isEmpty()) {
            return 0;
        }
        int n = 0;
        for (Map<Integer, PolicyRevision> versions : byPolicy.values()) {
            for (PolicyRevision r : versions.values()) {
                if (r.getStatus() == PolicyStatus.PUBLISHED && scene.equals(r.getScene())) {
                    r.setStatus(PolicyStatus.SUPERSEDED);
                    n++;
                }
            }
        }
        return n;
    }

    @Override
    public int updateStatus(String policyId, int revision, String status) {
        if (policyId == null || policyId.isEmpty() || status == null) {
            return 0;
        }
        PolicyStatus target = PolicyStatus.fromCode(status);
        if (target == null) {
            return 0;
        }
        Map<Integer, PolicyRevision> versions = byPolicy.get(policyId);
        if (versions == null) {
            return 0;
        }
        PolicyRevision r = versions.get(revision);
        if (r == null) {
            return 0;
        }
        r.setStatus(target);
        return 1;
    }

    @Override
    public int delete(String policyId, int revision) {
        if (policyId == null || policyId.isEmpty()) {
            return 0;
        }
        Map<Integer, PolicyRevision> versions = byPolicy.get(policyId);
        if (versions == null) {
            return 0;
        }
        PolicyRevision r = versions.get(revision);
        if (r == null || r.getStatus() == PolicyStatus.PUBLISHED) {
            return 0;
        }
        versions.remove(revision);
        return 1;
    }

    /** 复制（隔离内部对象）。 */
    private static PolicyRevision copy(PolicyRevision src) {
        PolicyRevision r = new PolicyRevision(src.getPolicyId(), src.getScene(),
                src.getRevision());
        r.setStatus(src.getStatus());
        r.setStages(src.getStages());
        r.setWatermarkType(src.getWatermarkType());
        r.setBlockThreshold(src.getBlockThreshold());
        r.setMaskPolicySetId(src.getMaskPolicySetId());
        r.setEnabled(src.isEnabled());
        r.setRemark(src.getRemark());
        r.setChangeReason(src.getChangeReason());
        r.setOperatorId(src.getOperatorId());
        r.setCreatedAt(src.getCreatedAt());
        return r;
    }
}
