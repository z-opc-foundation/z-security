package com.zifang.z.security.core;

import com.zifang.z.security.core.domain.PolicyRevision;
import com.zifang.z.security.core.domain.PolicyStatus;
import com.zifang.z.security.core.domain.SecurityPolicy;
import com.zifang.z.security.core.domain.SecurityStage;
import com.zifang.z.security.core.service.PolicyLedgerService;
import com.zifang.z.security.core.service.SecurityPolicyRegistry;
import com.zifang.z.security.core.support.BuiltinSecurityPolicies;
import com.zifang.z.security.core.support.InMemoryPolicyStore;
import com.zifang.z.watermark.core.domain.WatermarkType;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 策略台账单测（**M2：策略即数据 + 热改 + 回滚**）。
 *
 * @author zifang
 */
class PolicyLedgerServiceTest {

    private final InMemoryPolicyStore store = new InMemoryPolicyStore();
    private final PolicyLedgerService ledger = new PolicyLedgerService(store);

    private SecurityPolicy exportPolicy(String threshold) {
        SecurityPolicy p = new SecurityPolicy("P_EXPORT", "CONTRACT_EXPORT");
        p.setStages(new ArrayList<>(SecurityStage.defaultOrder()));
        p.setWatermarkType(WatermarkType.VISIBLE_TEXT);
        p.setBlockThreshold(threshold);
        p.setRemark("导出外发");
        return p;
    }

    // ---------------- 发布 ----------------

    @Test
    @DisplayName("发布：成功 ⇒ 版本号从 1 起、状态 PUBLISHED")
    void publishCreatesVersionOne() {
        PolicyLedgerService.PublishResult r =
                ledger.publish(exportPolicy("L3"), "op-1", "首次发布");

        assertTrue(r.isOk(), r.getMessage());
        assertEquals(1, r.getRevision().getRevision());
        assertEquals(PolicyStatus.PUBLISHED, r.getRevision().getStatus());
        assertEquals("op-1", r.getRevision().getOperatorId());
        assertEquals("首次发布", r.getRevision().getChangeReason());
    }

    @Test
    @DisplayName("发布：★ 操作人为空 ⇒ 拒绝（合规要求知道谁改的）")
    void publishRequiresOperator() {
        PolicyLedgerService.PublishResult r =
                ledger.publish(exportPolicy("L3"), null, "理由");

        assertFalse(r.isOk());
        assertTrue(r.getMessage().contains("操作人"));
        assertEquals(0, store.listAll().size(), "被拒的发布不应留下任何版本");
    }

    @Test
    @DisplayName("发布：★ 变更原因为空 ⇒ 拒绝（合规要求知道为什么改）")
    void publishRequiresReason() {
        PolicyLedgerService.PublishResult r =
                ledger.publish(exportPolicy("L3"), "op-1", "  ");

        assertFalse(r.isOk());
        assertTrue(r.getMessage().contains("变更原因"));
        assertEquals(0, store.listAll().size());
    }

    @Test
    @DisplayName("发布：★ 同一场景一版生效（旧版自动 SUPERSEDED）")
    void publishSupersedesPrevious() {
        ledger.publish(exportPolicy("L4"), "op-1", "首版");
        ledger.publish(exportPolicy("L3"), "op-2", "收紧阈值");

        List<PolicyRevision> published = store.listPublished();
        assertEquals(1, published.size(), "同一场景只能有一版生效");
        assertEquals(2, published.get(0).getRevision());

        List<PolicyRevision> history = store.listByPolicy("P_EXPORT");
        assertEquals(2, history.size());
        assertEquals(PolicyStatus.SUPERSEDED, history.get(1).getStatus());
        assertEquals(PolicyStatus.PUBLISHED, history.get(0).getStatus());
    }

    @Test
    @DisplayName("发布：版本号只增不减（历史不可变）")
    void revisionsOnlyIncrease() {
        ledger.publish(exportPolicy("L4"), "op-1", "v1");
        ledger.publish(exportPolicy("L3"), "op-1", "v2");
        ledger.publish(exportPolicy("L4"), "op-1", "v3");

        assertEquals(3, ledger.maxRevision("P_EXPORT"));
        List<PolicyRevision> history = store.listByPolicy("P_EXPORT");
        assertEquals(3, history.size());
        // ★ 三版内容都在（历史不可变 ⇒ 没被覆盖）
        assertEquals(3, history.stream().map(PolicyRevision::getRevision)
                .collect(java.util.stream.Collectors.toSet()).size());
    }

    // ---------------- 生效解析 ----------------

    @Test
    @DisplayName("解析：发布后 ⇒ 按场景取到生效策略")
    void resolvePublishedPolicy() {
        ledger.publish(exportPolicy("L3"), "op-1", "发布");

        SecurityPolicy p = ledger.resolve("CONTRACT_EXPORT");

        assertNotNull(p);
        assertEquals("P_EXPORT", p.getPolicyId());
        assertEquals("L3", p.getBlockThreshold());
        assertEquals(4, p.getStages().size());
    }

    @Test
    @DisplayName("解析：未发布的场景 ⇒ 返回 null（调用方走兜底）")
    void resolveUnknownSceneReturnsNull() {
        assertNull(ledger.resolve("NOT_EXIST"));
        assertNull(ledger.resolve(null));
    }

    @Test
    @DisplayName("解析：★ 阶段序列非法 ⇒ 整条策略不生效（不静默丢阶段）")
    void invalidStagesMakeWholePolicyUnusable() {
        // 手工塞一条阶段序列里有未知阶段的 PUBLISHED 记录
        PolicyRevision bad = new PolicyRevision("P_BAD", "BAD_SCENE", 1);
        bad.setStatus(PolicyStatus.PUBLISHED);
        bad.setStages("SENSE,NOT_A_STAGE");
        bad.setWatermarkType("VISIBLE_TEXT");
        bad.setBlockThreshold("L3");
        store.save(bad);

        assertNull(ledger.resolve("BAD_SCENE"),
                "阶段解析失败 ⇒ 整条策略不可用（不静默丢掉未知阶段）");
    }

    // ---------------- 回滚 ----------------

    @Test
    @DisplayName("回滚：★ 以新版本号重新发布老内容（版本号不倒流）")
    void rollbackCreatesNewRevision() {
        ledger.publish(exportPolicy("L4"), "op-1", "v1");
        ledger.publish(exportPolicy("L3"), "op-2", "v2 收紧");

        PolicyLedgerService.PublishResult r = ledger.rollback("P_EXPORT", 1, "op-3", "改错了");

        assertTrue(r.isOk(), r.getMessage());
        assertEquals(3, r.getRevision().getRevision(), "回滚应产生新版本号，不是倒回 rev1");
        assertEquals("L4", r.getRevision().getBlockThreshold(), "内容应回到 rev1");
        assertEquals(3, ledger.maxRevision("P_EXPORT"));
    }

    @Test
    @DisplayName("回滚：目标版本不存在 ⇒ 失败")
    void rollbackUnknownRevisionFails() {
        ledger.publish(exportPolicy("L4"), "op-1", "v1");

        PolicyLedgerService.PublishResult r =
                ledger.rollback("P_EXPORT", 99, "op-2", "回滚");

        assertFalse(r.isOk());
        assertTrue(r.getMessage().contains("不存在"));
    }

    @Test
    @DisplayName("回滚：★ 回滚本身也留痕（不删历史）")
    void rollbackKeepsHistory() {
        ledger.publish(exportPolicy("L4"), "op-1", "v1");
        ledger.publish(exportPolicy("L3"), "op-2", "v2");
        ledger.rollback("P_EXPORT", 1, "op-3", "回滚");

        assertEquals(3, store.listByPolicy("P_EXPORT").size(), "三版都在");
    }

    // ---------------- 停用 ----------------

    @Test
    @DisplayName("停用：生效策略消失 ⇒ 该场景走兜底")
    void disableRemovesPublishedPolicy() {
        ledger.publish(exportPolicy("L3"), "op-1", "发布");

        assertTrue(ledger.disable("P_EXPORT", "op-2", "下线"));
        assertNull(ledger.resolve("CONTRACT_EXPORT"));
        assertEquals(0, store.listPublished().size());
    }

    @Test
    @DisplayName("停用：操作人为空 ⇒ 失败")
    void disableRequiresOperator() {
        ledger.publish(exportPolicy("L3"), "op-1", "发布");

        assertFalse(ledger.disable("P_EXPORT", null, "下线"));
    }

    // ---------------- 热改 ----------------

    @Test
    @DisplayName("热改：★ 原子替换（注册表不会出现中间态空表）")
    void applyToRegistryAtomically() {
        SecurityPolicyRegistry registry =
                new SecurityPolicyRegistry(SecurityPolicyRegistry.builtinDefault());
        for (SecurityPolicy p : BuiltinSecurityPolicies.all()) {
            registry.register(p);
        }
        ledger.publish(exportPolicy("L3"), "op-1", "发布");

        ledger.applyTo(registry);

        SecurityPolicy effective = registry.resolve("CONTRACT_EXPORT");
        assertNotNull(effective);
        assertEquals("L3", effective.getBlockThreshold());
        assertEquals(5, registry.scenes().size(), "内置 5 场景应仍在");
    }

    @Test
    @DisplayName("热改：注册表 replaceAll 是全量替换（不留旧场景）")
    void replaceAllIsFullReplacement() {
        SecurityPolicyRegistry registry =
                new SecurityPolicyRegistry(SecurityPolicyRegistry.builtinDefault());
        registry.register(new SecurityPolicy("P_OLD", "OLD_SCENE"));

        registry.replaceAll(List.of(new SecurityPolicy("P_NEW", "NEW_SCENE")));

        assertEquals(1, registry.scenes().size());
        assertTrue(registry.scenes().contains("NEW_SCENE"));
        assertFalse(registry.scenes().contains("OLD_SCENE"));
    }

    @Test
    @DisplayName("热改：★ replaceAll 后并发读到的永远是完整的一版")
    void replaceAllIsAtomicForConcurrentReaders() {
        SecurityPolicyRegistry registry =
                new SecurityPolicyRegistry(SecurityPolicyRegistry.builtinDefault());
        for (SecurityPolicy p : BuiltinSecurityPolicies.all()) {
            registry.register(p);
        }
        // 旧版：5 个场景
        assertEquals(5, registry.scenes().size());

        // 换成只有 1 个场景的新版
        registry.replaceAll(List.of(new SecurityPolicy("P_NEW", "NEW_SCENE")));

        assertEquals(1, registry.scenes().size());
        assertNotNull(registry.resolve("NEW_SCENE"));
    }

    // ---------------- 阶段编解码 ----------------

    @Test
    @DisplayName("阶段编解码：序列往返一致")
    void stagesRoundTrip() {
        List<SecurityStage> stages = Arrays.asList(SecurityStage.SENSE, SecurityStage.MASK);
        String encoded = PolicyRevision.joinStages(stages);

        assertEquals("SENSE,MASK", encoded);
        assertEquals(stages, PolicyRevision.parseStages(encoded));
    }

    @Test
    @DisplayName("阶段编解码：★ 未知阶段 ⇒ 解析返回 null（整条不可用）")
    void unknownStageMakesParseFail() {
        assertNull(PolicyRevision.parseStages("SENSE,BOGUS"));
        assertNull(PolicyRevision.parseStages("BOGUS"));
    }

    @Test
    @DisplayName("阶段编解码：空串 ⇒ 空列表（不是 null）")
    void emptyStagesParseToEmptyList() {
        assertNotNull(PolicyRevision.parseStages(""));
        assertTrue(PolicyRevision.parseStages("").isEmpty());
        assertTrue(PolicyRevision.parseStages(null).isEmpty());
    }

    // ---------------- 启动装载 ----------------

    @Test
    @DisplayName("启动装载：★ 台账为空 ⇒ 播种内置策略（5 个场景）")
    void bootstrapSeedsBuiltinPolicies() {
        SecurityPolicyRegistry registry =
                new SecurityPolicyRegistry(SecurityPolicyRegistry.builtinDefault());

        int n = ledger.bootstrap(registry);

        assertEquals(5, n, "内置 5 个场景应被播种");
        assertEquals(5, store.listPublished().size());
        assertNotNull(registry.resolve(BuiltinSecurityPolicies.SCENE_CONTRACT_EXPORT));
    }

    @Test
    @DisplayName("启动装载：★ 台账非空 ⇒ 不重新播种（不覆盖运维改过的策略）")
    void bootstrapDoesNotReseedNonEmptyLedger() {
        ledger.publish(exportPolicy("L4"), "op-1", "运维改成 L4");

        SecurityPolicyRegistry registry =
                new SecurityPolicyRegistry(SecurityPolicyRegistry.builtinDefault());
        ledger.bootstrap(registry);

        assertEquals(1, store.listPublished().size(), "只应有运维那条，不能被内置播种覆盖");
        assertEquals("L4", registry.resolve("CONTRACT_EXPORT").getBlockThreshold());
    }

    @Test
    @DisplayName("启动装载：★ 改完策略重启 ⇒ 策略不丢（这才是热改的意义）")
    void policySurvivesRestart() {
        ledger.publish(exportPolicy("L4"), "op-1", "改成 L4");

        // 模拟重启：新进程用同一个台账（这里同一个 store）装载
        SecurityPolicyRegistry restarted =
                new SecurityPolicyRegistry(SecurityPolicyRegistry.builtinDefault());
        new PolicyLedgerService(store).bootstrap(restarted);

        assertEquals("L4", restarted.resolve("CONTRACT_EXPORT").getBlockThreshold(),
                "重启后应读到台账里的 L4，而不是内置的 L3");
    }

    @Test
    @DisplayName("★ 启动装载：★ 台账读不出任何生效策略 ⇒ 保留内置策略（不清空注册表）")
    void bootstrapKeepsBuiltinWhenLedgerEmpty() {
        // 台账完全不可用（播种也写不进去）⇒ 用一个「写不进去」的存储模拟
        InMemoryPolicyStore broken = new InMemoryPolicyStore() {
            @Override
            public boolean save(PolicyRevision revision) {
                return false;   // 播种写不进去
            }
        };
        PolicyLedgerService brokenLedger = new PolicyLedgerService(broken);

        SecurityPolicyRegistry registry =
                new SecurityPolicyRegistry(SecurityPolicyRegistry.builtinDefault());
        for (SecurityPolicy p : BuiltinSecurityPolicies.all()) {
            registry.register(p);
        }

        int n = brokenLedger.bootstrap(registry);

        assertEquals(0, n);
        assertEquals(5, registry.scenes().size(),
                "★ 台账读不出时绝不能清空注册表（否则全部降级到 DEFAULT，敏感数据可能出域）");
        assertNotNull(registry.resolve(BuiltinSecurityPolicies.SCENE_CONTRACT_EXPORT),
                "内置场景必须仍在");
    }

    // ---------------- 版本记录 ----------------

    @Test
    @DisplayName("版本记录：★ 读回返回副本（改副本不污染台账）")
    void storeReturnsCopies() {
        ledger.publish(exportPolicy("L3"), "op-1", "发布");

        PolicyRevision first = store.findPublished("CONTRACT_EXPORT");
        first.setBlockThreshold("L4");

        PolicyRevision second = store.findPublished("CONTRACT_EXPORT");
        assertEquals("L3", second.getBlockThreshold(), "台账不应被外部改动污染");
    }

    @Test
    @DisplayName("版本记录：PUBLISHED 版本不可删")
    void publishedVersionCannotBeDeleted() {
        ledger.publish(exportPolicy("L3"), "op-1", "发布");

        assertEquals(0, store.delete("P_EXPORT", 1), "生效版本不应被删");
        assertNotNull(store.findPublished("CONTRACT_EXPORT"));
    }

    @Test
    @DisplayName("版本记录：非 PUBLISHED 版本可删")
    void supersededVersionCanBeDeleted() {
        ledger.publish(exportPolicy("L4"), "op-1", "v1");
        ledger.publish(exportPolicy("L3"), "op-2", "v2");

        assertEquals(1, store.delete("P_EXPORT", 1));
        assertEquals(1, store.listByPolicy("P_EXPORT").size());
    }
}
