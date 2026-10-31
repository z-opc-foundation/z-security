package com.zifang.z.security.core.service;

import com.zifang.z.security.core.domain.PolicyRevision;
import com.zifang.z.security.core.domain.PolicyStatus;
import com.zifang.z.security.core.domain.SecurityPolicy;
import com.zifang.z.security.core.spi.PolicyStore;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 策略台账服务（**策略即数据 + 可热改 + 可回滚**）。
 *
 * <p><b>解决 M1 的什么问题</b>：M1 的策略写死在代码里 ⇒
 * <ol>
 *   <li>改阈值要发版 ⇒ 合规口径调整周期以天计；</li>
 *   <li>没有历史 ⇒ 「上次是谁把 L4 改成 L3 的」答不上来 ⇒ 内审必挂；</li>
 *   <li>没有回滚 ⇒ 改错了只能再发一版（越改越乱）。</li>
 * </ol>
 *
 * <p><b>★ 核心口径</b>：
 * <ul>
 *   <li><b>版本不可变</b>：已发布的版本不再改，要改就发新版本（版本号 +1）；</li>
 *   <li><b>一场景一版生效</b>：发布新版前先把旧的 PUBLISHED 降为 SUPERSEDED
 *       ⇒ 「当前生效的是哪一版」永远唯一；</li>
 *   <li><b>回滚 = 重新发布老版本</b>：老版本内容原样再发一版新版本号
 *       ⇒ 回滚本身也留痕（不删除历史）；</li>
 *   <li><b>★ 生效加载失败 ⇒ 走内置策略</b>，不静默用「半条策略」。</li>
 * </ul>
 *
 * <p><b>线程安全</b>：本类无可变状态（依赖是不可变存储）⇒ 可并发调用。
 *
 * @author zifang
 */
public class PolicyLedgerService {

    /** 台账存储。 */
    private final PolicyStore store;

    /**
     * 构造。
     *
     * @param store 台账存储（**不可为 null**）
     */
    public PolicyLedgerService(PolicyStore store) {
        if (store == null) {
            throw new IllegalArgumentException("策略台账存储不可为 null");
        }
        this.store = store;
    }

    /**
     * 发布一版策略（**新版本号 + 取代旧版**）。
     *
     * <p><b>流程</b>：算新版本号 ⇒ 旧 PUBLISHED 降级 ⇒ 写入新版本（PUBLISHED）。
     *
     * <p><b>★ 为什么不用 UPDATE 覆盖</b>：覆盖就丢历史 ⇒ 内审答不出「谁改的」。
     *
     * @param policy    运行时策略（可空 ⇒ 失败）
     * @param operator  操作人（**必填** —— 合规要求知道谁改的）
     * @param reason    变更原因（**必填** —— 合规要求知道为什么改）
     * @return 发布结果
     */
    public PublishResult publish(SecurityPolicy policy, String operator, String reason) {
        if (policy == null || policy.getScene() == null || policy.getScene().isEmpty()) {
            return PublishResult.failed("策略或场景码为空");
        }
        if (operator == null || operator.trim().isEmpty()) {
            return PublishResult.failed("操作人不可为空（合规要求知道谁改的）");
        }
        if (reason == null || reason.trim().isEmpty()) {
            return PublishResult.failed("变更原因不可为空（合规要求知道为什么改）");
        }
        // ★ 阶段解析失败 ⇒ 拒绝发布（不发布「半条策略」）
        List<com.zifang.z.security.core.domain.SecurityStage> stages =
                policy.getStages();
        if (PolicyRevision.parseStages(PolicyRevision.joinStages(stages)) == null) {
            return PublishResult.failed("阶段序列非法");
        }
        int next = store.maxRevision(policy.getPolicyId()) + 1;
        PolicyRevision rev = PolicyRevision.from(policy, next, PolicyStatus.PUBLISHED,
                operator.trim(), reason.trim());
        // 先把旧的降级，再写新的 ⇒ 不会出现「一场景两版同时生效」
        store.supersedePublished(policy.getScene());
        if (!store.save(rev)) {
            return PublishResult.failed("写入策略版本失败");
        }
        return PublishResult.ok(rev);
    }

    /**
     * 回滚到某个历史版本（**以新版本号重新发布老内容**）。
     *
     * <p><b>★ 为什么不是「把老版本状态改回 PUBLISHED」</b>：
     * 那样会让版本号倒流（当前 rev=5，回滚后生效的是 rev=3）⇒
     * 「现在是第几版」和「历史顺序」对不上 ⇒ 台账自相矛盾。
     * 重新发布（rev=6，内容 = rev=3 的内容）⇒ 历史是一条**只增不减**的时间线。
     *
     * @param policyId 策略 ID
     * @param revision 要回滚到的版本号
     * @param operator 操作人
     * @param reason   回滚原因
     * @return 发布结果
     */
    public PublishResult rollback(String policyId, int revision, String operator, String reason) {
        PolicyRevision target = store.findRevision(policyId, revision);
        if (target == null) {
            return PublishResult.failed("目标版本不存在（policyId=" + policyId
                    + " rev=" + revision + "）");
        }
        SecurityPolicy policy = target.toPolicy();
        if (policy == null) {
            return PublishResult.failed("目标版本的阶段序列无法解析，回滚中止");
        }
        int next = store.maxRevision(policyId) + 1;
        PolicyRevision rev = PolicyRevision.from(policy, next, PolicyStatus.PUBLISHED,
                operator == null ? "unknown" : operator,
                "回滚到 rev" + revision + "：" + (reason == null ? "" : reason));
        rev.setPolicyId(policyId);
        store.supersedePublished(policy.getScene());
        if (!store.save(rev)) {
            return PublishResult.failed("写入回滚版本失败");
        }
        return PublishResult.ok(rev);
    }

    /**
     * 停用某场景（**该场景不再有生效策略 ⇒ 走兜底**）。
     *
     * @param policyId 策略 ID
     * @param operator 操作人
     * @param reason   停用原因
     * @return 是否成功
     */
    public boolean disable(String policyId, String operator, String reason) {
        PolicyRevision target = store.findPublished(policyId) != null
                ? store.findPublished(policyId)
                : latestOf(policyId);
        if (target == null) {
            return false;
        }
        if (operator == null || operator.trim().isEmpty()) {
            return false;
        }
        store.supersedePublished(target.getScene());
        store.updateStatus(policyId, target.getRevision(), PolicyStatus.DISABLED.name());
        return true;
    }

    /**
     * 加载某场景的**生效策略**。
     *
     * <p><b>★ 加载失败 ⇒ 返回 {@code null}**（调用方走内置/兜底策略）。
     * 绝不用「半条策略」—— 阶段解析失败就整条不可用。
     *
     * @param scene 场景码
     * @return 生效策略；无 / 加载失败返回 {@code null}
     */
    public SecurityPolicy resolve(String scene) {
        if (scene == null || scene.isEmpty()) {
            return null;
        }
        PolicyRevision rev = store.findPublished(scene);
        if (rev == null) {
            return null;
        }
        SecurityPolicy policy = rev.toPolicy();
        if (policy == null) {
            // ★ 阶段解析失败 ⇒ 整条策略不可用（不静默丢阶段）
            System.err.println("[z-security] 策略阶段序列无法解析，场景 "
                    + scene + " 走兜底策略（rev=" + rev.getRevision() + "）");
            return null;
        }
        return policy;
    }

    /**
     * 把台账的生效策略装配进注册表（**热改的核心**：重建一份带新策略的注册表）。
     *
     * @param base 基础注册表（**保留其中的兜底策略**）
     * @return 装配后的注册表
     */
    public SecurityPolicyRegistry applyTo(SecurityPolicyRegistry base) {
        SecurityPolicyRegistry registry = base == null
                ? new SecurityPolicyRegistry(SecurityPolicyRegistry.builtinDefault())
                : base;
        for (PolicyRevision rev : store.listPublished()) {
            SecurityPolicy policy = rev.toPolicy();
            if (policy != null) {
                registry.register(policy);
            }
        }
        return registry;
    }

    /**
     * ★ 启动装载（**让台账成为策略的唯一权威源**）。
     *
     * <p><b>流程</b>：
     * <ol>
     *   <li>台账**为空** ⇒ 把内置场景策略**播种**进去（rev1 / PUBLISHED / operator=system）；</li>
     *   <li>读台账的生效策略 ⇒ <b>原子替换</b>进注册表。</li>
     * </ol>
     *
     * <p><b>为什么要有播种</b>：不播种的话，首次启动注册表里是内置策略、台账是空的
     * ⇒ 运维在台账里改了策略、重启后注册表又回到内置 ⇒ **改了就白改**。
     * 播种一次之后，台账就是唯一权威源，重启读台账 ⇒ 热改持久化。
     *
     * <p><b>为什么播种只在台账为空时做</b>：非空时再播种会把运维改过的策略覆盖回内置
     * ⇒ 每次重启都把合规口径打回原形。
     *
     * @param registry 目标注册表（**不可为 null**）
     * @return 装载后的生效场景数
     */
    public int bootstrap(SecurityPolicyRegistry registry) {
        if (registry == null) {
            return 0;
        }
        List<PolicyRevision> published = store.listPublished();
        if (published.isEmpty()) {
            for (SecurityPolicy p : com.zifang.z.security.core.support.BuiltinSecurityPolicies.all()) {
                PolicyRevision rev = PolicyRevision.from(p, 1, PolicyStatus.PUBLISHED,
                        "system", "内置策略播种（台账首次初始化）");
                store.save(rev);
            }
            published = store.listPublished();
        }
        List<SecurityPolicy> effective = new ArrayList<>();
        for (PolicyRevision rev : published) {
            SecurityPolicy policy = rev.toPolicy();
            if (policy != null) {
                effective.add(policy);
            }
        }
        // ★★ 装载不出任何生效策略时**不碰注册表**。
        //   原因：台账读不出来（表没建 / 库连不上 / 播种写失败）⇒ effective 为空
        //   ⇒ 若照样 replaceAll ⇒ **内置策略被清空** ⇒ 全部场景降级到 DEFAULT 兜底
        //   ⇒ 拦截阈值掉到 L4 ⇒ 本该拦的敏感数据**直接出域**。
        //   这比「用内置策略继续跑」严重得多。宁可不装载，也不装载成空。
        if (effective.isEmpty()) {
            System.err.println("[z-security] 策略台账装载不出任何生效策略，"
                    + "沿用现有内置策略（不替换注册表）");
            return 0;
        }
        registry.replaceAll(effective);
        return effective.size();
    }

    /**
     * 台账全量视图（**场景 → 生效策略**，供对外查询）。
     *
     * @return 场景 → 策略 的视图
     */
    public Map<String, SecurityPolicy> publishedView() {
        Map<String, SecurityPolicy> view = new LinkedHashMap<>();
        for (PolicyRevision rev : store.listPublished()) {
            SecurityPolicy policy = rev.toPolicy();
            if (policy != null) {
                view.put(rev.getScene(), policy);
            }
        }
        return view;
    }

    /** 某策略的全部版本（**版本号倒序**）。 */
    public List<PolicyRevision> history(String policyId) {
        return store.listByPolicy(policyId);
    }

    /** 台账全量版本。 */
    public List<PolicyRevision> allRevisions() {
        return store.listAll();
    }

    /** 某策略的最大版本号。 */
    public int maxRevision(String policyId) {
        return store.maxRevision(policyId);
    }

    /** 台账存储（只读用途）。 */
    public PolicyStore getStore() {
        return store;
    }

    /** 某策略的最新版本（不论状态）。 */
    private PolicyRevision latestOf(String policyId) {
        List<PolicyRevision> list = store.listByPolicy(policyId);
        return list.isEmpty() ? null : list.get(0);
    }

    /**
     * 发布结果。
     */
    public static class PublishResult {

        /** 是否成功。 */
        private final boolean ok;
        /** 发布后的版本（失败时为 null）。 */
        private final PolicyRevision revision;
        /** 失败原因。 */
        private final String message;

        private PublishResult(boolean ok, PolicyRevision revision, String message) {
            this.ok = ok;
            this.revision = revision;
            this.message = message;
        }

        /** 成功。 */
        static PublishResult ok(PolicyRevision revision) {
            return new PublishResult(true, revision, "发布成功");
        }

        /** 失败。 */
        static PublishResult failed(String message) {
            return new PublishResult(false, null, message);
        }

        public boolean isOk() {
            return ok;
        }

        public PolicyRevision getRevision() {
            return revision;
        }

        public String getMessage() {
            return message;
        }
    }

    /** 台账视图辅助（供 web 层用）。 */
    public static List<Map<String, Object>> toViews(List<PolicyRevision> revisions) {
        List<Map<String, Object>> views = new ArrayList<>();
        if (revisions == null) {
            return views;
        }
        for (PolicyRevision r : revisions) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("policyId", r.getPolicyId());
            m.put("scene", r.getScene());
            m.put("revision", r.getRevision());
            m.put("status", r.getStatus() == null ? null : r.getStatus().name());
            m.put("stages", r.getStages());
            m.put("watermarkType", r.getWatermarkType());
            m.put("blockThreshold", r.getBlockThreshold());
            m.put("enabled", r.isEnabled());
            m.put("remark", r.getRemark());
            m.put("changeReason", r.getChangeReason());
            m.put("operatorId", r.getOperatorId());
            m.put("createdAt", r.getCreatedAt());
            views.add(m);
        }
        return views;
    }
}
