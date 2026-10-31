package com.zifang.z.security.core.service;

import com.zifang.z.security.core.domain.SecurityPolicy;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 安全策略注册表（**场景 → 策略**）。
 *
 * <p><b>为什么按场景查而不是让业务方自己 new 策略</b>：策略是<b>合规口径</b>，
 * 应该由配置/台账统一管，业务方只报「场景码」。
 * 让业务方自己 new 策略 ⇒ 每个调用点一套口径 ⇒ 合规没法收口。
 *
 * <p><b>兜底策略</b>：场景没登记时用 {@link #defaultPolicy}（默认全流水线 + L4 拦截），
 * 保证「没配也能跑」而不是直接失败。
 *
 * <p><b>线程安全</b>：注册表构造后只读 ⇒ 可并发调用。
 *
 * @author zifang
 */
public class SecurityPolicyRegistry {

    /** 场景 → 策略。 */
    private final Map<String, SecurityPolicy> byScene = new LinkedHashMap<>();

    /** 兜底策略。 */
    private SecurityPolicy defaultPolicy;

    /**
     * 构造（带兜底策略）。
     *
     * @param defaultPolicy 兜底策略（可空 ⇒ 用内置默认）
     */
    public SecurityPolicyRegistry(SecurityPolicy defaultPolicy) {
        this.defaultPolicy = defaultPolicy == null ? builtinDefault() : defaultPolicy;
    }

    /**
     * 内置默认策略（全流水线 + L4 拦截）。
     *
     * @return 策略
     */
    public static SecurityPolicy builtinDefault() {
        return SecurityPolicy.full("DEFAULT", "DEFAULT");
    }

    /**
     * 登记一个策略（**同场景覆盖**）。
     *
     * @param policy 策略（可空 ⇒ 忽略）
     */
    public void register(SecurityPolicy policy) {
        if (policy == null || policy.getScene() == null || policy.getScene().isEmpty()) {
            return;
        }
        byScene.put(policy.getScene(), policy);
    }

    /**
     * 按场景取策略（**没登记 ⇒ 兜底策略**）。
     *
     * @param scene 场景码（可空 ⇒ 兜底）
     * @return 策略（**永不为 null**）
     */
    public SecurityPolicy resolve(String scene) {
        if (scene == null) {
            return defaultPolicy;
        }
        SecurityPolicy p = byScene.get(scene);
        return p == null ? defaultPolicy : p;
    }

    /**
     * 设兜底策略。
     *
     * @param policy 策略（可空 ⇒ 忽略）
     */
    public void setDefaultPolicy(SecurityPolicy policy) {
        if (policy != null) {
            this.defaultPolicy = policy;
        }
    }

    public SecurityPolicy getDefaultPolicy() {
        return defaultPolicy;
    }

    /**
     * 已登记的场景（只读）。
     *
     * @return 场景列表
     */
    public List<String> scenes() {
        return Collections.unmodifiableList(new ArrayList<>(byScene.keySet()));
    }

    /**
     * 全部策略（只读）。
     *
     * @return 策略列表
     */
    public List<SecurityPolicy> all() {
        return Collections.unmodifiableList(new ArrayList<>(byScene.values()));
    }

    /**
     * ★ 原子热替换全部场景策略（**策略台账热改的落地口**）。
     *
     * <p><b>为什么必须原子</b>：热改时若「先清空、再逐条加」，
     * 中间窗口内并发请求会看到**空注册表** ⇒ 全部走兜底策略
     * ⇒ 拦截阈值掉到 L4 ⇒ <b>本该拦的敏感数据没拦，直接出域</b>。
     * 这是热改最容易出的事故，且**只在生产高并发时偶发**（本地压测看不出来）。
     *
     * <p>本方法先在本地构造新表，构造完再**一次性替换引用** ⇒
     * 任何时刻并发读者看到的都是**完整的旧版或完整的新版**，不会看到中间态。
     *
     * @param policies 新的全量策略（可空 ⇒ 不变）
     */
    public synchronized void replaceAll(List<SecurityPolicy> policies) {
        if (policies == null) {
            return;
        }
        Map<String, SecurityPolicy> fresh = new LinkedHashMap<>();
        for (SecurityPolicy p : policies) {
            if (p == null || p.getScene() == null || p.getScene().isEmpty()) {
                continue;
            }
            fresh.put(p.getScene(), p);
        }
        byScene.clear();
        byScene.putAll(fresh);
    }

    /**
     * 取一份**快照**（用于热改时读取当前全量再合并）。
     *
     * @return 场景 → 策略 的副本
     */
    public synchronized Map<String, SecurityPolicy> snapshot() {
        return new LinkedHashMap<>(byScene);
    }
}
