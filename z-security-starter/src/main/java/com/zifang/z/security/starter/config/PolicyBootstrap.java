package com.zifang.z.security.starter.config;

import com.zifang.z.security.core.service.PolicyLedgerService;
import com.zifang.z.security.core.service.SecurityPolicyRegistry;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;

/**
 * 策略启动装载器。
 *
 * <p><b>为什么用 {@code ApplicationReadyEvent} 而不是 {@code InitializingBean}</b>：
 * {@code InitializingBean} 在**所有 bean 创建完之前**跑 ⇒ 此时 Mapper / DataSource
 * 可能还没就绪 ⇒ 读台账必然失败。
 * {@code ApplicationReadyEvent} 是上下文完全就绪后才发 ⇒ 此时读台账才可靠。
 *
 * <p><b>★ 装载失败不阻断启动</b>：台账读不出来（表没建 / 库连不上）
 * ⇒ 保留内置策略继续跑 ⇒ **安全防护不能因为台账故障就整个瘫掉**
 * （台账故障 ⇒ 降级到内置策略 ⇒ 仍有一层防护；直接启动失败 ⇒ 完全没防护）。
 *
 * @author zifang
 */
public class PolicyBootstrap {

    /** 策略注册表。 */
    private final SecurityPolicyRegistry registry;

    /** 策略台账服务。 */
    private final PolicyLedgerService ledger;

    /**
     * 构造。
     *
     * @param registry 策略注册表
     * @param ledger   台账服务
     */
    public PolicyBootstrap(SecurityPolicyRegistry registry, PolicyLedgerService ledger) {
        this.registry = registry;
        this.ledger = ledger;
    }

    /**
     * 上下文就绪后装载策略。
     */
    @EventListener(ApplicationReadyEvent.class)
    public void loadOnStartup() {
        try {
            int n = ledger.bootstrap(registry);
            System.out.println("[z-security] 策略台账装载完成，生效场景 " + n + " 个");
        } catch (RuntimeException e) {
            // ★ 不阻断启动：保留内置策略继续跑
            System.err.println("[z-security] 策略台账装载失败，沿用内置策略："
                    + e.getMessage());
        }
    }
}
