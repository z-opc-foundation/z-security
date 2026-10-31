package com.zifang.z.security.starter.config;

import com.zifang.z.audit.core.mapper.AuditEventMapper;
import com.zifang.z.audit.core.service.AuditService;
import com.zifang.z.audit.core.service.AuditTraceService;
import com.zifang.z.audit.core.service.PersistentAuditStore;
import com.zifang.z.security.core.mapper.SecurityPolicyMapper;
import com.zifang.z.security.core.service.LocalAuditTraceAdapter;
import com.zifang.z.security.core.service.PersistentPolicyStore;
import com.zifang.z.security.core.service.PolicyLedgerService;
import com.zifang.z.security.core.service.SecurityPipeline;
import com.zifang.z.security.core.service.SecurityPolicyRegistry;
import com.zifang.z.security.core.support.BuiltinSecurityPolicies;
import com.zifang.z.mask.core.service.MaskService;
import com.zifang.z.mask.core.support.DefaultPolicies;
import com.zifang.z.sense.core.service.SenseService;
import com.zifang.z.watermark.core.service.WatermarkService;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;

/**
 * z-security <b>编排引擎装配</b>（M2 #23 —— 引擎装配只有一处，在 starter，不在 web）。
 *
 * <p>本仓 starter 与三个能力仓不同：<b>自足带走本域数据源</b>
 * （{@link SecurityModuleDataSource}，含双包 {@code @MapperScan}）：
 * 引擎侧存储要构造器注入 Mapper，Mapper 没有 sqlSessionFactory 就是空的
 * ⇒ 数据源必须与引擎装配同生共死。
 *
 * <p><b>为什么不依赖 z-audit-starter / z-sense-starter 等四个 starter</b>：
 * 本域数据源的 {@code @MapperScan} 要把 {@code com.zifang.z.audit.core.mapper}
 * 绑到**本域** sqlSessionFactory 上（与 z-audit 同库同表的单写者口径）；
 * 若再依赖 z-audit-starter，它自带的 {@code AuditModuleDataSource} 会对同一个 Mapper 包
 * 二次 {@code @MapperScan}（绑另一个 factory）⇒ 双扫描冲突。故编排层直接依赖四个
 * <b>core</b>，自带全套引擎装配。
 *
 * <p>装配口径（四段流水线）：
 * <pre>
 *   z-sense-core     → SenseService   （识别）
 *   z-mask-core      → MaskService    （脱敏）
 *   z-watermark-core → WatermarkService（水印，挂溯源台账出口）
 *   z-audit-core     → AuditService   （审计，落库）
 * </pre>
 * 全部 {@code @ConditionalOnMissingBean} ⇒ 宿主自己装配了同类型 bean 时本仓让位。
 *
 * <p>⚠️ 本装配**不扫描**包树（无 {@code @ComponentScan}）—— 跨域交互按组织口径走 HTTP 边界，
 * 不把别人的 jar 拖进本仓上下文。
 *
 * @author zifang
 */
@AutoConfiguration
@Import(SecurityModuleDataSource.class)
public class SecurityStarterAutoConfiguration {

    /**
     * 敏感识别服务。
     *
     * @return 识别服务
     */
    @Bean
    @ConditionalOnMissingBean
    public SenseService senseService() {
        return new SenseService();
    }

    /**
     * 脱敏服务（默认策略集）。
     *
     * @param senseService 识别服务
     * @return 脱敏服务
     */
    @Bean
    @ConditionalOnMissingBean
    public MaskService maskService(SenseService senseService) {
        return new MaskService(senseService, DefaultPolicies.policies());
    }

    /**
     * 水印服务（**挂上溯源台账出口** —— M2 #22）。
     *
     * <p>⚠️ 早先实现是 {@code new WatermarkService()} —— **没挂任何溯源出口** ⇒
     * {@code embedTraced} 每次都标一句「未配置溯源台账出口」，
     * 而编排层的 AUDIT 阶段又只写 {@code SEC:} 处理行 ⇒
     * <b>「水印溯源行」永远缺位</b> ⇒ 打了水印却没留痕，而且没人知道。
     *
     * <p>修法：把 {@link LocalAuditTraceAdapter} 挂到 recorder + query 上 ⇒
     * 水印行（{@code WM:}）与处理行（{@code SEC:}）走**同一个** {@link AuditService}
     * ⇒ 共享同一条哈希链的链尾 ⇒ 链不分叉。
     *
     * @param auditService      审计门面
     * @param auditTraceService 反查服务
     * @return 水印服务
     */
    @Bean
    @ConditionalOnMissingBean
    public WatermarkService watermarkService(AuditService auditService,
                                             AuditTraceService auditTraceService) {
        WatermarkService service = new WatermarkService();
        LocalAuditTraceAdapter adapter = new LocalAuditTraceAdapter(auditService, auditTraceService);
        service.setTraceRecorder(adapter);
        service.setTraceQuery(adapter);
        return service;
    }

    /**
     * ★ 审计落库存储（M2 #22 —— 审计必须真的落库）。
     *
     * <p><b>⚠️ 为什么编排层要挂落库 Sink</b>：早先实现是 {@code new AuditService()}
     * —— **只算链不投递** ⇒ 编排层产生的安全事件**一条都没进台账**。
     * 结果是：盲水印里明明有追踪码，但拿去反查台账**永远是空的** ⇒ 溯源闭环是断的。
     *
     * <p><b>⚠️ 单写者口径</b>：{@code z_audit_event} 表的唯一权威写者是 z-audit 服务。
     * 本域直写同一张表适用于「编排层与审计域同进程部署」；
     * 若两者分进程部署，本域必须改走 HTTP 交给 z-audit 写（否则两条链分叉）。
     *
     * @param mapper 审计事件 Mapper
     * @return 落库存储
     */
    @Bean
    @ConditionalOnMissingBean
    public PersistentAuditStore persistentAuditStore(AuditEventMapper mapper) {
        return new PersistentAuditStore(mapper);
    }

    /**
     * 审计服务（**落库版** —— 事件真的进台账，且可按追踪码反查）。
     *
     * @param store 落库存储（兼查询出口）
     * @return 审计服务
     */
    @Bean
    @ConditionalOnMissingBean
    public AuditService auditService(PersistentAuditStore store) {
        AuditService service = new AuditService(store);
        service.setQuery(store);
        return service;
    }

    /**
     * ★ 溯源反查服务（M2 #22 —— 盲水印溯源的查询侧）。
     *
     * @param store 落库存储（兼查询出口）
     * @return 反查服务
     */
    @Bean
    @ConditionalOnMissingBean
    public AuditTraceService auditTraceService(PersistentAuditStore store) {
        return new AuditTraceService(store);
    }

    /**
     * 策略注册表（**内置场景集齐 5 个**）。
     *
     * @return 策略注册表
     */
    @Bean
    @ConditionalOnMissingBean
    public SecurityPolicyRegistry securityPolicyRegistry() {
        SecurityPolicyRegistry registry =
                new SecurityPolicyRegistry(SecurityPolicyRegistry.builtinDefault());
        for (com.zifang.z.security.core.domain.SecurityPolicy policy
                : BuiltinSecurityPolicies.all()) {
            registry.register(policy);
        }
        return registry;
    }

    /**
     * 策略台账存储（**落库版**）。
     *
     * <p>⚠️ 直接注入 {@code SecurityPolicyMapper}（不用 {@code @ConditionalOnBean}）——
     * 后者评估时机早于 {@code @MapperScan} 注册 ⇒ 条件恒不成立 ⇒ 服务静默缺失。
     *
     * @param mapper 策略 Mapper
     * @return 台账存储
     */
    @Bean
    @ConditionalOnMissingBean
    public PersistentPolicyStore persistentPolicyStore(SecurityPolicyMapper mapper) {
        return new PersistentPolicyStore(mapper);
    }

    /**
     * 策略台账服务（**发布 / 回滚 / 停用 / 热改**）。
     *
     * @param store 台账存储
     * @return 台账服务
     */
    @Bean
    @ConditionalOnMissingBean
    public PolicyLedgerService policyLedgerService(PersistentPolicyStore store) {
        return new PolicyLedgerService(store);
    }

    /**
     * ★ 启动装载：从台账读生效策略（**台账为空 ⇒ 播种内置策略**）。
     *
     * <p>做这件事的原因是：**不装载的话，台账里改的策略重启就没了**
     * ⇒ 热改只活到下次重启 ⇒ 等于「改了白改」。
     *
     * <p><b>⚠️ 装载失败不阻断启动</b>：台账读不出来（表没建 / 库连不上）
     * ⇒ 保留内置策略继续跑 ⇒ 安全防护不能因为台账故障就整个瘫掉。
     *
     * @param registry 策略注册表
     * @param ledger   策略台账服务
     * @return 装载器（启动后执行一次）
     */
    @Bean
    @ConditionalOnMissingBean
    public PolicyBootstrap policyBootstrap(SecurityPolicyRegistry registry,
                                          PolicyLedgerService ledger) {
        return new PolicyBootstrap(registry, ledger);
    }

    /**
     * 安全流水线（编排层主入口）。
     *
     * @param senseService     识别服务
     * @param maskService      脱敏服务
     * @param watermarkService 水印服务
     * @param auditService     审计服务
     * @return 流水线
     */
    @Bean
    @ConditionalOnMissingBean
    public SecurityPipeline securityPipeline(SenseService senseService,
                                            MaskService maskService,
                                            WatermarkService watermarkService,
                                            AuditService auditService) {
        return new SecurityPipeline(senseService, maskService, watermarkService, auditService);
    }
}
