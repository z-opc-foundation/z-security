package com.zifang.z.security.web.config;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;

/**
 * z-security <b>管控面（web）自动装配</b>。
 *
 * <p><b>只管部署关切</b>：健康检查。
 * <b>编排引擎装配 + 本域数据源已拆到 {@code z-security-starter}</b>（M2 #23）——
 * 四段流水线、策略注册表 / 台账 / 启动装载、落库审计与溯源反查、
 * {@code SecurityModuleDataSource}（含双包 {@code @MapperScan}）
 * 都由 {@code com.zifang.z.security.starter.config.SecurityStarterAutoConfiguration}
 * 提供，本类不再重复定义（重复定义会靠 {@code @ConditionalOnMissingBean} 侥幸让位，
 * 但读代码的人会以为有两处真装配）。
 *
 * <p>本仓 starter 与三个能力仓不同：<b>自足带走本域数据源</b> ——
 * 引擎侧存储要构造器注入 Mapper，Mapper 没有 sqlSessionFactory 就是空的
 * ⇒ 数据源必须与引擎装配同生共死，拆不进 web。
 *
 * <p>宿主引用本仓时：只想嵌入编排引擎 ⇒ 依赖 {@code z-security-starter}（轻，无 web 面）；
 * 想跑完整管控面 ⇒ 依赖 {@code z-security-web}（它传递带上 starter）。
 *
 * <p>⚠️ 本装配**不扫描**包树（无 {@code @ComponentScan}）—— 跨域交互按组织口径走 HTTP 边界，
 * 不把别人的 jar 拖进本仓上下文。
 *
 * @author zifang
 */
@AutoConfiguration
public class SecurityAutoConfiguration {

    /**
     * 本域健康检查（探活用）。
     *
     * @return 健康标识
     */
    @Bean
    @ConditionalOnMissingBean
    public SecurityHealthIndicator bizSecurityHealthIndicator() {
        return new SecurityHealthIndicator("z-security");
    }
}
