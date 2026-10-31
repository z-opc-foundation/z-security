package com.zifang.z.security.starter.config;

import com.baomidou.mybatisplus.extension.spring.MybatisSqlSessionFactoryBean;
import com.zifang.z.boot.datasource.starter.ModuleDataSourceTemplate;
import org.apache.ibatis.session.SqlSessionFactory;
import org.mybatis.spring.annotation.MapperScan;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.util.StringUtils;

import javax.sql.DataSource;

/**
 * 本域数据源装配（对齐 z-biz / z-trade 各域的写法）。
 *
 * <p>配置键名模式：{@code z.base.db.security.*}（{@code ModuleDataSourceTemplate} 的权威前缀常量在这），
 * 缺省回落到 {@code z.base.db.default.*}。
 *
 * <p>{@code @MapperScan} 把 {@code com.zifang.z.security.core.mapper} 下的 Mapper 绑到**本域**的
 * {@code sqlSessionFactorySecurity} 上 —— 不跟别域共用 sqlSessionFactory，避免跨域 Mapper 互相污染。
 *
 * <p><b>★ M2 #22：同时扫 z-audit 的 Mapper</b> ——
 * 编排层要把自己产生的安全事件**落进审计台账**（否则审计只算链不留库，
 * 溯源反查永远查不到东西）。
 * ⚠️ <b>z-audit 的 Mapper 绑在**本域**的 sqlSessionFactory 上</b> ——
 * 本仓与 z-audit 共用同一个 {@code oc} 库、共用同一张 {@code z_audit_event} 表，
 * 绑同一个 factory 才有同一个数据源 ⇒ 落库落对地方。
 *
 * <p><b>⚠️ 单写者口径</b>：{@code z_audit_event} 表的**唯一权威写者是 z-audit 服务**。
 * 本域直写同一张表是**编排层与审计域同进程部署**的场景（编排层自带审计落库能力）；
 * 若两者**分进程**部署，编排层必须改走 HTTP 交给 z-audit 写（否则两条链分叉）。
 *
 * <p>开发 / 测试口径：显式给 {@code z.base.db.security.url}（JDBC URL）时走**直连模式**，
 * 不套 MySQL 键名模式 —— 本仓验收项（DDL 幂等、接口可路由）就靠它跑在本地 H2 上，
 * **不连生产 RDS**。生产口径仍然是 {@code z.base.db.security.*} 键名模式。
 *
 * @author zifang
 */
@Configuration
@MapperScan(
        basePackages = {
                "com.zifang.z.security.core.mapper",
                // ★ M2 #22：审计事件 Mapper 也绑本域数据源（同一张 z_audit_event 表）。
                "com.zifang.z.audit.core.mapper"
        },
        sqlSessionFactoryRef = "sqlSessionFactorySecurity"
)
public class SecurityModuleDataSource extends ModuleDataSourceTemplate {

    /**
     * 本域数据源。
     *
     * @param env 环境
     * @return 数据源
     */
    @Bean(name = "dataSourceSecurity")
    public DataSource dataSourceSecurity(Environment env) {
        String url = env.getProperty("z.base.db.security.url");
        if (StringUtils.hasText(url)) {
            return buildDirectDataSource(env, "z.base.db.security", url.trim());
        }
        return buildDataSource(env, "bizsecurity");
    }

    /**
     * 本域 sqlSessionFactory（绑本域数据源）。
     *
     * @param dataSource 本域数据源
     * @return sqlSessionFactory
     * @throws Exception 构建失败
     */
    @Bean(name = "sqlSessionFactorySecurity")
    public SqlSessionFactory sqlSessionFactorySecurity(
            @Qualifier("dataSourceSecurity") DataSource dataSource) throws Exception {
        MybatisSqlSessionFactoryBean factoryBean = new MybatisSqlSessionFactoryBean();
        factoryBean.setDataSource(dataSource);
        factoryBean.setMapperLocations(new org.springframework.core.io.support.PathMatchingResourcePatternResolver()
                .getResources("classpath*:mapper/**/*.xml"));
        return factoryBean.getObject();
    }

    /**
     * 直连模式数据源：显式 JDBC URL（开发 / 测试用；生产走 {@code z.base.db.security.*} 键名模式）。
     *
     * @param env    环境
     * @param prefix 配置键前缀
     * @param url    JDBC URL
     * @return 数据源
     */
    static DataSource buildDirectDataSource(Environment env, String prefix, String url) {
        com.alibaba.druid.pool.DruidDataSource dataSource = new com.alibaba.druid.pool.DruidDataSource();
        dataSource.setUrl(url);
        String username = env.getProperty(prefix + ".username");
        if (StringUtils.hasText(username)) {
            dataSource.setUsername(username.trim());
        }
        String password = env.getProperty(prefix + ".password");
        if (password != null) {
            dataSource.setPassword(password);
        }
        String driverClassName = env.getProperty(prefix + ".driver-class-name");
        if (StringUtils.hasText(driverClassName)) {
            dataSource.setDriverClassName(driverClassName.trim());
        }
        return dataSource;
    }
}
