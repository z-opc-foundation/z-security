package com.example.embedhost;

import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * 模拟「只放 starter jar 的宿主」（M2 #23）。
 *
 * <p>包树 {@code com.example.embedhost} 与 starter 的装配类
 * （{@code com.zifang.z.security.starter.config.*}）**毫无关系** ⇒
 * 组件扫描绝无可能扫到装配类，装配只能走 {@code AutoConfiguration.imports}。
 * 用 {@code com.example.*} 是**不给包贴近留后门**。
 *
 * <p>⚠️ 本仓 web 的 imports 曾有**真实的包名斜杠笔误**
 * （{@code com.zifang.z.biz/security.web.config...}）——
 * 管控面测试因「同包组件扫描兜底」一个测试都没让它变红。
 * 本 starter 的装配与宿主模拟分处无关包树 + imports 完整性测试逐行 {@code Class.forName}
 * ⇒ 那类笔误在此**必判红**。
 *
 * @author zifang
 */
@SpringBootApplication
public class StarterHostTestApplication {
}
