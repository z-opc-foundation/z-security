package com.zifang.z.security.starter;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code AutoConfiguration.imports} <b>条目完整性</b>护栏（M2 #23）。
 *
 * <p><b>为什么需要它（实测得出，不是设想）</b>：z-sense 仓曾尝试只靠「宿主嵌入上下文能装配出引擎」
 * 这个正向用例来兜住 imports 文件的笔误 —— <b>实测兜不住</b>。
 * 把 imports 里的包名一个点改成斜杠后：{@code Class.forName} 直接 {@code ClassNotFoundException}
 * （JVM 层面这个名字就是坏的），但 Spring 上下文里引擎 bean <b>照样装配出来了</b> ——
 * Spring 侧对这类脏条目有容错，正向用例因此<b>恒绿</b>。
 *
 * <p>⇒ 真正能判红的护栏是：<b>把文件里每一行拿来当类名加载，加载不到即判红</b>。
 * 这是纯机械校验，不依赖 Spring 的任何容错行为。
 *
 * <p>⚠️ 这不是假想风险：z-security 的 imports 文件里就真的写着
 * {@code com.zifang.z.biz/security.web.config.SecurityAutoConfiguration}（斜杠），
 * 而它的管控面测试走**同包组件扫描**兜底 ⇒ <b>一个测试都没让它变红</b>。
 *
 * @author zifang
 */
class AutoConfigurationImportsIntegrityTest {

    private static final String IMPORTS_RESOURCE =
            "META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports";

    /**
     * 只校验**本组织自己写**的条目（{@code com.zifang.} 前缀）。
     *
     * <p>⚠️ 不能校验第三方（比如 spring-boot-autoconfigure 自己那份 imports）：
     * 它的 {@code JerseyAutoConfiguration} 等条目在「没有 spring-web」的 classpath 上本就
     * {@code NoClassDefFoundError} —— 那是**正常的可选依赖**，不是笔误，判它红就是误报。
     */
    private static final String OWN_PREFIX = "com.zifang.";

    @Test
    @DisplayName("★ 自家 AutoConfiguration.imports 的每一行都必须是真实存在的类")
    void everyOwnImportsEntryMustBeALoadableClass() throws Exception {
        ClassLoader loader = Thread.currentThread().getContextClassLoader();
        Enumeration<URL> urls = loader.getResources(IMPORTS_RESOURCE);
        List<String> problems = new ArrayList<>();
        int checked = 0;

        while (urls.hasMoreElements()) {
            URL url = urls.nextElement();
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(url.openStream(), StandardCharsets.UTF_8))) {
                String line;
                int no = 0;
                while ((line = reader.readLine()) != null) {
                    no++;
                    String entry = line.trim();
                    if (entry.isEmpty() || entry.startsWith("#") || !entry.startsWith(OWN_PREFIX)) {
                        continue;
                    }
                    checked++;
                    try {
                        Class.forName(entry, false, loader);
                    } catch (Throwable t) {
                        problems.add(url + " 第 " + no + " 行「" + entry + "」加载失败：" + t);
                    }
                }
            }
        }

        assertTrue(checked > 0, "★ 至少要校验到一条 " + OWN_PREFIX + " 前缀的 imports 条目（一条都没有说明护栏落空）");
        assertTrue(problems.isEmpty(),
                "★ imports 条目必须逐行可加载（纯机械校验，Spring 的容错救不了笔误）：\n"
                        + String.join("\n", problems));
    }
}
