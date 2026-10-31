package com.zifang.z.security.core.domain;

/**
 * 策略版本状态（**策略台账的状态机**）。
 *
 * <p><b>为什么要状态机而不是直接改一行</b>：策略是<b>合规口径</b>。
 * 「把导出场景的拦截阈值从 L4 改成 L3」不是一条 UPDATE 能了事的事 ——
 * 它必须能回答三个问题：
 * <ol>
 *   <li>现在生效的是<b>哪一版</b>？</li>
 *   <li>上一版是什么？出事了能不能<b>回滚</b>？</li>
 *   <li>谁在什么时候改的、为什么改？</li>
 * </ol>
 * 直接 UPDATE 覆盖 ⇒ 三个问题全部答不上来 ⇒ 合规审计直接挂。
 *
 * <p><b>状态流转</b>：
 * <pre>
 *   DRAFT ──publish──▶ PUBLISHED ──被新版本取代──▶ SUPERSEDED
 *                        │  ▲                        │
 *                    disable  └────rollback───────────┘
 *                        ▼
 *                    DISABLED
 * </pre>
 *
 * <p><b>★ 只有 PUBLISHED 参与运行时</b>：DRAFT 是草稿、DISABLED 是停用、
 * SUPERSEDED 是历史版本 —— 三者都<b>不生效</b>。
 *
 * @author zifang
 */
public enum PolicyStatus {

    /** 草稿：可编辑，不生效。 */
    DRAFT("草稿"),
    /** 已发布：**当前生效**。同一场景同一时刻**只能有一版**是 PUBLISHED。 */
    PUBLISHED("已发布"),
    /** 被取代：历史版本，可回滚到它。 */
    SUPERSEDED("已取代"),
    /** 已停用：该场景当前不生效（走兜底策略）。 */
    DISABLED("已停用");

    private final String label;

    PolicyStatus(String label) {
        this.label = label;
    }

    /** 中文标签。 */
    public String getLabel() {
        return label;
    }

    /**
     * 宽松解析（大小写不敏感；未知 ⇒ {@code null}）。
     *
     * @param code 状态码
     * @return 状态；未知返回 {@code null}
     */
    public static PolicyStatus fromCode(String code) {
        if (code == null || code.trim().isEmpty()) {
            return null;
        }
        String normalized = code.trim().toUpperCase(java.util.Locale.ROOT);
        for (PolicyStatus s : values()) {
            if (s.name().equals(normalized)) {
                return s;
            }
        }
        return null;
    }
}
