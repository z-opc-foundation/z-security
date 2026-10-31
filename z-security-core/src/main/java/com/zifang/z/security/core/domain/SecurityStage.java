package com.zifang.z.security.core.domain;

import java.util.Locale;

/**
 * 安全流水线阶段（识别 → 脱敏 → 水印 → 审计 四段）。
 *
 * <p><b>为什么编排层要显式枚举阶段</b>：编排层是「策略」的执行者 ——
 * 业务方可以只跑前两段（只脱敏不审计），也可以全跑。
 * 阶段枚举让「跑哪几段」变成**数据**（策略配置）而不是代码分支。
 *
 * @author zifang
 */
public enum SecurityStage {

    /** 识别：扫出敏感数据的位置与分级（z-sense）。 */
    SENSE,
    /** 脱敏：按策略遮蔽敏感数据（z-mask）。 */
    MASK,
    /** 水印：给内容打溯源水印（z-watermark）。 */
    WATERMARK,
    /** 审计：留痕（z-audit）。 */
    AUDIT;

    /**
     * 宽松解析（大小写不敏感；未知 ⇒ null，调用方自行决定跳过还是报错）。
     *
     * @param code 阶段码
     * @return 阶段；未知返回 null
     */
    public static SecurityStage fromCode(String code) {
        if (code == null || code.trim().isEmpty()) {
            return null;
        }
        String normalized = code.trim().toUpperCase(Locale.ROOT);
        for (SecurityStage s : values()) {
            if (s.name().equals(normalized)) {
                return s;
            }
        }
        return null;
    }

    /**
     * 默认全流水线顺序。
     *
     * @return 阶段序列
     */
    public static java.util.List<SecurityStage> defaultOrder() {
        return java.util.Arrays.asList(SENSE, MASK, WATERMARK, AUDIT);
    }
}
