package com.zifang.z.security.core.support;

import com.zifang.z.security.core.domain.SecurityPolicy;
import com.zifang.z.security.core.domain.SecurityStage;
import com.zifang.z.watermark.core.domain.WatermarkType;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * 内置安全场景策略（**默认场景口径**）。
 *
 * <p>把「常见业务场景」的口径先钉死，业务方不用每次现想：
 * <table border="1">
 *   <caption>内置场景</caption>
 *   <tr><th>场景码</th><th>流水线</th><th>水印</th><th>拦截阈值</th><th>意图</th></tr>
 *   <tr><td>{@code CONTRACT_VIEW}</td><td>识别+脱敏</td><td>无</td><td>不拦</td>
 *       <td>内部查看：脱敏即可，不必留痕也不必拦</td></tr>
 *   <tr><td>{@code CONTRACT_EXPORT}</td><td>全四段</td><td>显式文字</td><td>L4</td>
 *       <td>导出外发：必须可溯源 + 核心数据拦住</td></tr>
 *   <tr><td>{@code INTERNAL_REPORT}</td><td>全四段</td><td>盲水印</td><td>L3</td>
 *       <td>内部报告：不希望正文出现水印文字，但必须能反查</td></tr>
 *   <tr><td>{@code PUBLIC_SHARE}</td><td>全四段</td><td>显式文字</td><td>L3</td>
 *       <td>对外分享：显式威慑 + 核心数据不出</td></tr>
 *   <tr><td>{@code IMAGE_ASSET}</td><td>全四段</td><td>图片隐写</td><td>L4</td>
 *       <td>图片资产：隐写水印（肉眼不可见）+ 核心数据拦住</td></tr>
 * </table>
 *
 * @author zifang
 */
public final class BuiltinSecurityPolicies {

    /** 合同/文档查看。 */
    public static final String SCENE_CONTRACT_VIEW = "CONTRACT_VIEW";
    /** 合同/文档导出。 */
    public static final String SCENE_CONTRACT_EXPORT = "CONTRACT_EXPORT";
    /** 内部报告。 */
    public static final String SCENE_INTERNAL_REPORT = "INTERNAL_REPORT";
    /** 对外分享。 */
    public static final String SCENE_PUBLIC_SHARE = "PUBLIC_SHARE";
    /** 图片资产。 */
    public static final String SCENE_IMAGE_ASSET = "IMAGE_ASSET";

    private BuiltinSecurityPolicies() {
    }

    /**
     * 内置策略全集。
     *
     * @return 策略列表
     */
    public static List<SecurityPolicy> all() {
        List<SecurityPolicy> list = new ArrayList<>();

        SecurityPolicy view = new SecurityPolicy("P_VIEW", SCENE_CONTRACT_VIEW);
        view.setStages(new ArrayList<>(Arrays.asList(SecurityStage.SENSE, SecurityStage.MASK)));
        view.setWatermarkType(WatermarkType.VISIBLE_TEXT);
        // ⚠ **阈值空 = 不拦**（分只有 L1–L4，没有 L5）。
        //    写成 "L5" 会让 fromCode 返回 null ⇒ 判定恒为 false（结果一样），
        //    但读代码的人会以为存在 L5 这一级 ⇒ 用 null 把「不拦」写明白。
        view.setBlockThreshold(null);
        view.setRemark("内部查看：只脱敏，不拦不水印不审计");
        list.add(view);

        SecurityPolicy export = new SecurityPolicy("P_EXPORT", SCENE_CONTRACT_EXPORT);
        export.setStages(new ArrayList<>(SecurityStage.defaultOrder()));
        export.setWatermarkType(WatermarkType.VISIBLE_TEXT);
        // ⚠ 引擎口径：**身份证 / 手机号 = L3**（个人敏感信息），**银行卡 / 凭据 = L4**（核心）。
        //    导出场景拦 L3 ⇒ 个人敏感信息不出域；L4 本来也被 L3 阈值覆盖。
        export.setBlockThreshold("L3");
        export.setRemark("导出外发：显式水印 + L3 起拦（个人敏感信息不出域）");
        list.add(export);

        SecurityPolicy report = new SecurityPolicy("P_REPORT", SCENE_INTERNAL_REPORT);
        report.setStages(new ArrayList<>(SecurityStage.defaultOrder()));
        report.setWatermarkType(WatermarkType.BLIND_TRACE);
        report.setBlockThreshold("L3");
        report.setRemark("内部报告：盲水印（正文无水印文字）+ L3 起拦");
        list.add(report);

        SecurityPolicy share = new SecurityPolicy("P_SHARE", SCENE_PUBLIC_SHARE);
        share.setStages(new ArrayList<>(SecurityStage.defaultOrder()));
        share.setWatermarkType(WatermarkType.VISIBLE_TEXT);
        share.setBlockThreshold("L3");
        share.setRemark("对外分享：显式水印威慑 + L3 起拦");
        list.add(share);

        SecurityPolicy image = new SecurityPolicy("P_IMAGE", SCENE_IMAGE_ASSET);
        image.setStages(new ArrayList<>(SecurityStage.defaultOrder()));
        image.setWatermarkType(WatermarkType.IMAGE_STEGANO);
        image.setBlockThreshold("L3");
        image.setRemark("图片资产：隐写水印（肉眼不可见）+ L3 起拦");
        list.add(image);

        return list;
    }
}
