package com.zifang.z.security.core.spi;

import com.zifang.z.security.core.domain.PolicyRevision;

import java.util.List;

/**
 * 策略台账存储 SPI（**写与读分离**）。
 *
 * <p><b>为什么要 SPI</b>：策略台账可能落 MySQL、可能落配置中心、可能落内存（测试）。
 * 编排层只认这个接口 ⇒ 换实现不动消费方。
 *
 * <p><b>★ 不抛异常契约</b>：与 {@code AuditSink} 一致 —— 策略台账是**辅链路**，
 * 读失败不能把业务请求打断（退回内置策略继续跑）。
 *
 * @author zifang
 */
public interface PolicyStore {

    /**
     * 写入一个版本（**只新增，不覆盖**）。
     *
     * @param revision 版本记录（可空 ⇒ 忽略）
     * @return true = 写入成功
     */
    boolean save(PolicyRevision revision);

    /**
     * 取某场景**当前生效**（{@code PUBLISHED}）的版本。
     *
     * @param scene 场景码（可空 ⇒ 返回 {@code null}）
     * @return 版本记录；无则 {@code null}
     */
    PolicyRevision findPublished(String scene);

    /**
     * 取某策略的某个版本。
     *
     * @param policyId 策略 ID
     * @param revision 版本号
     * @return 版本记录；无则 {@code null}
     */
    PolicyRevision findRevision(String policyId, int revision);

    /**
     * 列某策略的全部版本（**版本号倒序**）。
     *
     * @param policyId 策略 ID
     * @return 版本记录列表（**永不为 null**）
     */
    List<PolicyRevision> listByPolicy(String policyId);

    /**
     * 列全部已发布版本（**一场景一版**）。
     *
     * @return 版本记录列表（**永不为 null**）
     */
    List<PolicyRevision> listPublished();

    /**
     * 列全部版本。
     *
     * @return 版本记录列表（**永不为 null**）
     */
    List<PolicyRevision> listAll();

    /**
     * 取某策略的最大版本号（无则 0）。
     *
     * @param policyId 策略 ID
     * @return 最大版本号
     */
    int maxRevision(String policyId);

    /**
     * 把某场景下所有已发布版本置为「已取代」。
     *
     * @param scene 场景码
     * @return 影响行数
     */
    int supersedePublished(String scene);

    /**
     * 把某策略的某个版本置为指定状态。
     *
     * @param policyId 策略 ID
     * @param revision 版本号
     * @param status   状态码
     * @return 影响行数
     */
    int updateStatus(String policyId, int revision, String status);

    /**
     * 删一个版本（**只允许删非 PUBLISHED 的**）。
     *
     * @param policyId 策略 ID
     * @param revision 版本号
     * @return 影响行数
     */
    int delete(String policyId, int revision);
}
