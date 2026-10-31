package com.zifang.z.security.core.mapper;

import com.zifang.z.security.core.domain.PolicyRevisionRecord;
import org.apache.ibatis.annotations.Delete;
import org.apache.ibatis.annotations.Insert;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;
import org.apache.ibatis.annotations.Update;

import java.util.List;

/**
 * 安全策略版本 Mapper（表 {@code z_security_policy}）。
 *
 * <p>由 web 层 {@code @MapperScan} 绑到**本域** sqlSessionFactory 上。
 *
 * <p><b>为什么用实体而不是 {@code Map}</b>：H2 在 {@code MODE=MySQL} 下会把未加引号的
 * 别名转成大写（{@code AS tenantId} ⇒ {@code TENANTID}），
 * MyBatis 映射成 Map 时直接用原始列标签做 key ⇒ 取不到值；映射成实体则正常。
 *
 * @author zifang
 */
@Mapper
public interface SecurityPolicyMapper {

    /** 列清单（别名 → 实体字段名）。 */
    String COLUMNS = "id, policy_id AS policyId, scene, revision, status, stages, "
            + "watermark_type AS watermarkType, block_threshold AS blockThreshold, "
            + "mask_policy_set_id AS maskPolicySetId, enabled, remark, "
            + "change_reason AS changeReason, operator_id AS operatorId, created_at AS createdAt";

    /**
     * 插入一条版本记录。
     *
     * @param record 版本记录
     * @return 影响行数
     */
    @Insert("INSERT INTO z_security_policy "
            + "(policy_id, scene, revision, status, stages, watermark_type, block_threshold, "
            + "mask_policy_set_id, enabled, remark, change_reason, operator_id, created_at) "
            + "VALUES (#{policyId}, #{scene}, #{revision}, #{status}, #{stages}, #{watermarkType}, "
            + "#{blockThreshold}, #{maskPolicySetId}, #{enabled}, #{remark}, #{changeReason}, "
            + "#{operatorId}, #{createdAt})")
    int insert(PolicyRevisionRecord record);

    /**
     * 取某策略的最大版本号（**没有则返回 0**）。
     *
     * @param policyId 策略 ID
     * @return 最大版本号
     */
    @Select("SELECT COALESCE(MAX(revision), 0) FROM z_security_policy "
            + "WHERE policy_id = #{policyId}")
    int maxRevision(@Param("policyId") String policyId);

    /**
     * 取某场景**当前生效**的版本（{@code status = 'PUBLISHED'}）。
     *
     * @param scene 场景码
     * @return 版本记录；无则返回 {@code null}
     */
    @Select("SELECT " + COLUMNS + " FROM z_security_policy "
            + "WHERE scene = #{scene} AND status = 'PUBLISHED' "
            + "ORDER BY revision DESC LIMIT 1")
    PolicyRevisionRecord selectPublished(@Param("scene") String scene);

    /**
     * 取某策略的某个版本。
     *
     * @param policyId 策略 ID
     * @param revision 版本号
     * @return 版本记录；无则返回 {@code null}
     */
    @Select("SELECT " + COLUMNS + " FROM z_security_policy "
            + "WHERE policy_id = #{policyId} AND revision = #{revision} LIMIT 1")
    PolicyRevisionRecord selectByRevision(@Param("policyId") String policyId,
                                          @Param("revision") int revision);

    /**
     * 列某策略的全部版本（**版本号倒序** —— 新的在前）。
     *
     * @param policyId 策略 ID
     * @return 版本记录列表
     */
    @Select("SELECT " + COLUMNS + " FROM z_security_policy "
            + "WHERE policy_id = #{policyId} ORDER BY revision DESC")
    List<PolicyRevisionRecord> selectByPolicy(@Param("policyId") String policyId);

    /**
     * 列全部**已发布**版本（**一场景一版** ⇒ 场景不重复）。
     *
     * @return 版本记录列表
     */
    @Select("SELECT " + COLUMNS + " FROM z_security_policy "
            + "WHERE status = 'PUBLISHED' ORDER BY scene ASC")
    List<PolicyRevisionRecord> selectAllPublished();

    /**
     * 列全部版本（台账全量视图）。
     *
     * @return 版本记录列表
     */
    @Select("SELECT " + COLUMNS + " FROM z_security_policy "
            + "ORDER BY policy_id ASC, revision DESC")
    List<PolicyRevisionRecord> selectAll();

    /**
     * 把某场景下**所有**已发布版本置为「已取代」。
     *
     * <p><b>★ 为什么是「所有」而不是「当前那一版」</b>：
     * 发布新版本前必须先把旧的 PUBLISHED 降级，否则会出现「一个场景两版都生效」
     * ⇒ 取哪一版变成不确定 ⇒ 合规口径失真。
     *
     * @param scene 场景码
     * @return 影响行数
     */
    @Update("UPDATE z_security_policy SET status = 'SUPERSEDED' "
            + "WHERE scene = #{scene} AND status = 'PUBLISHED'")
    int supersedePublished(@Param("scene") String scene);

    /**
     * 把某策略的某个版本置为指定状态。
     *
     * @param policyId 策略 ID
     * @param revision 版本号
     * @param status   目标状态
     * @return 影响行数
     */
    @Update("UPDATE z_security_policy SET status = #{status} "
            + "WHERE policy_id = #{policyId} AND revision = #{revision}")
    int updateStatus(@Param("policyId") String policyId,
                     @Param("revision") int revision,
                     @Param("status") String status);

    /**
     * 删一个版本（**只允许删非 PUBLISHED 的**）。
     *
     * @param policyId 策略 ID
     * @param revision 版本号
     * @return 影响行数
     */
    @Delete("DELETE FROM z_security_policy "
            + "WHERE policy_id = #{policyId} AND revision = #{revision} AND status <> 'PUBLISHED'")
    int delete(@Param("policyId") String policyId, @Param("revision") int revision);
}
