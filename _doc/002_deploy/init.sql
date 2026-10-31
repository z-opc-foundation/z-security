-- =====================================================================
-- z-security 数据安全域编排层 —— DDL（**幂等**，可重复执行）
--
-- 目标库：生产 `oc` 库（与 z-biz / z-trade 共用单库）
-- 字符集：utf8mb4（执行前确认）
--
-- ⚠️ 本脚本**不含** CREATE INDEX（MySQL 8.0 无 CREATE INDEX IF NOT EXISTS
--    ⇒ 会破坏幂等）。二级索引需求另开 _doc/002_deploy/init/00X_*.sql 并**只执行一次**。
-- =====================================================================

-- ===========================================================================
-- ★ z_audit_event（审计事件台账）—— **本表不是本域的资产，是共用表**
--
-- 权威源：`z-audit/_doc/002_deploy/init.sql`。本文件里的这份定义**只是副本**，
-- 给「编排层与审计域同进程部署」用 —— 两域共用一张 `z_audit_event`（共库 `oc`），
-- 编排层跑完流水线要写两条留痕（水印溯源行 `WM:` + 处理审计行 `SEC:`），
-- 没有这张表 ⇒ **打了水印却没留痕**（M2 #22 修掉的缺口）。
--
-- ⚠️ **只允许同进程部署时直写本表**：哈希链要求**单写者**（多写者各持链尾 ⇒ 链分叉）。
--    编排层与 z-audit 分进程部署时，编排层**必须**改走 HTTP 交给 z-audit 写。
--
-- ⚠️ **两份定义必须一致**：改了 z-audit 那边的定义，这边要同步。
--    对账脚本：`.workbuddy/check-audit-ddl-sync.py`（CI 里跑，不一致即判红）。
-- ===========================================================================
CREATE TABLE IF NOT EXISTS z_audit_event (
    id            BIGINT       NOT NULL AUTO_INCREMENT,
    event_id      VARCHAR(64)  NOT NULL,
    trace_id      VARCHAR(64)  NULL,
    operator_id   VARCHAR(64)  NULL,
    operator_name VARCHAR(64)  NULL,
    tenant_id     VARCHAR(64)  NULL,
    action        VARCHAR(32)  NOT NULL,
    result        VARCHAR(16)  NOT NULL,
    target_type   VARCHAR(64)  NULL,
    target_id     VARCHAR(128) NULL,
    detail        VARCHAR(1024) NULL,
    client_ip     VARCHAR(64)  NULL,
    user_agent    VARCHAR(512) NULL,
    occurred_at   BIGINT       NOT NULL,
    prev_hash     VARCHAR(64)  NOT NULL,
    hash          VARCHAR(64)  NOT NULL,
    CONSTRAINT pk_z_audit_event PRIMARY KEY (id),
    CONSTRAINT uk_z_audit_event_event_id UNIQUE (event_id)
);

-- 幂等键：event_id 唯一 ⇒ 同一追踪码的水印溯源行重放只留一条（不重复记账）。


CREATE TABLE IF NOT EXISTS z_security_policy (
    id                 BIGINT       NOT NULL AUTO_INCREMENT,
    policy_id          VARCHAR(64)  NOT NULL COMMENT '策略 ID（同一策略的多版本共享）',
    scene              VARCHAR(64)  NOT NULL COMMENT '业务场景码（如 CONTRACT_EXPORT）',
    revision           INT          NOT NULL COMMENT '版本号（从 1 递增，只增不减）',
    status             VARCHAR(16)  NOT NULL COMMENT '状态：DRAFT/PUBLISHED/SUPERSEDED/DISABLED',
    stages             VARCHAR(256) NOT NULL DEFAULT '' COMMENT '阶段序列（逗号分隔，顺序即执行顺序）',
    watermark_type     VARCHAR(32)  NOT NULL DEFAULT 'VISIBLE_TEXT' COMMENT '水印类型',
    block_threshold    VARCHAR(8)   DEFAULT NULL COMMENT '拦截阈值（L1-L4；NULL = 不拦）',
    mask_policy_set_id VARCHAR(64)  DEFAULT NULL COMMENT '脱敏策略集 ID',
    enabled            TINYINT      NOT NULL DEFAULT 1 COMMENT '是否启用',
    remark             VARCHAR(512) DEFAULT NULL COMMENT '备注',
    change_reason      VARCHAR(512) DEFAULT NULL COMMENT '变更原因（合规要求：为什么改）',
    operator_id        VARCHAR(64)  DEFAULT NULL COMMENT '操作人（合规要求：谁改的）',
    created_at         BIGINT       NOT NULL COMMENT '创建时刻（epoch 毫秒）',
    CONSTRAINT pk_z_security_policy PRIMARY KEY (id)
);

-- ★ 同一策略的版本号唯一 ⇒ 重复发布同一版本号会被数据库挡住。
-- ★ 同一场景**只允许一版**处于 PUBLISHED —— 由应用层保证（发布时先把旧的降级）。
--   ⚠️ MySQL 唯一索引里 NULL 与 NULL **不相等** ⇒ 用普通索引 + 应用层约束，
--   不用带 NULL 列的唯一索引。
