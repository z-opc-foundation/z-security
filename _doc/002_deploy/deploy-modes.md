# 部署三模式 —— `z_audit_event` 单写者口径的落法（M2 #34）

> 哈希链台账 `z_audit_event` **必须单写者**：多写者各持链尾 ⇒ 链分叉，篡改检出失效。
> 编排层（本仓）与 z-audit 都有能力写这张表 —— 谁写、怎么写，由部署形态决定。
> 本文把三种目标形态的**配置、单写者归属、代码支撑度**一次写清。

## 模式对照总表

| | 模式 A：同进程直写（**默认**） | 模式 B：分进程 HTTP | 模式 C：独立审计域（台账中心） |
|---|---|---|---|
| 写 `z_audit_event` 的进程 | 编排层进程（本域数据源直写） | z-audit 服务进程 | z-audit 服务进程（唯一，多业务面共用） |
| 编排层 SEC 处理行 | 本地 `PersistentAuditStore` ✅ | ❌ HTTP Sink 未提供（见「缺口」） | ❌ 同左 |
| WM 溯源行 | 本地 `LocalAuditTraceAdapter` ✅ | ✅ `AuditTraceHttpClient`（z-watermark-web 已实现） | ✅ 同左 |
| 按追踪码反查 | 本地 ✅ | ✅ HTTP（`GET /z-team/api/audit/trace/{id}`） | ✅ 同左 |
| 前提 | 编排层是**唯一**写者；z-audit 服务若部署只做查询/打锚点 | 编排层不得再开本地 Sink（当前代码做不到 ⇒ 见缺口） | 同 B |
| 代码支撑度 | **✅ 完整**（96 例覆盖） | **◐ 部分**（WM 行 + 查询侧已支持） | **◐ 部分**（同 B） |

## 模式 A：同进程直写（当前唯一可完整落地的形态）

- 编排层 starter **自足**装配 `SecurityModuleDataSource`（双包 `@MapperScan`：
  `biz.security.core.mapper` + `audit.core.mapper` 绑**本域** sqlSessionFactory）
  ⇒ `PersistentAuditStore` 直写 `z_audit_event`，与策略台账同库。
- z-audit 服务可以**不部署**；若部署，只当查询面 / 打锚点 / 校验面，**绝不能再开写**。
- 配置（开发 / 测试直连模式）：

  ```properties
  z.base.db.security.url=jdbc:h2:mem:...        # 或测试库
  z.base.db.security.username=sa
  z.base.db.security.password=
  ```

  生产口径仍是 MySQL 键名模式 `z.base.db.security.*`（`ModuleDataSourceTemplate`）。

- 单写者归属：**编排层进程**。验收：`GET /z-team/api/audit/chain/verify` 完整 + 锚点校验通过。

## 模式 B：分进程 HTTP（编排层不碰审计库）

- 归属：**z-audit 服务**是 `z_audit_event` 唯一写者；编排层与审计域分机 / 分库部署。
- 已支持的部分：
  - **WM 溯源行**：z-watermark-web 配 `z.watermark.audit-base-url=http://z-audit:port`
    ⇒ `AuditTraceHttpClient` 走 HTTP 写台账 + 反查（键为空串则不接，防空配误建客户端）。
  - **反查侧**：任何面都可走 `GET /z-team/api/audit/trace/{traceId}`（三态：200 / 404 / 503）。
- **⚠ 缺口（如实）**：编排层的 **SEC 处理行没有 HTTP Sink** —— `AuditService` 目前只有本地
  `PersistentAuditStore` 这一个出口。强行把编排层与审计库解耦部署 ⇒ SEC 行要么丢失、
  要么仍需本地半张链 ⇒ **链分叉**。
  **过渡期口径**：模式 B 未补齐前，编排层继续按模式 A 直写（与审计库同机），
  WM 行与查询侧先行走 HTTP；**完整模式 B 依赖后续给编排层加 `HttpAuditSink`（M3 候选）**。

## 模式 C：独立审计域（台账中心）

- 归属：z-audit 独立部署为**台账中心**，多业务面（编排层、watermark、其他域）统一交给它写；
  单写者 = z-audit 服务进程（唯一）。
- 与模式 B 的差别在**拓扑与治理**（中心化、独立权限、独立扩容、锚点集中管理），
  代码缺口与 B 相同（SEC 行 HTTP Sink 未提供）。
- **禁止**：任何业务面在模式 C 下再开本地 `z_audit_event` 写路径 —— 每开一条本地写 = 一条新链。

## 防链分叉禁配清单

1. **模式 A 下**：z-audit 服务不得对同一张 `z_audit_event` 开写（POST `/z-team/api/audit/events`
   会落库）—— 查询/打锚点可以，写事件不可以。
2. **模式 B / C 下**：编排层不得同时开「本地 Sink」与「HTTP Sink」。当前代码本地 Sink 是
   SEC 行唯一出口 ⇒ **B/C 落地前，编排层必须与审计库同机**（即事实上退回模式 A）。
3. **绝不要**给编排层配第二条数据源去写另一张库的 `z_audit_event` —— 两张表两条链，
   反查永远对不上，且**功能上看不出错**（各自链校验都「完整」）。

## 怎么确认没双写（验收清单）

- `GET /z-team/api/audit/chain/verify` ⇒ 完整（任何一处链分叉都会在交界处报 hash 不匹配）；
- 打锚点后 `GET /z-team/api/audit/chain/anchor/verify` ⇒ 通过（尾部截断 / 锚点篡改可检出）；
- 同一 `traceId` 反查：`WM:` 行与 `SEC:` 行**同链**（`prevHash` 相连）；
- 部署侧：写者进程与台账库账号一对一（z-audit 服务与编排层**不共用**写账号时才好审计「谁在写」）。

## 代码现状索引（改代码前先读）

| 关注点 | 位置 |
|---|---|
| 编排层数据源 + 双包 `@MapperScan` | `z-security-starter/.../SecurityModuleDataSource` |
| SEC 行落库 Sink（唯一出口） | `z-security-starter/.../SecurityStarterAutoConfiguration#persistentAuditStore` |
| WM 行 HTTP 出口（已支持分进程） | `z-watermark-web/.../client/AuditTraceHttpClient` + `z.watermark.audit-base-url` |
| z-audit 单写者声明（HTTP 面） | `z-audit/README.md` REST 端点段 |
| 链尾重载（重启不分叉） | `z-audit-starter/.../AuditChainTailLoader` |
