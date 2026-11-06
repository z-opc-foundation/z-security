# z-security

> **数据安全域编排层** —— 场景 → 策略 → **识别 → 脱敏 → 水印 → 审计** 四段流水线。
> 边界一句话：**只做编排与拦截判定，不自己实现四个引擎的算法。**

安全线四层能力栈的**编排层**（业务方只报场景码）。同族：`z-sense` · `z-mask` · `z-watermark` · `z-audit`。

立项文档：lead `002_项目需求/001_特性需求/015_z-security_数据安全线`。

## 📋 基本信息

| 项 | 值 |
|---|---|
| 层 | **L1 业务编排仓**（`groupId=com.zifang`，内部件口径，同 z-biz） |
| 坐标 | `com.zifang:z-security`，版本 `1.0.0` |
| parent | `io.github.yuku123:z-boot-parent:1.2.1`（Java 17 / Spring Boot 3.3.13 火车） |
| 包名 | `com.zifang.z.security.core.*` |
| 依赖 | `z-sense-core` · `z-mask-core` · `z-watermark-core` · `z-audit-core`（**只依赖 core，不拖 web / starter 进本 JVM**） |
| 端口 | 8098 |
| 发布 | **不发 Maven Central**（`maven.deploy.skip=true`，同 z-biz） |
| 模块 | `z-security-core` · `z-security-starter` · `z-security-web` |

## 🎯 能力清单

| 能力 | 状态 | 代码位置 |
|---|---|---|
| 安全策略模型（场景 / 阶段序列 / 水印类型 / 阈值） | ✅ | `domain/SecurityPolicy` |
| 阶段枚举（SENSE / MASK / WATERMARK / AUDIT） | ✅ | `domain/SecurityStage` |
| 策略注册表（场景 → 策略 + 兜底） | ✅ | `service/SecurityPolicyRegistry` |
| 内置场景策略（5 个） | ✅ | `support/BuiltinSecurityPolicies` |
| 四段流水线编排 | ✅ | `service/SecurityPipeline` |
| **拦截判定**（命中级别 ≥ 阈值 ⇒ 拦，不出域） | ✅ | `service/SecurityPipeline#shouldBlock` |
| 流水线结果模型 | ✅ | `domain/SecurityResult` |
| REST 端点（跑流水线 / 查策略 / 列场景） | ✅ | `web/api/SecurityPipelineController` |
| 策略台账化（DB + 热改 + 审批） | ✅ M2 | `service/PolicyLedgerService` · `spi/PolicyStore` · `mapper/SecurityPolicyMapper` |
| 策略版本状态机（DRAFT/PUBLISHED/SUPERSEDED/DISABLED） | ✅ M2 | `domain/PolicyStatus` |
| 策略回滚（**以新版本号重发老内容**） | ✅ M2 | `service/PolicyLedgerService#rollback` |
| 启动装载（台账为唯一权威源 + 首次播种） | ✅ M2 | `service/PolicyLedgerService#bootstrap` · `web/config/PolicyBootstrap` |
| **识别一次脱敏一次**（按命中列表脱敏的重载） | ✅ M2 | MASK 阶段复用 SENSE 的命中列表（`maskService.mask(text, sense)`） |
| **★★ 溯源闭环**（追踪码单一来源 + WM/SEC 两条留痕 + 三态反查） | ✅ M2 #22 | `service/SecurityPipeline` · `service/LocalAuditTraceAdapter` |
| **★ 追踪码单一来源**（结果 ≡ 载荷 ≡ 审计 ≡ 台账） | ✅ M2 #22 | `SecurityPipeline#resolveTraceId` |
| **★ 不重复记账**（`WM:<traceId>` 水印行 + `SEC:<traceId>` 处理行） | ✅ M2 #22 | 两个幂等键各司其职，不撞同一行 |
| **★ 审计真落库**（早先 `new AuditService()` 只算链） | ✅ M2 #22 | `web/config/SecurityAutoConfiguration` → `PersistentAuditStore` |
| 域内 DDL | ✅ M2 | `_doc/002_deploy/init.sql`（`z_security_policy` + `z_audit_event` **副本**） |

## 🔑 核心口径

### 流水线顺序（拦截判定必须在脱敏之前）

```
文本 ──SENSE────▶ 命中列表（位置 + 分级）
       │
       ├─▶ 拦截判定：命中级别 ≥ 策略阈值 ⇒ BLOCKED（**直接返回，不出域**）
       │
       ├─▶ MASK────▶ 脱敏后文本（按命中位置替换）
       │
       ├─▶ WATERMARK▶ 打好溯源水印的文本
       │
       └─▶ AUDIT────▶ 审计留痕（这次处理发生了什么）
```

> ⚠ **拦截判定必须在脱敏前**：拦截的目的是「不让出域」，
> 如果先脱敏再判定，被拦的内容虽然没返回，但也已经算过脱敏了 —— 语义混乱。
>
> 判定本身**不依赖任何下游** ⇒ 即使脱敏 / 水印 / 审计全挂，拦截依然有效。

### 阈值语义：null = 不拦

| 写法 | 含义 |
|---|---|
| `blockThreshold = null` | **永不拦截**（只脱敏） |
| `blockThreshold = "L3"` | 命中 L3 / L4 ⇒ 拦 |
| `blockThreshold = "L4"` | 只有 L4 ⇒ 拦 |

> ⚠ **没有 L5 这一级**（分只有 L1–L4）。「不拦」要写 `null`，别写 `"L5"` ——
> 写 `"L5"` 解析出来是 null，结果虽一样，但读代码的人会以为存在 L5。

### 引擎实际分级（对齐 z-sense）

| 数据类型 | 级别 |
|---|---|
| 详细地址、中文姓名 | L2 内部 |
| **身份证、手机号、邮箱** | **L3 敏感** |
| **银行卡、凭据（密钥 / token）** | **L4 核心** |

⇒ 内置场景策略统一按 **L3 起拦**（个人敏感信息不出域）。

### 各段失败不拖垮整条链

| 段失败 | 降级行为 |
|---|---|
| 识别失败 | 无识别结果 ⇒ 不拦（**但**：识别挂了就等于没防护，见下） |
| 脱敏失败 | **原样返回**（不返回半脱敏的内容） |
| 水印失败 | 不加水印（内容仍可用） |
| 审计失败 | 忽略（审计是辅链路） |

> ⚠ **识别失败 ⇒ 不拦**是个已知风险：识别引擎挂了等于防护失效。
> 生产上应配「识别不可用 ⇒ fail-close（拒绝出域）」的开关。**M1 未做，记在这里。**

### ★ 策略台账化：改策略不用发版（M2 落地）

M1 的策略写死在代码里 ⇒ 改阈值要发版、无历史、无回滚。本轮把策略变成**台账**。

```
z_security_policy（表）
  ├─ policy_id + scene + revision（版本号，只增不减）
  ├─ status：DRAFT / PUBLISHED / SUPERSEDED / DISABLED
  ├─ stages / watermark_type / block_threshold / mask_policy_set_id / enabled
  └─ change_reason + operator_id + created_at（★ 合规三件套）
```

**四条硬口径**：

| 口径 | 为什么 |
|---|---|
| **操作人与变更原因必填** | 没有这两个字段，台账答不出「谁改的、为什么改」⇒ 内审必挂。**服务端直接拒绝**，不靠调用方自觉 |
| **发布 = 新版本**，不是 UPDATE 覆盖 | 覆盖就丢历史 ⇒ 「上次是谁把 L4 改成 L3 的」答不上来 |
| **一场景一版生效** | 发布新版前先把旧的降为 SUPERSEDED ⇒「当前生效的是哪一版」永远唯一 |
| **回滚 = 以新版本号重新发布老内容** | 版本号**不倒流** ⇒ 台账是一条只增不减的时间线，历史一条不丢 |

**热改的原子性**：注册表用 `replaceAll` **一次性换引用**。
若「先清空、再逐条加」，中间窗口内并发请求会看到**空注册表** ⇒ 全部走兜底
⇒ 拦截阈值掉到 L4 ⇒ **本该拦的敏感数据没拦，直接出域**。这个坑只在生产高并发时偶发，
本地压测看不出来 ⇒ 必须原子替换。

#### ★★ 台账读不出时绝不清空注册表

这是本轮踩到的**真 bug**（被 web 层测试抓出来）：台账表不存在 / 库连不上时，
`bootstrap` 拿到空列表 ⇒ 若照样 `replaceAll` ⇒ **内置策略被清空** ⇒ 全部场景降级到
DEFAULT 兜底（阈值 L4）⇒ **身份证 / 手机号这类 L3 数据直接出域**。

修法：**装载不出任何生效策略时就不碰注册表**（保留内置策略继续跑）。
宁可不装载，也不装载成空。

**降级方向的口径**：台账故障 ⇒ 降级到**内置策略**（仍有一层防护），
而不是启动失败（完全没防护）。

#### 启动装载：台账是唯一权威源

`ApplicationReadyEvent` 时从台账读生效策略 ⇒ **热改活过重启**。
台账为空 ⇒ 播种内置策略（rev1 / PUBLISHED / operator=system）⇒ 首次初始化也有台账。

> ⚠ 用 `ApplicationReadyEvent` 而不是 `InitializingBean`：后者在所有 bean 创建完之前跑
> ⇒ 此时 Mapper / DataSource 可能还没就绪 ⇒ 读台账必然失败。

### ★ 编排层只识别一次（M2 落地）

SENSE 阶段跑一次识别拿到分级做**拦截判定**，MASK 阶段把**同一份命中列表**交给
z-mask 的「按命中脱敏」重载 ⇒ **全文只扫一遍**。

```java
MaskResult masked = (sense != null)
        ? maskService.mask(current, sense)   // ★ 复用命中，不重扫
        : maskService.mask(current);          // 没跑 SENSE ⇒ 退回自识别
```

**为什么必须只识别一次**（M1 口径下 MASK 会再扫一遍，看似无害，实则有两个真问题）：

| 问题 | 说明 |
|---|---|
| **白扫两遍** | 识别是「全文 × 规则集」线性扫描，规则集上量后是双倍开销 |
| **★ 可能打架** | 两次识别之间若规则集热更，拦截判定用的分级与脱敏用的分级可能来自**不同规则集** ⇒「判了不拦，却按另一套规则脱了」⇒ 口径失真 |

> ⚠ **「真只识别一次」必须用计数识别器验**：光断言「脱出来一样」会被
> 「偷偷识别了第二次但结果碰巧相同」蒙混过去 ⇒ 数调用次数才是唯一可靠判据。
> 已写进 `SecurityPipelineSingleSenseTest`（5 例）。

### ★★ 溯源闭环：追踪码必须只有一个来源（M2 #22 落地）

拿到泄密文件的人提取出盲水印里的**追踪码**，拿这个码反查台账，
还原「谁在什么时候把哪份单号导出去的」。

```
流水线结果 traceId ≡ 水印载荷 traceId ≡ 审计事件 traceId ≡ 台账记录 traceId
```

> ⚠ **这条等式是 #22 的全部价值**：早先实现里流水线自己 `UUID.randomUUID()`、
> 水印用调用方给的 `traceId` ⇒ **两个不同的值** ⇒
> 拿水印里的码去反查审计台账**永远查不到** ⇒ 溯源闭环是断的。
> 而且**从功能上完全看不出来** —— 打水印成功、审计也成功，只有反查时才暴露。
>
> ⇒ 追踪码必须在**任何阶段开始前**定下来（`SecurityPipeline#resolveTraceId`），
> 且必须是**短码**（盲水印容量硬约束：UUID 32 字符需约 141 个词间隔 ⇒ 打不上）。

#### 两条留痕，各司其职

| 行 | 幂等键 | 内容 | 谁写 |
|---|---|---|---|
| **水印溯源行** | `WM:<traceId>` | 这份内容被打了水印：操作人 / 租户 / 单号 / 水印类型 | `LocalAuditTraceAdapter`（`embedTraced` 阶段） |
| **处理审计行** | `SEC:<traceId>` | 这次安全处理发生过：脱敏几处 / 有没有被拦 / 用的哪个策略 | `SecurityPipeline#audit`（AUDIT 阶段） |

> ⚠ **两个前缀 ⇒ 两行不撞同一行，也不丢任何线索**。
> 早先只有一行且语义重叠 ⇒ 要么重复、要么看不出「处理发生过」。

#### 三态反查（404 ≠ 503）

| 情况 | HTTP | 含义 | 处置 |
|---|---|---|---|
| 查到 | **200** | — | 看 summary |
| 台账里没有这条 | **404** | **合规缺口**（打过水印却没留痕，或记录被删） | **报警** |
| 台账不可用 | **503** | **基础设施故障**（库连不上 / SQL 报错） | **修库** |

> ⚠ 两者都返回「空列表」⇒ 运维会误判成「没发生过」⇒ **漏报合规缺口**。

#### ⚠ 单写者口径与部署前提

`z_audit_event` 的**唯一权威写者是 z-audit 服务**（哈希链要求单写者 ——
多写者各持链尾 ⇒ 链分叉 ⇒ 校验必然报断）。

**当前实现是「同进程直写」**：编排层与审计域同进程部署时，编排层通过
`PersistentAuditStore` 直写同一张表，并在 `_doc/002_deploy/init.sql` 里
带上 `z_audit_event` 的**定义副本**（否则只部署编排层就没这张表 ⇒
「打了水印却没留痕」）。

> ⚠ **两份定义必须一致**（以 z-audit 为权威源）——
> 对账脚本 `.workbuddy/check-audit-ddl-sync.py`（CI 判红）。
>
> ⚠ **分进程部署时编排层不得直写该表** ⇒ 走 HTTP 交给 z-audit 写。
> 部署三模式见 **#23**。

## 🎯 内置场景策略（5 个）

| 场景码 | 流水线 | 水印 | 阈值 | 意图 |
|---|---|---|---|---|
| `CONTRACT_VIEW` | 识别+脱敏 | 无 | **不拦** | 内部查看：脱敏即可 |
| `CONTRACT_EXPORT` | 全四段 | 显式文字 | L3 | 导出外发：可溯源 + 个人敏感信息不出域 |
| `INTERNAL_REPORT` | 全四段 | 盲水印 | L3 | 正文不留水印文字，但必须能反查 |
| `PUBLIC_SHARE` | 全四段 | 显式文字 | L3 | 对外分享：显式威慑 |
| `IMAGE_ASSET` | 全四段 | 图片隐写 | L3 | 图片资产：肉眼不可见地溯源 |

未登记的场景 ⇒ 走**兜底策略**（全流水线 + L4 阈值），**保证「没配也能跑」而不是直接失败**。

## 📡 REST 端点

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/z-team/api/security/process` | 跑一条流水线（按场景码） |
| GET | `/z-team/api/security/policies?scene=...` | 查某场景的策略 |
| GET | `/z-team/api/security/scenes` | 列全部已登记场景 |
| **POST** | `/z-team/api/security/policy/publish` | **发布一版策略**（新版本 + 取代旧版 + 热改生效） |
| **POST** | `/z-team/api/security/policy/rollback` | **回滚到历史版本**（以新版本号重发老内容） |
| **POST** | `/z-team/api/security/policy/disable` | **停用某场景**（该场景走兜底） |
| **GET** | `/z-team/api/security/policy/ledger` | **台账全量查询**（所有场景的所有版本） |
| **GET** | `/z-team/api/security/policy/published` | 当前生效策略视图 |
| **POST** | `/z-team/api/security/policy/refresh` | 手动热改刷新（改了库没发版时兜一把） |
| GET | `/api/security/health` | 健康检查（**无 /z-team 前缀**） |

**业务方怎么用**：只报场景码 + 内容，不自己拼脱敏策略。

```http
POST /z-team/api/security/process
{"scene":"CONTRACT_EXPORT","text":"...","operatorId":"op-1","tenantId":"t-9",
 "bizNo":"B-1","traceId":"trace-1","timestamp":1767225600000}
```

- 命中级别 ≥ 阈值 ⇒ **HTTP 403** + `status=BLOCKED`（业务方据此拒绝出域）
- 否则 HTTP 200 + `status=MASKED` / `PASS` + 处理后内容

## 🏗️ 项目结构

```
z-security/
├── pom.xml
├── z-security-core/
│   └── src/main/java/com/zifang/z/security/core/
│       ├── domain/    SecurityPolicy · SecurityStage · SecurityResult
│       │              PolicyStatus · PolicyRevision · PolicyRevisionRecord
│       ├── spi/       PolicyStore
│       ├── mapper/    SecurityPolicyMapper
│       ├── service/   SecurityPipeline（编排）· SecurityPolicyRegistry
│       │              PolicyLedgerService（台账）· PersistentPolicyStore
│       └── support/   BuiltinSecurityPolicies（5 个内置场景）· InMemoryPolicyStore
├── z-security-starter/
│   └── src/main/java/com/zifang/z/security/starter/config/
│       ├── SecurityStarterAutoConfiguration   编排引擎装配（仅此一处）+ @Import 本域数据源
│       ├── SecurityModuleDataSource           本域数据源（双包 @MapperScan，与引擎同生共死）
│       └── PolicyBootstrap                       策略启动装载（台账为空 ⇒ 播种内置）
├── z-security-web/
│   └── src/main/java/com/zifang/z/security/web/
│       ├── config/    SecurityAutoConfiguration（只管部署关切：健康检查，依赖 starter）
│       │              SecurityHealthIndicator
│       └── api/       SecurityPipelineController · SecurityPolicyAdminController
│                      SecurityHealthController · ZSecurityWebApplication
└── _doc/002_deploy/init.sql    # 1 张表（幂等）
```

> **编排引擎装配只有一处**：本仓 starter **自足带走本域数据源**
> （引擎侧存储要构造器注入 Mapper，Mapper 没有 sqlSessionFactory 就是空的
> ⇒ 数据源必须与引擎装配同生共死）。**starter 直接依赖四个能力仓的 `-core` 而非它们的
> starter** —— 本域数据源的双包 `@MapperScan` 要把 z-audit Mapper 绑到本域
> sqlSessionFactory（同库同表单写者口径），依赖 z-audit-starter 会引发同一个 Mapper 包
> 被两个数据源二次 `@MapperScan` 的冲突。

## 🧪 测试

```bash
export JAVA_HOME=/Users/zifang/Library/Java/JavaVirtualMachines/corretto-17.0.19/Contents/Home
mvn -f z-security-core/pom.xml test       # 70 例
mvn -f z-security-starter/pom.xml test    # 3 例（H2 真落库）
mvn -f z-security-web/pom.xml test        # 23 例（H2 + 真 HTTP）
```

> **CI**：push / PR 自动跑 GitHub Actions（`.github/workflows/ci.yml`：JDK 17 + `mvn -B -ntp verify`）。
> 因四引擎 core **未发 Central**，CI 先检出四个兄弟仓装 `*-core` 再构建本仓
> —— 需在本仓 Secrets 配 `Z_OPC_FOUNDATION_TOKEN`（classic，scope=repo），没配则 CI 红（基础设施缺口）。

**core 70 例**（21 + 5 + 26 + 9 + 9）：识别+脱敏、普通文本零改动、null 安全、禁用策略透传、
拦截（≥ 阈值）、**阈值区分 L3/L4**、null 阈值永不拦、拦截不外泄原文、
水印阶段生效/不生效、先脱敏后水印、审计留痕/不审计、拦截也留痕（DENIED）、
策略注册表（按场景 / 兜底）、内置 5 场景、查看场景不拦、阶段解析、默认阶段顺序、结果视图；
**「只识别一次」5 例**：全文只识别一次（计数验）、只跑 SENSE 也只一次、
只跑 MASK ⇒ 退回自识别一次（不是零次）、**规则中途变化 ⇒ 拦截与脱敏仍同源**、
拦截时命中数一致；
**「策略台账」26 例**：发布建版、操作人/原因必填、一场景一版、版本号只增、
按场景解析、阶段非法 ⇒ 整条不可用、回滚建新版、回滚留痕、停用、
原子替换、阶段编解码、**台账读空不清空注册表**、播种、不重复播种、**重启策略不丢**、
读回副本、PUBLISHED 不可删；
**「溯源闭环」9 例**（`SecurityPipelineTraceIdTest`）：追踪码自动补 + 回写载荷、
**结果/载荷/审计事件/台账四处完全一致**、调用方给码则全链路用它、
**水印里提取的码能反查到审计记录**、WM 与 SEC 不撞行、同 traceId 跑两次只留一条、
审计事件带租户/单号/操作人、台账炸了 ⇒ `traceError` 非空但水印仍生效、
无水印阶段 ⇒ 不产生溯源记录；
**「溯源台账适配器」9 例**（`LocalAuditTraceAdapterTest`）：**WM 行真落台账**、
幂等、空码拒写、反查命中、查不到返 null、**查不了抛异常**、
优先取 WM 行、**出口抛异常仍如实报 false**、事件按时间正序。

**web 23 例**（8 + 10 + 5）：查看场景只脱敏、导出场景脱敏+水印、导出场景 L3 ⇒ **403**、
导出场景 L4 ⇒ 403、未登记场景走兜底、策略查询端点、场景列表端点、健康检查可路由；
**「策略台账」10 例**：发布落库 + 热改生效、**操作人为空 400 且不落库**、
**变更原因为空 400**、一场景一版、**回滚建新版且历史不丢**、台账全量查询（含原因/操作人）、
停用、DDL 幂等、**重启后策略不丢**、**台账为空 ⇒ 播种内置 5 场景**；
**「溯源闭环 E2E」5 例**（`SecurityTraceClosureE2ETest`，真落库）：
**两条行都在**（WM + SEC）、水印行带单号/操作人/租户、**无溯源缺口**（`traceError` 为空）、
反查 200 + `trace` 单条视图、查不到 ⇒ **404**。

**starter 3 例**（嵌入式装配，宿主模拟应用放 `com.example.embedhost` 无关包树 ⇒ 组件扫描不可能兜底）：
纯宿主只靠 `AutoConfiguration.imports` 装出**编排引擎全家 + 本域数据源**（流水线/台账/装载器/审计/数据源齐备）、
**嵌入的流水线真跑**（查看场景 L3 身份证被遮蔽）+ **编排层直写台账可反查**（带链哈希）、
**imports 完整性逐行 `Class.forName` 纯机械校验**（实测：正向用例抓不住包名笔误——
Spring 侧有容错；本仓 web 的 imports 曾有真实斜杠笔误且管控面测试全绿，此护栏钉住后必判红）。

## 📌 踩坑留档

| 坑 | 现象 | 修法 |
|---|---|---|
| **测试数据校验位不对** | 身份证 `11010119900307123X` 校验位不过 ⇒ 引擎不命中 ⇒ 用例假红 | 换成 z-sense 里已验证的 `110101199003078515` |
| **分级假设错** | 以为身份证是 L4，实际引擎口径是 **L3**（银行卡/凭据才是 L4） | 改测试阈值并**同步改内置策略**（导出场景改 L3 起拦） |
| **骨架生成器包名笔误** | `com.zifang.z.biz/security.web.api`（斜杠混进包名）⇒ 编译期 `';' expected` | 全五仓扫 `com\.zifang\.z\.[a-z-]+/` 批量修 |
| **★★ imports 文件斜杠笔误（编译期看不见）** | web 的 `AutoConfiguration.imports` 里是 `com.zifang.z.biz/security.web.config...` —— 编译器不管资源文件 ⇒ 编译过；管控面测试走**同包组件扫描兜底** ⇒ **一个测试都没让它变红** | 改成点号；starter 的宿主模拟放无关包树（扫描兜不了底）+ **imports 完整性测试逐行 `Class.forName`**（纯机械校验，变异验证过：常态绿 / 斜杠变异红） |
| **测试断言写歪** | 期望 `status=PASS` 但实际 `MASKED`（有脱敏就是 MASKED）；导出场景用身份证 ⇒ 被 L3 阈值拦 ⇒ 403 | 改期望值；改用 L2 地址验证「脱敏+水印」两件事同时生效 |
| **`SensitiveDetector` 不是函数式接口** | 有 `detect` + `name` 两个方法 ⇒ 不能用 lambda 构造「坏识别器」 | 写匿名内部类实现两个方法 |
| **重叠消解口径与 z-sense 不一致** | z-sense 是「级别高者**替换**旧命中」，自己实现成「先占位者一律留」⇒ 上游已消解的命中被再消一次可能消出不同结果 ⇒ 错位遮蔽 | 与 `SenseResult#addHit` **逐条比对同算法**，并写单测钉住 |
| **★★ 台账读空 ⇒ 注册表被清空** | 启动装载时台账表不存在 ⇒ 拿到空列表 ⇒ `replaceAll(空)` ⇒ **内置 5 场景全没** ⇒ 全部降级 DEFAULT（阈值 L4）⇒ L3 身份证/手机号直接出域 | **装载不出任何生效策略时就不碰注册表**；web 层热改同样加这个守卫 |
| **原子替换被中途态打断** | 热改若「先清空再逐条加」⇒ 并发窗口内看到空注册表 ⇒ 阈值掉到 L4 ⇒ 敏感数据出域 | `replaceAll` 先构造新表再一次性换引用 |
| **`InitializingBean` 里读台账** | 上下文未就绪 ⇒ Mapper / DataSource 可能没起来 ⇒ 读台账必失败 | 改用 `ApplicationReadyEvent` |
| **★★ 追踪码两处各自生成** | 流水线 `UUID.randomUUID()` + 水印用调用方 traceId ⇒ **两个值** ⇒ 反查永远查不到，而**功能上看不出来**（打水印成功、审计也成功） | **追踪码在任何阶段开始前定下来**（`resolveTraceId`），四处用同一个值 |
| **★★ 编排层审计只算链不落库** | `new AuditService()` 无 Sink ⇒ 编排层的安全事件**一条都没进台账** ⇒ 「打了水印却没留痕」 | 挂 `PersistentAuditStore` 落库；并把 `z_audit_event` 加进本域 `init.sql`（否则只部署本域就缺表） |
| **编排层漏挂水印溯源出口** | `embedTraced` 每次标「未配置溯源台账出口」⇒ WM 行**永远缺位** | `LocalAuditTraceAdapter` 把 `WatermarkTrace` 转 `AuditEvent` 交给**同一个** `AuditService`（共享链尾 ⇒ 链不分叉） |
| **幂等命中被误报成「落库失败」** | 出口 `accept()` 返回 false 时不告诉你是「已在库里」还是「写失败」 ⇒ 重复提交会误报合规缺口 | 回查台账判「是否已在」；已在 ⇒ 算成功（**留痕在**），不在 ⇒ 如实报缺口 |
| **`z_audit_event` DDL 两份会漂移** | 本域 `init.sql` 带了表定义副本 ⇒ 改了 z-audit 那边不同步 ⇒ 一边能跑一边炸，**且不会有测试变红** | 对账脚本 `.workbuddy/check-audit-ddl-sync.py`（CI 判红） |

## 文档目录

本项目文档统一收口在 `_doc/` 下（lead 002 规范八类固定编号表，桶按需存在）:

- [`_doc/001_arch/`](_doc/001_arch/) — 架构与不变式：
  - [`00-overview.md`](_doc/001_arch/00-overview.md) — 总体设计（四段流水线、只依赖四仓 core、注册表/台账双权威源、十二条不变式含「台账读不出绝不清空注册表」、已知边界）。
- [`_doc/002_deploy/`](_doc/002_deploy/) — 部署资产与初始化 SQL：
  - [`init.sql`](_doc/002_deploy/init.sql) — 策略台账表 `z_security_policy`（幂等）。
  - [`00-deploy-modes.md`](_doc/002_deploy/00-deploy-modes.md) — 部署三模式（同进程直写 / 分进程 HTTP / 独立审计域：单写者归属、配置键、防链分叉禁配清单、代码现状与缺口）。
- [`_doc/005_testing/`](_doc/005_testing/) — 验收复跑：
  - [`001_验收复跑.md`](_doc/005_testing/001_验收复跑.md) — 五仓复跑命令、实测读数、已知边界与生产执行清单。
- [`_doc/003_script/`](_doc/003_script/) — 仓内工具脚本：
  - [`arch-gate/`](_doc/003_script/arch-gate/) — 架构棘轮守门人（CI 用，工具 + 基线 gate-baseline.json）。
  - [`vite-safe-empty/`](_doc/003_script/vite-safe-empty/) — vite 防误删 outDir 插件（只移不删，绕沙箱批量删除闸）。
