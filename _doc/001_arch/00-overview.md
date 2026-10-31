# 总体设计

> 口径截至 2026-10-31 的 `main`（M1 四段流水线 + M2 策略台账化已落地）。
> README 的「能力清单 / 核心口径 / 内置场景策略 / REST 端点 / 踩坑留档」是逐条细节的权威位置，
> 本文只讲**架构切分、依赖方向与不变式**。

## 1. 这仓解决什么问题

业务方不该自己拼安全策略——它只该报一个**场景码**。本仓把「场景 → 策略 → 四段流水线」收在一处：

```
(scene, text) ──▶ SecurityPolicyRegistry 查策略
                ├─▶ SENSE     识别（命中 + 分级）
                ├─▶ 拦截判定   命中级别 ≥ blockThreshold ⇒ BLOCKED，直接返回、不出域
                ├─▶ MASK      按同一份命中列表脱敏（不重扫）
                ├─▶ WATERMARK 打溯源水印
                └─▶ AUDIT     留痕
```

边界一句话：**只做编排与拦截判定，不自己实现四个引擎的算法**——
识别在 z-sense、遮蔽在 z-mask、水印在 z-watermark、留痕在 z-audit。

## 2. 模块与依赖方向

```
z-security/
├── z-security-core/
│   ├── domain/    SecurityPolicy · SecurityStage(SENSE/MASK/WATERMARK/AUDIT) · SecurityResult
│   │              PolicyRevision · PolicyRevisionRecord · PolicyStatus(DRAFT/PUBLISHED/SUPERSEDED/DISABLED)
│   ├── spi/       PolicyStore（台账读写口）
│   ├── service/   SecurityPipeline（编排门面）· SecurityPolicyRegistry（内存注册表）
│   │              PolicyLedgerService（台账：发布/回滚/停用/装载）· PersistentPolicyStore
│   ├── mapper/    SecurityPolicyMapper
│   └── support/   BuiltinSecurityPolicies（5 个内置场景）· InMemoryPolicyStore
├── z-security-starter/       编排引擎装配（仅此一处）+ 本域数据源（自足带走，3 例）
│   └── config/    SecurityStarterAutoConfiguration · SecurityModuleDataSource（双包 @MapperScan）
│                  · PolicyBootstrap（启动装载）
└── z-security-web/           管控面部署：依赖 starter，只管 REST + 健康检查（23 例）
    ├── config/    SecurityAutoConfiguration（健康检查）· SecurityHealthIndicator
    └── api/       SecurityPipelineController · SecurityPolicyAdminController · SecurityHealthController
```

三条结构约束：

1. **只依赖四个仓的 `-core`**（starter 也是），不把任何仓的 web / starter 拖进本 JVM ——
   编排层与引擎同进程，无 RPC 依赖；本域数据源的双包 `@MapperScan` 要把 z-audit Mapper
   绑到本域 sqlSessionFactory（同库同表单写者口径），依赖 z-audit-starter 会引发双扫描冲突；
2. **注册表是运行期唯一判定入口**，台账是**持久化唯一权威源**，两者靠 `replaceAll` 原子衔接；
3. 本仓是 **L1 业务编排仓**：`groupId=com.zifang`、`maven.deploy.skip=true`，**不发 Central**（同 z-biz）。

## 3. 不变式（改代码必须守住）

| 不变式 | 实现位置 | 破掉的后果 |
|---|---|---|
| **拦截判定在脱敏之前**，且判定不依赖任何下游 | `SecurityPipeline#shouldBlock` | 先脱敏再拦 ⇒ 语义混乱；判定依赖下游 ⇒ 引擎挂等于没防护 |
| 全文**只识别一次**，MASK 复用 SENSE 的命中列表 | `SecurityPipeline`（`mask(text, sense)`） | 两次识别之间规则集热更 ⇒ 判定与脱敏来自不同规则集 ⇒ 口径失真 |
| 「真只识别一次」用**计数识别器**验证 | `SecurityPipelineSingleSenseTest` | 只断言结果一致 ⇒ 「偷偷扫了第二遍但碰巧相同」蒙混过关 |
| 注册表热改用 `replaceAll` **一次性换引用** | `SecurityPolicyRegistry` | 「先清空再逐条加」的窗口内并发请求看到空注册表 ⇒ 全走兜底（L4）⇒ L3 数据出域 |
| **台账读不出 ⇒ 绝不 `replaceAll`** | `PolicyLedgerService#bootstrap` | 表不存在/库连不上时装载空列表 ⇒ 内置策略被清空 ⇒ 全部降级兜底（本轮真 bug，被 web 测试抓出） |
| 发布 = **新版本**，不是 UPDATE 覆盖 | `PolicyLedgerService#publish` | 覆盖即丢历史 ⇒「上次是谁把 L4 改成 L3」答不上来 |
| 一场景**只有一版 PUBLISHED** | 发布前旧版降 `SUPERSEDED` | 「当前生效哪一版」出现歧义 |
| 回滚 = **以新版本号重发老内容** | `PolicyLedgerService#rollback` | 版本号倒流 ⇒ 台账时间线不可信 |
| 操作人 + 变更原因**服务端必填** | 发布入口 | 台账答不出「谁改的、为什么」⇒ 内审必挂 |
| `blockThreshold=null` 才是「不拦」 | `SecurityPolicy` | 写 `"L5"` 解析成 null，结果一样但读代码的人以为存在 L5 |
| 未登记场景走**兜底策略**而非报错 | `SecurityPolicyRegistry` | 「没配也能跑」的可用性承诺 |
| 启动装载挂 `ApplicationReadyEvent` | `web/config/PolicyBootstrap` | 用 `InitializingBean` 时 Mapper/DataSource 未必就绪 ⇒ 读台账必失败 |

降级方向口径：台账故障 ⇒ 退到**内置策略**（仍有一层防护），而不是启动失败（完全没防护）。

## 4. 已知边界（不是 bug）

| 边界 | 影响 | 后续 |
|---|---|---|
| 识别失败 ⇒ 不拦 | 识别引擎挂掉等于防护失效 | 生产应配「识别不可用 ⇒ fail-close」开关 |
| 盲水印不带操作人/单号 | 只能反查追踪码 | 靠 traceId 回查 z-audit 台账 |
| 策略表只有 `z_security_policy` 一张 | 台账不含审批流 | 审批 M3 |

## 5. 相关文档

- DDL：[`_doc/002_deploy/init.sql`](_doc/002_deploy/init.sql)（幂等）
- 复跑与实测读数：[`_doc/005_testing/001_验收复跑.md`](_doc/005_testing/001_验收复跑.md)
- 四段引擎口径：z-sense / z-mask / z-watermark / z-audit 各自 `_doc/001_arch/00-overview.md`
- 细节权威位置：[README](../../README.md)
