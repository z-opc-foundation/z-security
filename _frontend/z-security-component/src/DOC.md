# @yuku123/z-security-component

z-security（安全线编排中间件）可复用前端组件（lead 005 §9 component 共享）。

## 使用

```js
import { configureSecurity } from '@yuku123/z-security-component'
configureSecurity({ apiBase: '' })
```

## pages 入口（路由清单）

```js
import { routes, menuItems, appMeta } from '@yuku123/z-security-component/pages'
```

| 路径 | 页面 | 说明 |
|---|---|---|
| `/z-security/home` | HomePage | 首页着陆 |
| `/z-security/console` | ConsolePage | 流程试跑（POST `/z-team/api/security/process`，403 拦截单独呈现） |
| `/z-security/policies` | PoliciesPage | 场景/现行策略/已发布/变更台账 |
| `/z-security/docs` | ComponentDocPage | 组件文档 |

## 后端契约

- `POST /z-team/api/security/process`，body `{scene, text, operatorId, tenantId, bizNo, traceId, timestamp}`；拦截=403
- `GET /z-team/api/security/policies?scene` / `GET /scenes`
- `GET /z-team/api/security/policy/published`、`GET /policy/ledger?policyId`
- `GET /api/security/health`（健康检查）

`.` 入口保持 props-only（lead 005 §5）；fetch 只出现在 `./pages` 的默认装配里。
