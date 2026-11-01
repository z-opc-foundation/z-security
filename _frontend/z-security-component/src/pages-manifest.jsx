import { HomeOutlined, ApiOutlined, AuditOutlined, ReadOutlined } from '@ant-design/icons'
import HomePage from './pages/HomePage'
import LoginPage from './pages/LoginPage'
import ComponentDocPage from './pages/ComponentDoc.jsx'
import ConsolePage from './pages/ConsolePage.jsx'
import PoliciesPage from './pages/PoliciesPage.jsx'

/** 菜单 + 路由清单（lead 005 §8.3：主壳按本清单重组）。App 壳在 suit 侧组装。 */
export const appMeta = { title: 'z-security 安全线编排', short: 'z-security' }

export const menuItems = [
    { key: '/z-security/home', label: '首页', icon: <HomeOutlined /> },
    { key: '/z-security/console', label: '流程试跑', icon: <ApiOutlined /> },
    { key: '/z-security/policies', label: '策略台账', icon: <AuditOutlined /> },
    { key: '/z-security/docs', label: '组件文档', icon: <ReadOutlined /> },
]

export const routes = [
    { path: '/z-security/home', Component: HomePage },
    { path: '/z-security/console', Component: ConsolePage },
    { path: '/z-security/policies', Component: PoliciesPage },
    { path: '/z-security/docs', Component: ComponentDocPage },
]

export { HomePage, LoginPage, ComponentDocPage }
