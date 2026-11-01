import { useEffect, useState } from 'react'
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import { AppLayout, ErrorBoundary } from '@yuku123/z-frontend-common'
import { menuItems, routes, HomePage, LoginPage } from '@yuku123/z-security-component/pages'
import { Result, Button } from 'antd'

function NotFound() {
    return (
        <Result
            status="404"
            title="页面不存在"
            subTitle="路由表里没有这条路径。"
            extra={<Button type="primary" onClick={() => { window.location.href = '/security/home' }}>去首页</Button>}
        />
    )
}

// mock 账号不写死在仓里（001 凭证规范）：构建期注入 VITE_MOCK_USER / VITE_MOCK_PASSWORD
const MOCK_AUTH = import.meta.env.VITE_MOCK_USER && import.meta.env.VITE_MOCK_PASSWORD
    ? {
        username: import.meta.env.VITE_MOCK_USER,
        password: import.meta.env.VITE_MOCK_PASSWORD,
        user: { name: import.meta.env.VITE_MOCK_USER, role: '管理员' },
    }
    : null

function LoginRoute() {
    return <LoginPage mockAuth={MOCK_AUTH} />
}

function ProtectedShell() {
    const [user, setUser] = useState(null)
    const [ready, setReady] = useState(false)

    useEffect(() => {
        if (!localStorage.getItem('token')) {
            window.location.replace('/security/login')
            return
        }
        const raw = localStorage.getItem('userInfo')
        if (raw) { try { setUser(JSON.parse(raw)) } catch { setUser({ name: raw }) } }
        setReady(true)
    }, [])

    if (!ready) return null

    return (
        <AppLayout
            menuItems={menuItems}
            appTitle="z-security 安全线编排"
            appVersion="0.1.0"
            appUser={user}
            appIcon={{ icon: <div style={{ width: '100%', height: '100%', borderRadius: 8, background: 'linear-gradient(135deg, #059669, #047857)', color: '#fff', display: 'flex', alignItems: 'center', justifyContent: 'center', fontWeight: 700 }}>z</div>, color: '#059669', label: 'z-security 安全线编排' }}
        />
    )
}

/** suit 一次整合：登录路由 + 鉴权壳 + URL 即状态。 */
export default function App() {
    return (
        <ErrorBoundary>
            <BrowserRouter>
                <Routes>
                    <Route path="/security/login" element={<LoginRoute />} />
                    <Route element={<ProtectedShell />}>
                        <Route path="/" element={<Navigate to={menuItems[0].key} replace />} />
                        {routes.map((r) => (
                            <Route key={r.path} path={r.path} element={<r.Component />} />
                        ))}
                        <Route path="*" element={<NotFound />} />
                    </Route>
                </Routes>
            </BrowserRouter>
        </ErrorBoundary>
    )
}
