import { Card, Col, Row, Space, Tag, Typography } from 'antd'
import { useNavigate } from 'react-router-dom'
import { useEffect, useState } from 'react'
import { menuItems } from '../pages-manifest'

const { Title, Paragraph } = Typography

/** 首页 —— 登录后着陆页：欢迎语 + 快捷入口卡（菜单动态生成）。 */
export default function HomePage() {
    const navigate = useNavigate()
    const [user, setUser] = useState(null)

    useEffect(() => {
        const raw = localStorage.getItem('userInfo')
        if (raw) { try { setUser(JSON.parse(raw)) } catch { setUser({ name: raw }) } }
    }, [])

    const cards = menuItems.filter((m) => m.key !== '/security/home')

    return (
        <div>
            <Card style={{ marginBottom: 16, background: 'linear-gradient(135deg, #059669 0%, #047857 100%)', border: 'none' }}>
                <Space direction="vertical" size={4} style={{ color: '#fff' }}>
                    <Title level={3} style={{ color: '#fff', margin: 0 }}>
                        欢迎{user?.name ? `，${user.name}` : ''}
                    </Title>
                    <Paragraph style={{ color: 'rgba(255,255,255,0.85)', margin: 0 }}>
                        z-security 安全线编排 管理台
                    </Paragraph>
                    {user?.role && (
                        <Tag style={{ marginTop: 8, background: 'rgba(255,255,255,0.2)', color: '#fff', border: 'none' }}>{user.role}</Tag>
                    )}
                </Space>
            </Card>

            <Row gutter={[16, 16]}>
                {cards.map((m) => (
                    <Col key={m.key} xs={24} sm={12} md={12} lg={8}>
                        <Card hoverable onClick={() => navigate(m.key)} style={{ borderTop: `3px solid #059669` }}>
                            <Space align="start" size={12}>
                                <div style={{
                                    width: 44, height: 44, borderRadius: 8, flexShrink: 0,
                                    background: '#05966914', color: '#059669',
                                    display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 20,
                                }}>
                                    {m.icon}
                                </div>
                                <div style={{ minWidth: 0 }}>
                                    <div style={{ fontSize: 15, fontWeight: 600, color: '#0f172a' }}>{m.label}</div>
                                </div>
                            </Space>
                        </Card>
                    </Col>
                ))}
            </Row>
        </div>
    )
}
