import { useEffect, useState } from 'react'
import { Button, Card, Descriptions, Space, Tag, Typography, message } from 'antd'
import { AuditOutlined, ReloadOutlined } from '@ant-design/icons'
import { securityApi } from '../services/api'

const { Text } = Typography

function KvList({ obj }) {
    if (!obj) return <Text type="secondary">空。</Text>
    return (
        <Descriptions bordered column={1} size="small">
            {Object.entries(obj)
                .filter(([, v]) => v !== null && v !== undefined)
                .map(([k, v]) => (
                    <Descriptions.Item key={k} label={k}>
                        <Text code={typeof v !== 'string'} copyable={typeof v === 'string' && v.length > 20}>
                            {typeof v === 'object' ? JSON.stringify(v) : String(v)}
                        </Text>
                    </Descriptions.Item>
                ))}
        </Descriptions>
    )
}

/** 策略台账：GET /scenes + /policies?scene + /policy/published + /policy/ledger。 */
export default function PoliciesPage() {
    const [scenes, setScenes] = useState([])
    const [scene, setScene] = useState('')
    const [policy, setPolicy] = useState(null)
    const [published, setPublished] = useState(null)
    const [ledger, setLedger] = useState(null)
    const [loading, setLoading] = useState(false)

    const loadAll = async () => {
        setLoading(true)
        try {
            const [s, p] = await Promise.allSettled([securityApi.scenes(), securityApi.published()])
            if (s.status === 'fulfilled') {
                const list = s.value.data?.scenes || []
                setScenes(list)
                if (list.length && !list.includes(scene)) setScene(list[0])
            }
            if (p.status === 'fulfilled') setPublished(p.value.data)
        } finally {
            setLoading(false)
        }
    }

    useEffect(() => { loadAll() /* eslint-disable-next-line */ }, [])

    useEffect(() => {
        if (!scene) return
        securityApi.policies(scene)
            .then(({ data }) => setPolicy(data))
            .catch((e) => message.error(`查场景策略失败：${e.response?.status || e.message}`))
    }, [scene])

    const loadLedger = async () => {
        const pid = policy?.policy?.policyId || policy?.policyId
        if (!pid) { message.warning('当前没有可查的策略 ID'); return }
        try {
            const { data } = await securityApi.ledger(pid)
            setLedger(data)
        } catch (e) {
            message.error(`查台账失败：${e.response?.status || e.message}`)
        }
    }

    return (
        <div>
            <Card
                title="场景与现行策略"
                style={{ marginBottom: 16 }}
                extra={<Button icon={<ReloadOutlined />} loading={loading} onClick={loadAll}>刷新</Button>}
            >
                <Space size={8} wrap style={{ marginBottom: 12 }}>
                    {scenes.length
                        ? scenes.map((s) => <Tag.CheckableTag key={s} checked={s === scene} onChange={() => setScene(s)}>{s}</Tag.CheckableTag>)
                        : <Text type="secondary">暂无场景数据（服务未达或未发布策略）。</Text>}
                </Space>
                {policy && <KvList obj={policy} />}
            </Card>

            <Card
                title="已发布策略"
                style={{ marginBottom: 16 }}
                extra={<Button icon={<AuditOutlined />} onClick={loadLedger}>查当前策略台账</Button>}
            >
                {published ? <KvList obj={published} /> : <Text type="secondary">暂无已发布策略。</Text>}
            </Card>

            {ledger && (
                <Card title="策略变更台账">
                    <KvList obj={ledger} />
                </Card>
            )}
        </div>
    )
}
