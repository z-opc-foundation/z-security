import { useState } from 'react'
import { Button, Card, Descriptions, Form, Input, Space, Tag, Typography, message } from 'antd'
import { ApiOutlined } from '@ant-design/icons'
import { securityApi } from '../services/api'

const { TextArea } = Input
const { Text, Paragraph } = Typography

/**
 * 安全流程试跑：POST /z-team/api/security/process。
 * 拦截场景服务端返回 403 —— 这是业务结果不是错误，单独呈现。
 */
export default function ConsolePage() {
    const [form] = Form.useForm()
    const [loading, setLoading] = useState(false)
    const [result, setResult] = useState(null) // {kind: 'pass'|'blocked', data|detail}

    const runProcess = async (values) => {
        if (!values.text?.trim()) { message.warning('请输入试跑文本'); return }
        setLoading(true)
        setResult(null)
        try {
            const { data } = await securityApi.process({
                scene: values.scene || '',
                text: values.text,
                operatorId: values.operatorId || '',
                tenantId: values.tenantId || '',
                bizNo: values.bizNo || '',
                traceId: values.traceId || '',
                timestamp: Date.now(),
            })
            setResult({ kind: 'pass', data })
            message.success('流程放行（200）')
        } catch (e) {
            if (e.response?.status === 403) {
                setResult({ kind: 'blocked', detail: e.response?.data })
                message.warning('被策略拦截（403）')
            } else {
                message.error(`流程失败：${e.response?.status || e.message}`)
            }
        } finally {
            setLoading(false)
        }
    }

    return (
        <div>
            <Card title="安全流程试跑" style={{ marginBottom: 16 }}>
                <Form form={form} layout="vertical" onFinish={runProcess}>
                    <Space size={12} wrap>
                        <Form.Item name="scene" label="场景 scene" style={{ minWidth: 200 }}>
                            <Input placeholder="例如 default" />
                        </Form.Item>
                        <Form.Item name="operatorId" label="操作人" style={{ minWidth: 160 }}>
                            <Input placeholder="operatorId" />
                        </Form.Item>
                        <Form.Item name="tenantId" label="租户" style={{ minWidth: 160 }}>
                            <Input placeholder="tenantId" />
                        </Form.Item>
                        <Form.Item name="bizNo" label="业务号" style={{ minWidth: 160 }}>
                            <Input placeholder="bizNo" />
                        </Form.Item>
                        <Form.Item name="traceId" label="traceId（可空）" style={{ minWidth: 200 }}>
                            <Input placeholder="留空由链路生成" />
                        </Form.Item>
                    </Space>
                    <Form.Item name="text" label="试跑文本">
                        <TextArea rows={5} placeholder="粘贴要过安全管线的文本（可含敏感内容观察识别/脱敏/拦截行为）" />
                    </Form.Item>
                    <Button type="primary" icon={<ApiOutlined />} loading={loading} htmlType="submit">
                        执行流程
                    </Button>
                </Form>
            </Card>

            {result?.kind === 'pass' && (
                <Card title="流程结果（放行）">
                    {result.data.policyId && <Tag color="green">策略：{result.data.policyId}</Tag>}
                    {result.data.traceId && (
                        <div style={{ marginTop: 8 }}>
                            <Text type="secondary">traceId：</Text>
                            <Text copyable code>{result.data.traceId}</Text>
                        </div>
                    )}
                    {result.data.result != null && (
                        <div style={{ marginTop: 8 }}>
                            <Text type="secondary">处理结果：</Text>
                            {typeof result.data.result === 'object'
                                ? <Paragraph><pre style={{ whiteSpace: 'pre-wrap', marginBottom: 0 }}>{JSON.stringify(result.data.result, null, 2)}</pre></Paragraph>
                                : <Paragraph copyable style={{ whiteSpace: 'pre-wrap' }}>{String(result.data.result)}</Paragraph>}
                        </div>
                    )}
                </Card>
            )}
            {result?.kind === 'blocked' && (
                <Card title="流程结果（拦截）">
                    <Tag color="red">403 已拦截</Tag>
                    {result.detail != null && (
                        <Descriptions bordered column={1} size="small" style={{ marginTop: 12 }}>
                            {Object.entries(result.detail).map(([k, v]) => (
                                <Descriptions.Item key={k} label={k}>
                                    <Text code={typeof v !== 'string'}>{typeof v === 'object' ? JSON.stringify(v) : String(v)}</Text>
                                </Descriptions.Item>
                            ))}
                        </Descriptions>
                    )}
                </Card>
            )}
        </div>
    )
}
