import { useCallback, useEffect, useRef, useState } from 'react'
import { Alert, App, Checkbox, Descriptions, Empty, Form, Input, InputNumber, Modal, Radio, Spin, Tabs, Tag, Tooltip } from 'antd'
import { Cloud, Layers3, Plus, RefreshCw, Save, Star, Trash2, Unplug } from 'lucide-react'
import { api } from '../api'
import { modelConfigurationError, publicModelConfiguration, publicModelConfigurations, publicModelConnectionTest, validModelEndpoint } from '../modelConfigurations'
import type { ModelConfiguration, ModelConfigurationInput, ModelConfigurations, ModelConnectionTest, RuntimeMode, RuntimeProfiles } from '../types'
import { MODE_LABELS } from '../workflowModel'
import { LiquidGlassButton } from './LiquidGlassButton'
import '../model-settings.css'

interface ConfigurationFields extends ModelConfigurationInput { api_key: string; set_default: boolean }
type Operation = 'save' | 'test' | 'default' | 'delete' | null

const EMPTY_FIELDS: ConfigurationFields = {
  name: '', provider_id: '', base_url: '', api_mode: 'chat_completions', model: '',
  timeout_seconds: 120, enabled: true, api_key: '', set_default: false,
}

function fieldsFor(profile: ModelConfiguration | undefined): ConfigurationFields {
  return profile ? { ...EMPTY_FIELDS, name: profile.name, provider_id: profile.provider_id,
    base_url: profile.base_url, api_mode: profile.api_mode, model: profile.model,
    timeout_seconds: profile.timeout_seconds, enabled: profile.enabled } : { ...EMPTY_FIELDS }
}

export function ModelSettingsDialog({ open, initialMode, profiles, error, refreshing, onRefresh, onClose, workInFlight = false }: {
  open: boolean
  initialMode: RuntimeMode
  profiles: RuntimeProfiles | null
  error: string | null
  refreshing: boolean
  onRefresh: () => void
  onClose: () => void
  workInFlight?: boolean
}) {
  const [tab, setTab] = useState(initialMode === 'deterministic' ? 'deterministic' : 'cloud')
  const [form] = Form.useForm<ConfigurationFields>()
  const { modal } = App.useApp()
  const [configurations, setConfigurations] = useState<ModelConfigurations | null>(null)
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const selectedRef = useRef<string | null>(null)
  const newId = useRef('')
  const requestVersion = useRef(0)
  const operationInFlight = useRef(false)
  const [loading, setLoading] = useState(false)
  const [operation, setOperation] = useState<Operation>(null)
  const [dirty, setDirty] = useState(false)
  const [reconcileRequired, setReconcileRequired] = useState(false)
  const [configurationError, setConfigurationError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [tested, setTested] = useState<{ id: string; result: ModelConnectionTest } | null>(null)
  const [confirmTest, setConfirmTest] = useState(false)
  const [testConsent, setTestConsent] = useState(false)
  const selected = configurations?.items.find((item) => item.id === selectedId)
  const editable = configurations !== null && !loading && operation === null && !reconcileRequired
  const adapterReady = configurations?.supported_api_modes.includes('chat_completions') === true
  const selectedAdapterReady = selected?.api_mode === 'chat_completions' && adapterReady
  const ruleProfile = profiles?.items.find((item) => item.mode === 'deterministic')
  const enabled = Form.useWatch('enabled', form)
  const endpoint = Form.useWatch('base_url', form)
  const providerId = Form.useWatch('provider_id', form)
  const requiresFreshKey = Boolean(selected?.has_key && (endpoint?.trim() !== selected.base_url || providerId?.trim() !== selected.provider_id))

  const selectProfile = useCallback((profile: ModelConfiguration | undefined) => {
    selectedRef.current = profile?.id ?? null
    setSelectedId(profile?.id ?? null)
    if (!profile) newId.current = crypto.randomUUID()
    form.resetFields()
    form.setFieldsValue(fieldsFor(profile))
    setDirty(false); setNotice(null); setTested(null); setConfirmTest(false); setTestConsent(false)
  }, [form])

  const refresh = useCallback(async (preferredId?: string) => {
    const version = ++requestVersion.current
    setLoading(true); setConfigurationError(null)
    try {
      const next = publicModelConfigurations(await api.modelConfigurations())
      if (version !== requestVersion.current) return
      setConfigurations(next)
      setReconcileRequired(false)
      const id = preferredId ?? selectedRef.current ?? next.default_id
      selectProfile(next.items.find((item) => item.id === id) ?? next.items[0])
      return next
    } catch (failure) {
      if (version !== requestVersion.current) return
      setConfigurations(null); selectProfile(undefined)
      setConfigurationError(modelConfigurationError(failure, '配置读取失败；未判定为无配置，请刷新重试。'))
      return null
    } finally { if (version === requestVersion.current) setLoading(false) }
  }, [selectProfile])

  useEffect(() => {
    if (!open) return undefined
    setTab(initialMode === 'deterministic' ? 'deterministic' : 'cloud')
    setConfigurations(null); selectedRef.current = null
    void refresh()
    return () => {
      requestVersion.current += 1
      form.setFieldValue('api_key', '')
      setConfirmTest(false); setTestConsent(false)
    }
  }, [form, initialMode, open, refresh])

  const choose = (profile?: ModelConfiguration) => {
    if (!editable) return
    const apply = () => { setConfigurationError(null); selectProfile(profile) }
    if (dirty) modal.confirm({ title: '放弃未保存的配置？', content: '切换后未保存的字段与密钥输入将清空。',
      okText: '放弃并切换', cancelText: '继续编辑', onOk: apply })
    else apply()
  }

  const close = () => {
    if (operationInFlight.current) return
    form.setFieldValue('api_key', '')
    setDirty(false); setConfirmTest(false); setTestConsent(false); setTested(null)
    onClose()
  }

  const save = async (values: ConfigurationFields) => {
    if (operationInFlight.current || !editable || !adapterReady || values.api_mode !== 'chat_completions' || workInFlight) return
    if ((values.enabled && !selected?.has_key || requiresFreshKey) && !values.api_key.trim()) {
      form.setFields([{ name: 'api_key', errors: ['请填写此服务的 API 密钥'] }])
      return
    }
    const id = selectedId ?? newId.current
    const body: ModelConfigurationInput = {
      name: values.name.trim(), provider_id: values.provider_id.trim(), base_url: values.base_url.trim(),
      api_mode: values.api_mode, model: values.model.trim(), timeout_seconds: values.timeout_seconds,
      enabled: values.enabled,
      ...(values.api_key.trim() ? { api_key: values.api_key.trim() } : {}),
      ...(values.set_default ? { set_default: true } : {}),
    }
    form.setFieldValue('api_key', '')
    setDirty(false)
    operationInFlight.current = true
    setOperation('save'); setConfigurationError(null); setNotice(null); setTested(null)
    try {
      const stored = publicModelConfiguration(await api.saveModelConfiguration(id, body))
      if (stored.id !== id) throw new Error('Configuration identity mismatch')
      await refresh(id)
      setNotice('配置已保存，尚未测试连接；实际调用结果以运行记录为准。')
      onRefresh()
    } catch (failure) {
      setReconcileRequired(true)
      setConfigurationError(modelConfigurationError(failure, '保存结果未确认，请刷新配置后核对；未自动重复提交。'))
    } finally { operationInFlight.current = false; setOperation(null) }
  }

  const setDefault = async () => {
    if (!selected || operationInFlight.current || !editable || dirty || workInFlight) return
    operationInFlight.current = true
    setOperation('default'); setConfigurationError(null); setNotice(null)
    try {
      await api.setDefaultModelConfiguration(selected.id)
      const next = await refresh(selected.id)
      if (!next) return
      if (next.default_id !== selected.id) throw new Error('Default configuration not confirmed')
      setNotice('默认服务已更新，仅作用于后续任务。')
      onRefresh()
    } catch (failure) {
      setReconcileRequired(true)
      setConfigurationError(modelConfigurationError(failure, '默认服务变更结果未确认，请刷新核对；当前任务未被重启。'))
    } finally { operationInFlight.current = false; setOperation(null) }
  }

  const remove = () => {
    if (!selected || selected.is_default || !editable || workInFlight || dirty) return
    const id = selected.id
    modal.confirm({ title: `删除配置“${selected.name}”？`, content: '删除后不能用于新任务，已有运行记录保留。',
      okText: '删除配置', okButtonProps: { danger: true }, cancelText: '取消', onOk: async () => {
        if (operationInFlight.current) return
        operationInFlight.current = true
        setOperation('delete'); setConfigurationError(null); setNotice(null)
        try {
          await api.deleteModelConfiguration(id)
          const next = await refresh()
          if (!next) return
          if (next.items.some((item) => item.id === id)) throw new Error('Configuration removal not confirmed')
          setNotice('配置已删除，已有任务记录不变。')
          onRefresh()
        } catch (failure) {
          setReconcileRequired(true)
          setConfigurationError(modelConfigurationError(failure, '删除结果未确认，请刷新配置后核对。'))
        }
        finally { operationInFlight.current = false; setOperation(null) }
      } })
  }

  const testConnection = async () => {
    if (!selected || !testConsent || !editable || dirty || operationInFlight.current || !selectedAdapterReady) return
    operationInFlight.current = true
    setOperation('test'); setConfirmTest(false); setTestConsent(false); setTested(null); setConfigurationError(null); setNotice(null)
    try {
      const result = publicModelConnectionTest(await api.testModelConfiguration(selected.id))
      if (result.model_requested !== null && result.model_requested !== selected.model) throw new Error('Test configuration mismatch')
      setTested({ id: selected.id, result })
    } catch (failure) {
      setConfigurationError(modelConfigurationError(failure, '连接测试结果未确认；可能已产生调用费用，未自动重试。'))
    } finally { operationInFlight.current = false; setOperation(null) }
  }

  const edit = () => { setDirty(true); setNotice(null); setTested(null) }
  const testResult = tested?.id === selectedId ? tested.result : null
  const connectionDisabled = !editable || dirty || !selectedAdapterReady || !selected?.enabled || !selected.has_key

  return <>
    <Modal open={open} onCancel={close} title="智能体运行配置" width={1040} footer={null}
      className="model-settings-dialog" destroyOnHidden maskClosable={operation === null} keyboard={operation === null}
      closable={operation === null}>
      <Tabs activeKey={tab} onChange={setTab} items={[
        { key: 'cloud', label: <span className="model-settings-tab"><Cloud size={16} />{MODE_LABELS.cloud}</span>, forceRender: true,
          children: <>
            {configurationError ? <Alert type="error" showIcon message={configurationError} /> : null}
            {notice ? <Alert type="info" showIcon message={notice} /> : null}
            <div className="model-configuration-layout">
              <aside className="model-configuration-list" aria-label="模型服务配置">
                <div className="model-config-list-heading"><h3>模型服务</h3><Tooltip title="新增服务配置"><LiquidGlassButton size="small" icon={<Plus size={16} />} aria-label="新增服务配置" disabled={!editable} onClick={() => choose()} /></Tooltip></div>
                {loading ? <Spin size="small" aria-label="读取模型服务" /> : null}
                {configurations?.items.map((item) => <button type="button" key={item.id} className={`model-config-entry${selectedId === item.id ? ' selected' : ''}`}
                  aria-pressed={selectedId === item.id} disabled={!editable} onClick={() => choose(item)}>
                  <Cloud size={17} /><span><strong>{item.name}</strong><small>{item.model}</small></span>
                  {item.is_default ? <Star size={14} aria-label="默认服务" /> : null}
                  <span className={`model-config-entry-status${item.enabled ? ' enabled' : ''}`}>{item.enabled ? '启用' : '停用'}</span>
                </button>)}
                {configurations && configurations.items.length === 0 ? <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="尚无模型服务" /> : null}
                {configurations && selectedId === null ? <span className="model-config-new-entry"><Plus size={14} />新服务配置</span> : null}
              </aside>
              <div className="model-configuration-editor">
                <div className="model-config-editor-heading"><h3>{selected ? selected.name : '新服务配置'}</h3>
                  {selected ? <Tag color={selected.has_key ? 'blue' : 'orange'}>{selected.has_key ? '密钥已保存' : '密钥未配置'}</Tag> : null}
                </div>
                <Form form={form} layout="vertical" initialValues={EMPTY_FIELDS} onFinish={(values) => void save(values)}
                  onValuesChange={edit} disabled={!editable} preserve={false} autoComplete="off" className="model-configuration-form">
                  <div className="model-config-field-grid">
                    <Form.Item name="name" label="名称" rules={[{ required: true, whitespace: true, message: '请输入配置名称' }, { max: 80, message: '名称不超过 80 个字符' },
                      { validator: (_, value: string) => !value || Array.from(value).every((character) => character.charCodeAt(0) >= 32 && character.charCodeAt(0) !== 127) ? Promise.resolve() : Promise.reject(new Error('名称不能含控制字符')) }]}>
                      <Input maxLength={80} placeholder="例如：企业智能体服务" />
                    </Form.Item>
                    <Form.Item name="provider_id" label="提供商 ID" rules={[{ required: true, message: '请输入提供商标识' }, { pattern: /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$/, message: '使用字母、数字、点、下划线或连字符，最多 64 位' }]}>
                      <Input maxLength={64} placeholder="provider-id" />
                    </Form.Item>
                    <Form.Item name="base_url" label="端点 URL" className="model-config-full-field" rules={[{ required: true, message: '请输入服务端点' },
                      { validator: (_, value: string) => !value || validModelEndpoint(value.trim()) ? Promise.resolve() : Promise.reject(new Error('使用公开 HTTPS 地址，不含凭据、查询参数、片段或本机地址')) }, { max: 512, message: '端点 URL 不超过 512 个字符' }]}>
                      <Input maxLength={512} placeholder="https://api.example.com/v1" spellCheck={false} />
                    </Form.Item>
                    <Form.Item name="api_mode" label="API 模式" className="model-config-full-field" rules={[{ required: true }]}>
                      <Radio.Group className="model-api-modes" optionType="button" buttonStyle="solid" options={[
                        { value: 'chat_completions', label: 'Chat Completions', disabled: !adapterReady },
                        { value: 'responses', label: 'Responses API · 未适配', disabled: true },
                        { value: 'anthropic_messages', label: 'Anthropic Messages · 未适配', disabled: true },
                      ]} aria-label="API 模式" />
                    </Form.Item>
                    <Form.Item name="model" label="模型 ID" rules={[{ required: true, whitespace: true, message: '请输入服务商提供的完整模型 ID' }, { max: 128, message: '模型 ID 不超过 128 个字符' }, { pattern: /^[A-Za-z0-9][A-Za-z0-9_.:/-]*$/, message: '模型 ID 格式不符合接口要求' }]}>
                      <Input maxLength={128} placeholder="服务商的模型 ID" spellCheck={false} />
                    </Form.Item>
                    <Form.Item name="timeout_seconds" label="请求超时（秒）" rules={[{ required: true, type: 'integer', min: 5, max: 300, message: '请输入 5 至 300 的整数' }]}>
                      <InputNumber min={5} max={300} precision={0} />
                    </Form.Item>
                    <Form.Item name="api_key" label="API 密钥" className="model-config-full-field" dependencies={['enabled', 'provider_id', 'base_url']}
                      rules={[...(enabled && !selected?.has_key || requiresFreshKey ? [{ required: true, whitespace: true, message: requiresFreshKey ? '更换端点或提供商后请重新填写密钥' : '请填写此服务的 API 密钥' }] : []),
                        { pattern: /^[\x21-\x7E]*$/, message: '密钥不可包含空格或控制字符' }]}>
                      <Input.Password autoComplete="new-password" placeholder={requiresFreshKey ? '重新填写密钥，不转发旧凭据' : selected?.has_key ? '留空以保留当前密钥' : '输入 API 密钥'} maxLength={1024} visibilityToggle={false} />
                    </Form.Item>
                  </div>
                  <div className="model-config-options"><Form.Item name="enabled" valuePropName="checked"><Checkbox>启用服务</Checkbox></Form.Item>
                    {!selected?.is_default ? <Form.Item name="set_default" valuePropName="checked"><Checkbox disabled={!editable || workInFlight}>保存后设为默认</Checkbox></Form.Item> : <Tag color="blue">当前默认服务</Tag>}
                  </div>
                  {workInFlight ? <p className="model-config-status-note" role="status">有任务尚未终结；可编辑配置，任务结束后才能保存、切换或删除。</p> : null}
                  {selected && !selectedAdapterReady ? <Alert type="warning" showIcon message="此配置的 API 协议当前未适配，请选择 Chat Completions 后保存。" /> : null}
                  <div className="model-config-form-actions">
                    <Tooltip title={dirty ? '先保存改动，再测试已保存的配置' : selected ? '测试已保存的端点和模型' : '先保存新配置'}>
                      <span><LiquidGlassButton icon={<Unplug size={16} />} disabled={connectionDisabled} loading={operation === 'test'}
                        onClick={() => { setTestConsent(false); setConfirmTest(true) }}>测试连接</LiquidGlassButton></span>
                    </Tooltip>
                    <LiquidGlassButton type="primary" icon={<Save size={16} />} htmlType="submit" loading={operation === 'save'} disabled={!editable || !adapterReady || workInFlight}>保存配置</LiquidGlassButton>
                    <LiquidGlassButton icon={<Star size={16} />} disabled={!editable || dirty || !selected?.enabled || !selected.has_key || selected.is_default || workInFlight || !selectedAdapterReady}
                      loading={operation === 'default'} onClick={() => void setDefault()}>设为默认</LiquidGlassButton>
                    <Tooltip title={selected?.is_default ? '请先切换默认服务' : '删除此服务配置'}><span><LiquidGlassButton danger icon={<Trash2 size={16} />}
                      aria-label="删除服务配置" disabled={!editable || dirty || !selected || selected.is_default || workInFlight} loading={operation === 'delete'} onClick={remove} /></span></Tooltip>
                  </div>
                </Form>
                {testResult ? <section className="model-config-test-result" aria-label="连接测试结果">
                  <Tag color={testResult.status === 'PASS' ? 'green' : 'red'}>{testResult.status === 'PASS' ? '连接测试通过' : '连接测试未通过'}</Tag>
                  <Descriptions column={1} size="small" items={[
                    { key: 'requested', label: '请求模型', children: testResult.model_requested ?? '未返回请求型号' },
                    { key: 'returned', label: '返回模型', children: testResult.model_returned ?? '未返回型号' },
                    { key: 'duration', label: '调用耗时', children: testResult.duration_ms != null ? `${testResult.duration_ms} ms` : '未记录' },
                    ...(testResult.reason_code ? [{ key: 'reason', label: '结果代码', children: testResult.reason_code }] : []),
                  ]} />
                </section> : null}
                <p className="model-config-status-note">保存仅更新配置，不调用模型；连接测试不代表业务任务已验收。</p>
              </div>
            </div>
          </> },
        { key: 'deterministic', label: <span className="model-settings-tab"><Layers3 size={16} />{MODE_LABELS.deterministic}</span>,
          children: <>
            {error ? <Alert type="warning" showIcon message={error} /> : null}
            <div className="model-settings-state"><Tag color={ruleProfile?.available ? 'blue' : 'orange'}>{ruleProfile?.available ? '规则模式可用' : '配置尚未就绪'}</Tag><span>规则规划不调用大模型</span></div>
            <Descriptions column={1} size="small" items={[
              { key: 'identity', label: '角色身份', children: '协调、知识、工单、退款；各自签名身份' },
              { key: 'workflow', label: '运行存储', children: profiles?.workflow_enabled ? '已配置' : '未配置' },
              { key: 'control', label: '执行条件', children: '授权、网关验权、工具验签与预算检查仍执行' },
            ]} />
            <LiquidGlassButton icon={<RefreshCw size={16} />} loading={refreshing} onClick={onRefresh}>刷新运行配置</LiquidGlassButton>
          </> },
      ]} />
      <div className="model-settings-actions"><Tooltip title={dirty ? '先保存或切换以放弃改动' : '重新读取公开配置'}><span><LiquidGlassButton icon={<RefreshCw size={16} />} loading={loading}
        disabled={operation !== null || dirty && !reconcileRequired} onClick={() => void refresh()}>刷新配置</LiquidGlassButton></span></Tooltip><LiquidGlassButton disabled={operation !== null} onClick={close}>关闭</LiquidGlassButton></div>
    </Modal>
    <Modal open={confirmTest} title="确认连接测试" okText="确认并测试" cancelText="取消" onCancel={() => { setConfirmTest(false); setTestConsent(false) }}
      onOk={() => void testConnection()} okButtonProps={{ disabled: !testConsent || connectionDisabled }}>
      <p>向已保存的服务端点发送最小连接测试请求，可能产生费用。不发送工单、关联文档或业务记录，不启动任务。</p>
      <p className="model-config-test-target">{selected?.name} · {selected?.model}<br />{selected?.base_url}</p>
      <Checkbox checked={testConsent} onChange={(event) => setTestConsent(event.target.checked)}>允许本次模型调用及可能产生的费用</Checkbox>
    </Modal>
  </>
}
