import { useEffect, useState } from 'react'
import { App, Descriptions, Form, Input, InputNumber, Modal, Select, Tooltip } from 'antd'
import { FileText, Play, Plus, ShieldCheck } from 'lucide-react'
import { api, ApiError } from '../api'
import type { BusinessTicket } from '../api'
import type { BusinessCaseResult } from '../api'
import { customerLabel } from '../customerDisplay'
import { fenToYuan, yuanToFen } from '../money'
import { isBusinessIdentifier, isProtocolIdentifier } from '../businessIdentifiers'
import { businessTicketKey, ticketBusinessStatus, ticketCanRefund } from '../businessTickets'
import { reasonLabel, statusLabel } from '../labels'
import { taskAuthorizationLabel, workflowStatus } from '../workflowModel'
import { LiquidGlassButton } from '../components/LiquidGlassButton'
import { Fen, ShortHash } from '../components/Evidence'
import { BusinessCaseForm } from '../components/BusinessCaseForm'
import type { BusinessCaseSeed } from '../components/BusinessCaseForm'
import { BusinessFacts } from '../components/BusinessFacts'
import type { EvidenceSelection } from '../executionModel'
import type { DemoResult, TaskSummary } from '../types'

interface TaskFormValues {
  tenant_id: string; ticket_id: string; customer_id: string
  refund_total_yuan: string; max_tool_calls: number; expires_in_seconds: number
}

export function TaskCenter({ tasks, selectedTaskId, onSelect, onChanged, onDemo, onDemoStart, onDemoError, onInspect, onAuthorization, requesting = false, businessMode = false, currentTaskReady = true, pageTitle, compact = false }: {
  tasks: TaskSummary[]; selectedTaskId: string | null; onSelect: (taskId: string) => void
  onChanged: (taskId?: string) => Promise<void>; onDemo: (result: DemoResult) => Promise<void>
  onDemoStart?: (kind: string) => void; onDemoError?: () => void
  onInspect?: (selection: EvidenceSelection) => void
  onAuthorization?: () => void
  requesting?: boolean
  businessMode?: boolean
  currentTaskReady?: boolean
  pageTitle?: string
  compact?: boolean
}) {
  const [form] = Form.useForm<TaskFormValues>()
  const [busy, setBusy] = useState<string | null>(null)
  const [newTaskOpen, setNewTaskOpen] = useState(false)
  const [businessCaseOpen, setBusinessCaseOpen] = useState(false)
  const [businessCaseSeed, setBusinessCaseSeed] = useState<BusinessCaseSeed | null>(null)
  const [tickets, setTickets] = useState<BusinessTicket[]>([])
  const [ticketsLoading, setTicketsLoading] = useState(false)
  const tenant = Form.useWatch('tenant_id', form)
  const ticketId = Form.useWatch('ticket_id', form)
  const customer = Form.useWatch('customer_id', form)
  const businessTicket = tickets.find((ticket) => ticket.tenant_id === tenant && ticket.ticket_id === ticketId && ticket.customer_id === customer)
  const { modal, message: messageApi } = App.useApp()
  const selected = tasks.find((task) => task.task_id === selectedTaskId) ?? null
  const reportError = (error: unknown) => messageApi.error(error instanceof ApiError ? `${reasonLabel(error.reasonCode)}：${error.message}` : '请求失败')

  const newBusinessCase = (copy = false) => {
    setBusinessCaseSeed({ tenant_id: tenant || 'tenant-A', customer_id: copy ? customer || 'customer-A' : 'customer-A',
      ...(copy && businessTicket?.business_facts ? { business_facts: businessTicket.business_facts } : {}) })
    setBusinessCaseOpen(true)
  }
  const businessCaseCreated = (result: BusinessCaseResult) => {
    const newTicket: BusinessTicket = { ...result, title: '重复扣款退款申请', status: 'OPEN', source: 'facts', business_verification: null }
    setTickets((current) => [newTicket, ...current.filter((ticket) => businessTicketKey(ticket) !== businessTicketKey(newTicket))])
    form.setFieldsValue({ tenant_id: result.tenant_id, customer_id: result.customer_id, ticket_id: result.ticket_id })
    setBusinessCaseOpen(false)
  }

  useEffect(() => {
    if (!newTaskOpen) return
    let active = true
    setTicketsLoading(true)
    void api.businessTickets().then((result) => {
      if (!active) return
      setTickets(result.items)
      const candidate = result.items.find((ticket) => ticketCanRefund(ticket) && Number(ticket.transaction_remaining_fen) >= 7000
        && Number.isSafeInteger(ticket.refundable_amount_fen) && Number(ticket.refundable_amount_fen) >= 7000)
      if (candidate && !form.isFieldsTouched(['tenant_id', 'ticket_id', 'customer_id']) && !form.getFieldValue('ticket_id')) {
        form.setFieldsValue({ tenant_id: candidate.tenant_id, ticket_id: candidate.ticket_id, customer_id: candidate.customer_id })
      }
    }).catch(() => {
      if (active) messageApi.error('已有工单读取失败，请稍后重新打开；仍可填写已知业务记录')
    }).finally(() => { if (active) setTicketsLoading(false) })
    return () => { active = false }
  }, [form, newTaskOpen, messageApi])

  const create = async (values: TaskFormValues) => {
    setBusy('create')
    try {
      const { refund_total_yuan, ...identity } = values
      const result = await api.createTask({ ...identity, refund_total_fen: yuanToFen(refund_total_yuan) })
      // The task is already committed once createTask resolves. Close the form
      // and select it before refreshing so a transient read failure cannot make
      // the operator submit the same business task a second time.
      onSelect(result.task_id)
      setNewTaskOpen(false)
      messageApi.success('待授权任务已创建')
      try {
        await onChanged(result.task_id)
      } catch {
        messageApi.warning(`任务 ${result.task_id} 已创建，但任务列表刷新失败；请刷新任务列表查看，暂不要重复创建`)
      }
    } catch (error) {
      if (error instanceof ApiError) {
        const names: (keyof TaskFormValues)[] = ['tenant_id', 'ticket_id', 'customer_id', 'refund_total_yuan', 'max_tool_calls', 'expires_in_seconds']
        form.setFields(names.flatMap((name) => error.fieldErrors[name === 'refund_total_yuan' ? 'refund_total_fen' : name] ? [{ name, errors: [error.fieldErrors[name === 'refund_total_yuan' ? 'refund_total_fen' : name]] }] : []))
        messageApi.error(error.message)
      } else reportError(error)
    } finally { setBusy(null) }
  }
  const authorize = () => {
    if (!selected || !currentTaskReady || requesting || busy !== null) return
    modal.confirm({
      title: '确认签发根授权',
      content: `${selected.ticket_id} / ${customerLabel(selected.customer_id)} / 退款上限 ${fenToYuan(selected.refund_total_fen)} 元`,
      okText: '确认签发根授权', cancelText: '取消', icon: <ShieldCheck size={20} />,
      onOk: async () => {
        setBusy('authorize')
        try {
          await api.authorizeTask(selected.task_id, {
            confirmed: true, confirmer_id: 'policy-refund-v1', holder_agent_id: 'agent-coordinator',
            holder_key_id: 'agent-coordinator-key-01', delegation_depth: 2,
          })
          messageApi.success('根授权已签发')
          await onChanged(selected.task_id)
        } catch (error) { reportError(error); throw error } finally { setBusy(null) }
      },
    })
  }
  const run = async () => {
    if (!selected || !currentTaskReady || requesting || busy !== null) return
    setBusy('run'); onDemoStart?.('NORMAL')
    try {
      const result = await api.runTask(selected.task_id)
      await onDemo(result)
      if (result.status === 'COMPLETED') messageApi.success('受控执行已完成')
      else if (result.status === 'QUEUED') messageApi.success('任务已启动，请查看协作流程')
      else messageApi.warning(`受控执行：${workflowStatus(result.status, result.reason_code).label ?? statusLabel(result.status)}；请查看执行记录`)
    } catch (error) { onDemoError?.(); reportError(error) } finally { setBusy(null) }
  }
  const normalDemo = async () => {
    setBusy('demo'); onDemoStart?.('NORMAL')
    try {
      const result = await api.normalDemo()
      await onDemo(result)
      if (result.status === 'COMPLETED') messageApi.success('四智能体协作已完成')
      else if (result.status === 'QUEUED') messageApi.success('任务已启动，请查看协作流程')
      else messageApi.warning(`任务协作：${workflowStatus(result.status, result.reason_code).label ?? statusLabel(result.status)}；请查看执行记录`)
    } catch (error) { onDemoError?.(); reportError(error) } finally { setBusy(null) }
  }

  return <>
    <section className={`workspace-toolbar${compact ? ' studio-task-toolbar' : ''}`} data-testid="task-center">
    <div className="workspace-heading">{compact ? <span className="page-eyebrow">企业任务 / 售后业务</span> : <><span className="page-eyebrow">企业任务控制台</span><h1>{pageTitle ?? (businessMode ? '多智能体授权与受控执行' : '任务授权与执行')}</h1></>}</div>
    <div className="workspace-actions">
      <Select className="task-switcher record-select" value={selectedTaskId ?? undefined} onChange={onSelect}
        aria-label="切换当前任务" showSearch optionFilterProp="label" placeholder={businessMode ? '选择已保存的任务' : '选择任务'} classNames={{ popup: { root: 'record-select-dropdown' } }} virtual={false} disabled={busy !== null || requesting}
        options={tasks.map((task) => ({
          value: task.task_id,
          label: `${task.ticket_id} / ${customerLabel(task.customer_id)} · ${task.workflow_state ? workflowStatus(task.workflow_state, task.workflow_reason_code).label ?? statusLabel(task.workflow_state) : taskAuthorizationLabel(task.status) ?? statusLabel(task.status)} · ${task.task_id.slice(-7)}`,
        }))} />
      <Tooltip title="新建待授权业务任务"><LiquidGlassButton className="task-create-button" icon={<Plus size={16} />} onClick={() => setNewTaskOpen(true)} aria-label="新建任务" disabled={busy !== null || requesting} /></Tooltip>
      {businessMode && selected?.status === 'PENDING_AUTHORIZATION' ? <LiquidGlassButton className="task-authorization-button" icon={<ShieldCheck size={16} />}
        onClick={onAuthorization} disabled={!onAuthorization || !currentTaskReady || busy !== null || requesting}>打开当前任务授权</LiquidGlassButton> : null}
      {selected && onInspect ? <Tooltip title="查看当前任务约束"><LiquidGlassButton className="task-inspect-button" icon={<FileText size={16} />}
        onClick={() => onInspect({ kind: 'task' })} disabled={!currentTaskReady} aria-label="查看当前任务约束" /></Tooltip> : null}
      {!businessMode && selected?.status === 'PENDING_AUTHORIZATION' ? <LiquidGlassButton className="task-authorization-button" icon={<ShieldCheck size={16} />} onClick={authorize} loading={busy === 'authorize'} disabled={!currentTaskReady || busy !== null || requesting}>确认当前任务授权</LiquidGlassButton> : null}
      {!businessMode && selected?.status === 'AUTHORIZED' && !selected.execution_count ? <LiquidGlassButton type="primary" icon={<Play size={16} />} onClick={run} loading={busy === 'run'} disabled={!currentTaskReady || busy !== null || requesting}>运行当前任务</LiquidGlassButton> : null}
      {!businessMode ? <LiquidGlassButton type="primary" icon={<Play size={15} />} onClick={normalDemo} loading={busy === 'demo'} disabled={busy !== null || requesting}>另建标准任务并运行</LiquidGlassButton> : null}
    </div>
    <Modal open={newTaskOpen} title="基于已有工单创建待授权任务" width={608} onCancel={() => setNewTaskOpen(false)} footer={null} destroyOnHidden>
      <div className="modal-actions" style={{ justifyContent: 'flex-start', marginBottom: 12 }}>
        <LiquidGlassButton icon={<Plus size={14} />} onClick={() => newBusinessCase()} disabled={ticketsLoading || busy !== null}>新建业务工单</LiquidGlassButton>
        {businessTicket?.business_facts ? <LiquidGlassButton onClick={() => newBusinessCase(true)} disabled={ticketsLoading || busy !== null}>复制为新案例</LiquidGlassButton> : null}
      </div>
      <Form<TaskFormValues> form={form} layout="vertical" preserve={false} initialValues={{ tenant_id: '', ticket_id: '', customer_id: '', refund_total_yuan: '70.00', max_tool_calls: 4, expires_in_seconds: 1800 }} onFinish={create}>
        <Form.Item label="已有业务工单">
          <Select className="record-select" aria-label="选择已有业务工单" placeholder="选择已有业务工单" showSearch loading={ticketsLoading} optionFilterProp="label" allowClear classNames={{ popup: { root: 'record-select-dropdown' } }} virtual={false}
            value={businessTicket ? businessTicketKey(businessTicket) : undefined}
            options={tickets.map((ticket) => ({ value: businessTicketKey(ticket), label: `${ticket.ticket_id} · ${ticket.tenant_id} · ${customerLabel(ticket.customer_id)} · ${ticketBusinessStatus(ticket)}` }))}
            onChange={(key: string | undefined) => {
              const ticket = tickets.find((item) => businessTicketKey(item) === key)
              if (ticket) form.setFieldsValue({ ticket_id: ticket.ticket_id, tenant_id: ticket.tenant_id, customer_id: ticket.customer_id })
              else form.setFieldsValue({ ticket_id: '', tenant_id: '', customer_id: '' })
            }} />
        </Form.Item>
        {businessTicket?.business_facts ? <section aria-label="当前工单业务资格">
          <p>办理状态：{ticketBusinessStatus(businessTicket)}</p>
          <BusinessFacts facts={businessTicket.business_facts} compact />
          {businessTicket.business_verification?.reason ? <p>核验说明：{businessTicket.business_verification.reason}</p> : null}
        </section> : businessTicket ? <section aria-label="当前工单业务资格"><Descriptions column={1} size="small" items={[
          { key: 'source', label: '资格来源', children: '已保存的业务核验记录' },
          { key: 'status', label: '办理状态', children: ticketBusinessStatus(businessTicket) },
          { key: 'transaction', label: '原交易', children: <ShortHash value={businessTicket.original_transaction_id} copyable={false} /> },
          { key: 'remaining', label: '交易剩余额', children: typeof businessTicket.transaction_remaining_fen === 'number' && Number.isSafeInteger(businessTicket.transaction_remaining_fen) && businessTicket.transaction_remaining_fen >= 0 ? <Fen value={businessTicket.transaction_remaining_fen} /> : '未提供' },
          { key: 'reference', label: '核验依据（原始材料标识）', children: businessTicket.evidence_reference ?? '未提供' },
        ]} /></section> : null}
        <div className="form-grid">
          <Form.Item label="租户" name="tenant_id" rules={[{ required: true, message: '请输入租户' }, { validator: (_, value) => isBusinessIdentifier(value) ? Promise.resolve() : Promise.reject(new Error('请输入 1 至 128 字中文、字母或数字，不可含空白')) }]}><Input maxLength={128} /></Form.Item>
          <Form.Item label="工单编号" name="ticket_id" rules={[{ required: true, message: '请输入工单编号' }, { validator: (_, value) => isProtocolIdentifier(value) ? Promise.resolve() : Promise.reject(new Error('工单编号只能包含字母、数字和 . _ : -')) }]}><Input maxLength={128} /></Form.Item>
          <Form.Item label="客户" name="customer_id" getValueProps={(id: string | undefined) => ({ value: customerLabel(id ?? ''), title: id })} getValueFromEvent={(event) => tickets.find((ticket) => customerLabel(ticket.customer_id) === event.target.value)?.customer_id ?? event.target.value} rules={[{ required: true, message: '请输入客户' }, { validator: (_, value) => isBusinessIdentifier(value) ? Promise.resolve() : Promise.reject(new Error('请输入 1 至 128 字中文、字母或数字，不可含空白')) }]}><Input maxLength={128} /></Form.Item>
          <Form.Item label="退款预算（元）" name="refund_total_yuan" rules={[{ required: true, message: '请输入退款预算' }, { validator: (_, value) => { try { yuanToFen(value); return Promise.resolve() } catch (error) { return Promise.reject(error) } } }]}><InputNumber stringMode min="0" step="0.01" className="full-width" /></Form.Item>
          <Form.Item label="工具调用预算（次）" name="max_tool_calls" rules={[{ required: true, message: '请输入调用预算' }]}><InputNumber min={1} max={32} precision={0} className="full-width" /></Form.Item>
          <Form.Item label="有效期（秒）" name="expires_in_seconds" rules={[{ required: true, message: '请输入有效期' }]}><InputNumber min={60} max={86400} precision={0} className="full-width" /></Form.Item>
        </div>
        <div className="modal-actions"><LiquidGlassButton onClick={() => setNewTaskOpen(false)}>取消</LiquidGlassButton><LiquidGlassButton type="primary" htmlType="submit" icon={<Plus size={16} />} loading={busy === 'create'}>创建待授权任务</LiquidGlassButton></div>
      </Form>
    </Modal>
    <BusinessCaseForm open={businessCaseOpen} seed={businessCaseSeed} onCancel={() => setBusinessCaseOpen(false)} onCreated={businessCaseCreated} />
    </section>
  </>
}
