import { CustomerName } from './CustomerName'
import { useRef, useState } from 'react'
import { Alert, Checkbox, Descriptions, Modal } from 'antd'
import { RefreshCw, ShieldCheck } from 'lucide-react'
import { api, ApiError } from '../api'
import type { CoauthorizationStatus, TaskSummary } from '../types'
import { Fen, TimeValue } from './Evidence'
import { LiquidGlassButton } from './LiquidGlassButton'

export function RootAuthorizationButton({ task, onChanged }: {
  task: Omit<TaskSummary, 'credential_count' | 'execution_count'> | null
  onChanged?: (taskId: string) => Promise<void>
}) {
  const [open, setOpen] = useState(false)
  const [reading, setReading] = useState(false)
  const [busy, setBusy] = useState(false)
  const [confirmed, setConfirmed] = useState(false)
  const [policy, setPolicy] = useState<CoauthorizationStatus | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [unconfirmed, setUnconfirmed] = useState(false)
  const version = useRef(0)
  const inFlight = useRef(false)
  const current = useRef(task)
  current.current = task

  const readPolicy = async () => {
    const id = ++version.current
    setReading(true); setPolicy(null); setError(null); setConfirmed(false)
    try {
      const value = await api.coauthorizationStatus()
      if (id !== version.current) return
      if (value.schema_version !== '1.0' || typeof value.enabled !== 'boolean'
        || value.policy_source !== 'SERVER_REGISTERED_PUBLIC_KEYS' || value.signing !== 'EXTERNAL_APPROVERS_ONLY') {
        throw new Error('Invalid authorization policy')
      }
      setPolicy(value)
    } catch {
      if (id === version.current) setError('授权策略读取失败，不能签发；请刷新重试。')
    } finally { if (id === version.current) setReading(false) }
  }

  const close = () => {
    if (inFlight.current) return
    version.current += 1
    setOpen(false); setConfirmed(false); setPolicy(null); setReading(false)
  }
  const pending = task?.status === 'PENDING_AUTHORIZATION'
  const ready = pending && policy?.enabled === false && !reading && !busy && !unconfirmed
    && (task?.expires_at ?? 0) > Date.now() / 1000 && Boolean(onChanged)
  const authorize = async () => {
    const target = current.current
    if (!ready || !confirmed || !target || target.task_id !== task?.task_id
      || target.status !== 'PENDING_AUTHORIZATION' || target.expires_at <= Date.now() / 1000 || inFlight.current) return
    inFlight.current = true
    setBusy(true); setError(null)
    let signed = false
    try {
      await api.authorizeTask(target.task_id, {
        confirmed: true, confirmer_id: 'policy-refund-v1', holder_agent_id: 'agent-coordinator',
        holder_key_id: 'agent-coordinator-key-01', delegation_depth: 2,
      })
      signed = true
      await onChanged?.(target.task_id)
      setOpen(false); setConfirmed(false)
    } catch (failure) {
      const knownRejection = failure instanceof ApiError && [400, 403, 404, 409, 422].includes(failure.status)
      setUnconfirmed(signed || !knownRejection)
      setConfirmed(false)
      setError(signed ? '已收到签发结果，页面刷新未确认；请刷新任务核对，不要重复签发。'
        : knownRejection ? `授权未签发（${failure.reasonCode}），请刷新任务核对。`
          : '签发结果未确认；请刷新任务核对，不自动重试。')
    } finally { inFlight.current = false; setBusy(false) }
  }

  return <>
    <LiquidGlassButton icon={<ShieldCheck size={15} />} disabled={!pending || !onChanged || busy}
      onClick={() => { setOpen(true); setUnconfirmed(false); void readPolicy() }}>查看并授权当前任务</LiquidGlassButton>
    <Modal open={open} title="确认任务授权" onCancel={close} closable={!busy} maskClosable={!busy}
      footer={<><LiquidGlassButton disabled={busy} onClick={close}>取消</LiquidGlassButton>
        <LiquidGlassButton type="primary" icon={<ShieldCheck size={15} />} disabled={!ready || !confirmed}
          loading={busy} onClick={() => void authorize()}>确认签发根授权</LiquidGlassButton></>}>
      <Descriptions size="small" column={1} items={[
        { key: 'task', label: '任务', children: task?.task_id },
        { key: 'tenant', label: '租户', children: task?.tenant_id },
        { key: 'ticket', label: '工单', children: task?.ticket_id },
        { key: 'customer', label: '客户', children: task ? <CustomerName id={task.customer_id} /> : '未读取' },
        { key: 'amount', label: '累计退款上限', children: task ? <Fen value={task.refund_total_fen} /> : '未读取' },
        { key: 'calls', label: '累计工具调用上限', children: task?.max_tool_calls },
        { key: 'expiry', label: '任务有效期至', children: <TimeValue value={task?.expires_at} /> },
        { key: 'holder', label: '根持有者', children: '协调智能体 / agent-coordinator-key-01' },
        { key: 'depth', label: '最多子委托层级', children: '2 级，仅能收窄' },
      ]} />
      {reading ? <p role="status">正在核对服务端授权策略</p> : null}
      {policy?.enabled ? <Alert type="warning" showIcon message="本任务要求企业与财务共同授权"
        description="不能通过基础授权签发；请关闭此窗口后进入共同审批，提交同一任务的双签包。" /> : null}
      {error ? <Alert type="error" showIcon message={error} /> : null}
      {!reading && !busy && !unconfirmed ? <LiquidGlassButton icon={<RefreshCw size={15} />}
        onClick={() => void readPolicy()}>刷新授权策略</LiquidGlassButton> : null}
      <p>授权限定当前工单、客户与额度，不等于业务核验通过；此操作仅签发根凭证，不执行退款。</p>
      <Checkbox disabled={!ready} checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)}>
        我确认本次工单、客户和授权额度
      </Checkbox>
    </Modal>
  </>
}
