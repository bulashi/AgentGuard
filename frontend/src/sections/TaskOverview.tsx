import { CustomerName } from '../components/CustomerName'
import { useEffect, useState, type ReactNode } from 'react'
import { Empty } from 'antd'
import { ArrowRight, ArrowUpRight, BookOpen, FileText, GitBranch, KeyRound, Layers3, MessageSquare, Pause, Play, ReceiptText, Settings2, ShieldCheck, WalletCards } from 'lucide-react'
import { Fen, ShortHash, StatusTag } from '../components/Evidence'
import { LiquidGlassButton } from '../components/LiquidGlassButton'
import { NotificationPreview } from '../components/NotificationPreview'
import { WorkflowStatusTag } from '../components/WorkflowStatusTag'
import { RefundVerificationFacts } from '../components/RefundVerificationFacts'
import type { EvidenceSelection, StageKey } from '../executionModel'
import type { TaskSnapshot, WorkflowEvent } from '../types'
import { activeWorkflow, AGENT_IDS, agentNodeState, businessOutcome, eventTitle, gatewayNodeState, MODE_LABELS, NODE_STATE_LABELS, taskAuthorizationLabel, workflowBusinessResults, workflowIsRunning } from '../workflowModel'
import type { NodeState } from '../workflowModel'
import { observeCredential } from '../credentialObservation'
import { agentLabel, toolLabel } from '../labels'
import { observeReceipt } from '../sourceVerification'

function replayStage(event: WorkflowEvent): StageKey {
  if (event.action === 'delegate') return 'authorization'
  if (event.action.startsWith('gateway')) return 'gateway'
  if (event.action === 'call_tool' || event.action.endsWith('_result')) return 'tools'
  if (event.action.includes('receipt')) return 'evidence'
  return 'agents'
}

export function TaskOverview({ snapshot, observedAt, onInspect, onFlow, onRecords, onAuthorization, onConfigure, controlsOpen, controls }: {
  snapshot: TaskSnapshot | null; observedAt: number
  onInspect: (selection: EvidenceSelection) => void; onFlow: () => void; onRecords: () => void
  onAuthorization?: () => void; onConfigure: () => void; controlsOpen: boolean
  controls?: ReactNode
}) {
  const run = activeWorkflow(snapshot)
  const [cursor, setCursor] = useState<number | null>(null)
  const [playing, setPlaying] = useState(false)
  const events = run?.events ?? []
  const total = events.length
  const identity = `${snapshot?.task.task_id ?? ''}:${run?.run_id ?? ''}`
  useEffect(() => { setCursor(null); setPlaying(false) }, [identity])
  useEffect(() => {
    if (!playing || cursor === null || cursor >= total) return undefined
    const timer = window.setTimeout(() => setCursor((value) => Math.min((value ?? 0) + 1, total)), 650)
    return () => window.clearTimeout(timer)
  }, [cursor, playing, total])

  if (!snapshot) return <Empty description="尚未选择业务任务" />
  const root = snapshot.credentials.find((item) => item.credential_type === 'ROOT')
  const rootObservation = observeCredential(root, snapshot.credentials, observedAt)
  const outcomeEvidence = businessOutcome(snapshot)
  const allowed = snapshot.executions.filter((item) => item.decision === 'ALLOW').length
  const denied = snapshot.executions.filter((item) => item.decision === 'DENY').length
  const undecided = snapshot.executions.length - allowed - denied
  // Business rows remain task totals; replay only highlights unsigned process observations.
  const refunds = snapshot.business_effects.refunds.filter((item) => item.status === 'COMMITTED')
  const notices = snapshot.business_effects.notifications.filter((item) => item.status === 'SENT')
  const business = workflowBusinessResults({ ...snapshot, business_effects: { refunds, notifications: notices } })
  const inconsistent = refunds.length > 0 && business.refund.state !== 'completed'
    || notices.length > 0 && business.notification.state !== 'completed'
  const refundCount = business.refund.state === 'completed' ? business.refund.count : 0
  const noticeCount = business.notification.state === 'completed' ? business.notification.count : 0
  const refundFen = business.refund.amountFen ?? 0
  const running = workflowIsRunning(run)
  const historicalAuthorization = Boolean(run && !running && rootObservation.code === 'EXPIRED')
  const authorizationLabel = historicalAuthorization ? '历史授权 · 当前已到期（根授权）' : rootObservation.code === 'WINDOW_OPEN' ? '根授权已签发 · 当前有效' : rootObservation.label
  const hasEffects = refundCount > 0 || noticeCount > 0
  const unconfirmed = business.refund.state === 'unknown' || business.notification.state === 'unknown'
    || snapshot.executions.some((execution) => ['UNKNOWN', 'RECONCILING', 'RECOVERY_FAILED_FINAL'].includes(execution.state))
  const incomplete = run?.state === 'FAILED' || run?.state === 'INTERRUPTED'
  const stopped = run?.state === 'DENIED'
  const outcome = ['BUSINESS_STOPPED', 'NO_EFFECT', 'INCONSISTENT'].includes(outcomeEvidence.status) ? outcomeEvidence.label : inconsistent ? '业务记录关联异常，待核对' : unconfirmed ? hasEffects ? '已有业务提交，仍有结果待确认' : '业务结果未确认，请勿重复办理' : running ? '协作处理中'
    : incomplete ? hasEffects ? '本次运行未完成，已有业务提交' : '本次运行未完成'
      : stopped ? hasEffects ? '本次运行已停止，已有业务提交' : '任务已停止，未执行退款'
      : hasEffects ? denied ? '业务已提交，另有拒绝记录' : '业务结果已提交'
        : denied ? '请求已被拒绝' : '等待受控执行'
  const replayEvent = cursor !== null && cursor > 0 ? events[Math.min(cursor, total) - 1] : null
  const highlighted = replayEvent ? replayStage(replayEvent) : null
  const verifiedReceipts = snapshot.receipts.filter((receipt) => observeReceipt(receipt).status === 'VALID')
  const agentStates = AGENT_IDS.map((id) => agentNodeState(id, events, snapshot, run?.state === 'INTERRUPTED'))
  const agentState: NodeState = agentStates.includes('unknown') ? 'unknown' : agentStates.includes('failed') ? 'failed'
    : agentStates.includes('stopped') ? 'stopped' : agentStates.includes('denied') ? 'denied'
      : agentStates.every((state) => state === 'completed') ? 'completed' : running ? 'active' : 'waiting'
  const businessState: NodeState = ['BUSINESS_STOPPED', 'INCONSISTENT'].includes(outcomeEvidence.status) ? 'stopped' : inconsistent ? 'failed' : unconfirmed ? 'unknown'
    : business.refund.state === 'completed' && business.notification.state === 'completed' ? 'completed'
      : running ? 'active' : business.refund.state === 'denied' || business.notification.state === 'denied' ? 'denied' : stopped ? 'stopped' : 'waiting'
  const steps = [
    { key: 'authorization', title: '企业授权', description: authorizationLabel, state: rootObservation.windowOpen ? 'authorized' : 'waiting', icon: KeyRound, inspect: () => { if (onAuthorization) onAuthorization(); else onInspect({ kind: 'stage', stage: 'authorization' }) } },
    { key: 'agents', title: '智能体协作', description: agentState === 'stopped' ? '已停止后续办理' : `${events.filter((event) => event.action === 'plan').length} 次规划记录`, state: agentState, icon: GitBranch, inspect: onFlow },
    { key: 'gateway', title: '安全网关', description: `${allowed} 允许 / ${denied} 拒绝`, state: gatewayNodeState(events, snapshot, false), icon: ShieldCheck, inspect: () => onInspect({ kind: 'stage', stage: 'gateway' }) },
    { key: 'tools', title: '业务工具', description: outcomeEvidence.status === 'BUSINESS_STOPPED' ? '业务核验未通过 · 未执行' : outcomeEvidence.status === 'INCONSISTENT' || inconsistent ? '业务记录待核对' : unconfirmed ? '业务结果未确认' : `${refundCount} 笔退款 / ${noticeCount} 条通知`, state: businessState, icon: WalletCards, inspect: () => onInspect({ kind: 'business', resource: 'result' }) },
  ]
  const executions = [...snapshot.executions].sort((a, b) => a.created_at - b.created_at || a.execution_id.localeCompare(b.execution_id))
  const toolIcons = { 'knowledge.read_associated': BookOpen, 'ticket.read': FileText, 'refund.create': WalletCards, 'notification.send_template': MessageSquare }
  const end = cursor !== null && cursor >= total
  const replayActive = playing && !end
  return <section className="task-overview studio-workspace" data-testid="task-overview">
    <div className="studio-task-heading">
      <div className="studio-task-subject"><div className="studio-task-eyebrow">工单 {snapshot.task.ticket_id}{run?.scenario === 'policy_injection' ? <><span />关联文档指令注入</> : null}</div>
        <h1>{snapshot.business_context?.ticket?.title ?? `工单 ${snapshot.task.ticket_id}`}</h1>
        <p>工单 {snapshot.task.ticket_id} · 客户 <CustomerName id={snapshot.task.customer_id} /></p>
        <div className="studio-task-meta">{run ? <WorkflowStatusTag state={run.state} reasonCode={run.reason_code} /> : <StatusTag value={snapshot.task.status} label={taskAuthorizationLabel(snapshot.task.status)} />}{run ? <span>{MODE_LABELS[run.runtime_mode]}</span> : null}<ShortHash value={snapshot.task.task_id} size={10} /></div>
      </div>
      <div className="studio-subject-actions"><LiquidGlassButton icon={<Settings2 size={16} />} onClick={onConfigure} aria-expanded={controlsOpen}>运行与配置</LiquidGlassButton>
        <div><button type="button" onClick={() => onInspect({ kind: 'business', resource: 'ticket' })}>工单详情<ArrowUpRight size={14} /></button><button type="button" onClick={() => onInspect({ kind: 'business', resource: 'knowledge' })}>关联知识<ArrowUpRight size={14} /></button></div>
      </div>
    </div>
    <div className="studio-authorization-strip"><div><KeyRound size={16} /><span>授权客户</span><strong><CustomerName id={snapshot.task.customer_id} /></strong></div><div><WalletCards size={16} /><span>任务授权上限</span><strong><Fen value={snapshot.task.refund_total_fen} /></strong></div><div><Layers3 size={16} /><span>调用上限</span><strong>{snapshot.task.max_tool_calls} 次</strong></div>
      <span className="studio-authorization-status">{authorizationLabel}</span>
    </div>
    {controls ? <div hidden={!controlsOpen} className="studio-inline-controls">{controls}</div> : null}
    <RefundVerificationFacts value={snapshot.business_context?.ticket?.refund_verifications} ticket={snapshot.business_context?.ticket} compact />
    <div className="studio-workspace-grid"><div className="studio-primary">
      <div className="studio-section-heading"><h2>授权范围 → 角色处理 → 网关核验 → 实际结果</h2><span>任务记录</span></div>
      <div className="studio-process-path">{steps.map((step, index) => { const Icon = step.icon; return <button type="button" key={step.key} data-state={step.state} className={`studio-process-stage process-${step.state}${highlighted === step.key ? ' replay-active' : ''}`} onClick={step.inspect}>
        <span className="studio-stage-index">{index + 1}</span><span className="studio-stage-icon"><Icon size={22} /></span><strong>{step.title}</strong><span className="studio-stage-state">{step.description}</span>
      </button> })}</div>
      <div className="studio-agent-roster">{AGENT_IDS.map((id, index) => <button type="button" key={id} onClick={() => onInspect({ kind: 'agent', agentId: id })}><GitBranch size={13} />{agentLabel(id)}<span>{NODE_STATE_LABELS[agentStates[index]]}</span></button>)}</div>
      {total ? <div className="studio-replay" data-testid="overview-replay">
        <LiquidGlassButton icon={replayActive ? <Pause size={15} /> : <Play size={15} />} onClick={() => {
          if (cursor === null || end) { setCursor(0); setPlaying(true) } else setPlaying((value) => !value)
        }}>{replayActive ? '暂停回放' : '回放过程'}</LiquidGlassButton>
        <input type="range" aria-label="首页回放进度" min={0} max={total} value={cursor ?? total} onChange={(event) => { setPlaying(false); setCursor(Number(event.target.value)) }} />
        <span className="studio-replay-count">{cursor ?? total} / {total}</span>
        <span className="studio-replay-caption">{cursor === null ? '最新运行 · 已保存的完整过程' : replayEvent ? eventTitle(replayEvent) : '最新运行 · 回放开始'}</span>
        {replayEvent && run ? <button type="button" className="studio-replay-detail" onClick={() => onInspect({ kind: 'workflow', runId: run.run_id, sequence: replayEvent.sequence })}>查看事件<ArrowUpRight size={13} /></button> : null}
      </div> : null}
      <section className="studio-tool-section"><div className="studio-section-heading"><h2>工具执行记录</h2><button type="button" onClick={onRecords}>执行记录<ArrowRight size={15} /></button></div>
        {executions.length ? <div className="studio-tool-list">{executions.slice(-8).map((execution) => { const Icon = toolIcons[execution.tool_name as keyof typeof toolIcons] ?? FileText; return <button type="button" className="studio-tool-row" key={execution.execution_id} onClick={() => onInspect({ kind: 'execution', execution })}>
          <span className="studio-tool-icon"><Icon size={18} /></span><span className="studio-tool-copy"><strong>{toolLabel(execution.tool_name)}</strong><small>{execution.tool_service} · {execution.tool_version}</small></span><StatusTag value={execution.decision ?? 'PENDING'} /><StatusTag value={execution.state} /><ArrowRight size={15} />
        </button> })}</div> : <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="尚无工具执行记录" />}
        <span className="studio-tool-caption">{snapshot.executions.length} 笔任务累计请求{undecided ? ` · ${undecided} 笔待裁决` : ''}{executions.length > 8 ? ' · 展示最近 8 笔' : ''}</span>
      </section>
    </div><aside className="studio-result-rail" aria-label="任务累计结果">
      <section className="studio-business-result"><span className="studio-result-label">业务结果 · 任务累计</span><h2>{outcome}</h2><p className="studio-result-detail" data-testid="business-outcome-detail">{outcomeEvidence.detail}</p><strong className="studio-result-amount">{inconsistent ? '待核对' : unconfirmed ? '结果待确认' : <Fen value={refundFen} />}</strong><p>{inconsistent ? '执行与业务记录的绑定未满足核对条件' : unconfirmed ? <>已核对退款 <Fen value={refundFen} /> · 仍有请求需要对账</> : <>退款 <Fen value={refundFen} /> · 通知 {noticeCount} 条</>}</p>
        <dl><div><dt>客户</dt><dd><CustomerName id={snapshot.task.customer_id} /></dd></div><div><dt>工单</dt><dd>{snapshot.task.ticket_id}</dd></div></dl>
        <button type="button" onClick={() => onInspect({ kind: 'business', resource: 'result' })}>查看业务效果<ArrowUpRight size={14} /></button>
      </section>
      <section className="studio-result-proof"><h3>执行证据</h3><div><ReceiptText size={15} /><span>回执来源核对</span><strong>{verifiedReceipts.length} / {snapshot.receipts.length}</strong></div><div><Layers3 size={15} /><span>审计记录</span><strong>{snapshot.audit_events.length} 条</strong></div>
        <LiquidGlassButton icon={<ReceiptText size={15} />} aria-label="回执留证" onClick={() => onInspect({ kind: 'stage', stage: 'evidence' })}>查看签名回执<ArrowRight size={14} /></LiquidGlassButton>
      </section>
      <section className="studio-result-policy"><h3>网关裁决</h3><strong>{allowed} 允许 / {denied} 拒绝</strong><span>{snapshot.receipts.length} 份回执 · {snapshot.audit_events.length} 条审计事件</span><button type="button" onClick={onFlow}>查看协作流程<ArrowRight size={14} /></button></section>
    </aside></div>
    <section className="studio-notifications" aria-label="客户通知" data-testid="overview-notifications">
      <div className="studio-section-heading"><h2>客户通知</h2>
        <LiquidGlassButton icon={<MessageSquare size={17} />} onClick={() => onInspect({ kind: 'business', resource: 'notifications' })}>查看通知记录</LiquidGlassButton>
      </div>
      <p className="studio-notification-context">工单 {snapshot.task.ticket_id} · 客户 <CustomerName id={snapshot.task.customer_id} /></p>
      <NotificationPreview snapshot={snapshot} includeTemplatePreview={snapshot.business_effects.notifications.length === 0} />
    </section>
  </section>
}
