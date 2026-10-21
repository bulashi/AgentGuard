import type { CredentialView, ExecutionView, TaskSnapshot, WorkflowEvent, WorkflowRun } from './types'
import { agentLabel, reasonLabel, toolLabel } from './labels'

export const AGENT_IDS = ['agent-coordinator', 'agent-knowledge', 'agent-case', 'agent-refund'] as const
export const TOOL_NAMES = ['knowledge.read_associated', 'ticket.read', 'refund.create', 'notification.send_template'] as const
export type NodeState = 'waiting' | 'authorized' | 'active' | 'completed' | 'stopped' | 'denied' | 'failed' | 'unknown'
export const NODE_STATE_LABELS: Record<NodeState, string> = {
  waiting: '等待', authorized: '持有凭证', active: '处理中', completed: '已完成', stopped: '已停止',
  denied: '权限拒绝', failed: '执行失败', unknown: '结果未确认',
}
export const MODE_LABELS = { deterministic: '确定性规则', local: '历史规划记录', cloud: '智能体审查' }

export function modelDisplayLabel(model: unknown): string {
  return typeof model === 'string' && model.length > 0 ? 'AI 规划器' : '无大模型调用'
}
export const STAGE_LABELS: Record<string, string> = {
  coordinate: '任务分工', knowledge_read: '检索规划', knowledge_summary: '知识分析',
  case_read: '工单核验', refund: '退款规划', case_notify: '通知规划',
}
export const PROPOSAL_STAGE_LABELS: Record<string, string> = {
  coordinate: '任务分工', knowledge_read: '知识读取候选', knowledge_summary: '知识分析',
  case_read: '工单读取候选', refund: '退款候选', case_notify: '通知候选',
}
export const WORKFLOW_STAGES = [
  { id: 'coordinate', label: '任务分工', agentId: 'agent-coordinator', tool: null },
  { id: 'knowledge_read', label: '知识检索', agentId: 'agent-knowledge', tool: 'knowledge.read_associated' },
  { id: 'case_read', label: '工单读取', agentId: 'agent-case', tool: 'ticket.read' },
  { id: 'refund', label: '退款提交', agentId: 'agent-refund', tool: 'refund.create' },
  { id: 'case_notify', label: '结果通知', agentId: 'agent-case', tool: 'notification.send_template' },
] as const
export const AGENT_DUTIES: Record<string, string> = {
  'agent-coordinator': '分工与受控委托', 'agent-knowledge': '检索并分析退款规则',
  'agent-case': '核验工单与通知客户', 'agent-refund': '提出原路退款动作',
}

export function activeWorkflow(snapshot: TaskSnapshot | null): WorkflowRun | null {
  return snapshot?.workflow_runs?.[0] ?? null
}

export function workflowIsRunning(run: WorkflowRun | null): boolean {
  return Boolean(run && ['QUEUED', 'RUNNING'].includes(run.state))
}

export function taskAuthorizationLabel(status: string | null | undefined): string | undefined {
  if (status === 'AUTHORIZED') return '根授权已签发'
  if (status === 'PENDING_AUTHORIZATION') return '待签发根授权'
  if (status === 'REVOKED') return '根授权已撤销'
  return undefined
}

export type BusinessOutcomeStatus = 'COMPLETED' | 'BUSINESS_STOPPED' | 'DENIED' | 'UNKNOWN' | 'RUNNING' | 'NO_EFFECT' | 'INCONSISTENT' | 'NOT_RUN'

export interface BusinessOutcome {
  status: BusinessOutcomeStatus
  label: string
  detail: string
  refundFen: number
  notificationCount: number
}

export function isBusinessStop(reasonCode: unknown): boolean {
  return typeof reasonCode === 'string' && (reasonCode === 'PLANNER_DECLINED' || reasonCode.startsWith('BUSINESS_PRECONDITION') || reasonCode.startsWith('BUSINESS_VERIFICATION'))
}

export function workflowStatus(state: string | null | undefined, reasonCode?: string | null): { value: string; label?: string } {
  if (['DENIED', 'FAILED', 'STOPPED'].includes(state ?? '') && isBusinessStop(reasonCode)) {
    return { value: 'BUSINESS_STOPPED', label: reasonCode === 'PLANNER_DECLINED' ? '业务已停止'
      : reasonCode?.includes('PENDING') || reasonCode?.includes('UNVERIFIED') ? '资料待核验' : '办理条件未满足' }
  }
  if (state === 'DENIED' && !reasonCode) return { value: 'STOPPED', label: '已停止 · 原因未记录' }
  if (state === 'DENIED') return { value: 'DENIED', label: '权限拒绝' }
  if (state === 'UNKNOWN' || state === 'RECONCILING' || reasonCode?.includes('RESULT_UNKNOWN') || reasonCode?.includes('RESULT_UNCONFIRMED')) {
    return { value: 'UNKNOWN', label: '结果未确认' }
  }
  if (state === 'FAILED') return { value: 'FAILED', label: '执行失败' }
  return { value: state ?? 'NOT_RECORDED' }
}

export function workflowEventState(event: WorkflowEvent): NodeState | null {
  if (event.action === 'business_verification' && event.details.status !== 'VERIFIED') return 'stopped'
  if (event.details.decision === 'decline' || isBusinessStop(event.details.reason_code)) return 'stopped'
  if (event.status === 'UNKNOWN' || ['UNKNOWN', 'RECONCILING', 'RECOVERY_FAILED_FINAL'].includes(String(event.details.state ?? event.details.execution_state))
    || typeof event.details.reason_code === 'string' && /RESULT_(UNKNOWN|UNCONFIRMED)/.test(event.details.reason_code)) return 'unknown'
  if (event.status === 'FAILED') return 'failed'
  if (event.status === 'DENIED') return 'denied'
  return null
}

export function executionNodeState(execution: ExecutionView): NodeState {
  if (execution.decision === 'DENY') return 'denied'
  if (execution.state === 'COMMITTED') return execution.decision === 'ALLOW' ? 'completed' : 'unknown'
  if (['UNKNOWN', 'RECONCILING', 'RECOVERY_FAILED_FINAL'].includes(execution.state)) return 'unknown'
  if (execution.state === 'CANCELLED_NO_EFFECT') return 'stopped'
  if (['FAILED', 'FAILED_NO_EFFECT', 'RELEASED'].includes(execution.state)) return 'failed'
  return 'active'
}

export function visibleCredentials(snapshot: TaskSnapshot | null, events: WorkflowEvent[], replay: boolean): CredentialView[] {
  const issued = new Set(events.filter((event) => event.action === 'delegate').map((event) => event.details.credential_id))
  return snapshot?.credentials.filter((credential) => !replay || credential.credential_type === 'ROOT' || issued.has(credential.credential_id)) ?? []
}

export function visibleExecutions(snapshot: TaskSnapshot | null, events: WorkflowEvent[], replay: boolean): ExecutionView[] {
  // Replay reveals stored terminal projections only after a result event, not at request dispatch.
  const ids = new Set(events.filter((event) => ['gateway_decision', 'call_tool'].includes(event.action)).map((event) => event.details.execution_id))
  return snapshot?.executions.filter((execution) => !replay || ids.has(execution.execution_id)) ?? []
}

export interface BusinessResultState {
  label: string; state: NodeState; amountFen?: number; count: number
}

export function workflowBusinessResults(snapshot: TaskSnapshot | null, events: WorkflowEvent[] = [], replay = false): {
  refund: BusinessResultState; notification: BusinessResultState
} {
  const stopped = !replay && ['DENIED', 'FAILED', 'INTERRUPTED', 'STOPPED'].includes(activeWorkflow(snapshot)?.state ?? '')
  const executions = visibleExecutions(snapshot, events, replay)
  const visibleIds = new Set(executions.map((execution) => execution.execution_id))
  const refunds = snapshot?.business_effects.refunds.filter((row) => !replay || visibleIds.has(row.execution_id)) ?? []
  const notices = snapshot?.business_effects.notifications.filter((row) => !replay || visibleIds.has(row.execution_id)) ?? []
  const bound = (executionId: string, effectId: string, tool: string) => {
    const matches = executions.filter((execution) => execution.execution_id === executionId)
    return matches.length === 1 && matches[0].tool_name === tool && matches[0].decision === 'ALLOW'
      && matches[0].state === 'COMMITTED' && matches[0].business_effect_id === effectId
  }
  const pending = (tool: string, waitingLabel: string): BusinessResultState => {
    const own = executions.filter((execution) => execution.tool_name === tool)
    const last = own[own.length - 1]
    if (last?.state === 'COMMITTED') return { label: '业务结果待核对', state: 'unknown', count: 0 }
    if (last?.decision === 'DENY') return { label: tool === 'refund.create' ? '退款权限被拒绝' : '通知权限被拒绝', state: 'denied', count: 0 }
    if (last) {
      const state = executionNodeState(last)
      if (state === 'unknown') return { label: tool === 'refund.create' ? '退款结果未确认' : '通知结果未确认', state, count: 0 }
      if (state === 'active') return { label: tool === 'refund.create' ? '退款处理中' : '通知处理中', state, count: 0 }
      return { label: tool === 'refund.create' ? '退款未执行' : '通知未执行', state, count: 0 }
    }
    if (!last && stopped) return { label: tool === 'refund.create' ? '退款未执行' : '通知未执行', state: 'waiting', count: 0 }
    return { label: waitingLabel, state: last ? 'failed' : 'waiting', count: 0 }
  }
  const amountFen = refunds.reduce((total, row) => total + row.amount_fen, 0)
  const refundValid = refunds.length > 0 && refunds.every((row) => row.status === 'COMMITTED'
    && Number.isSafeInteger(row.amount_fen) && row.amount_fen > 0
    && bound(row.execution_id, row.refund_id, 'refund.create'))
    && new Set(refunds.map((row) => row.refund_id)).size === refunds.length
    && new Set(refunds.map((row) => row.execution_id)).size === refunds.length
    && Number.isSafeInteger(amountFen) && amountFen <= (snapshot?.task.refund_total_fen ?? 0)
  const refund: BusinessResultState = refundValid
    ? { label: '退款已提交', state: 'completed', count: refunds.length, amountFen }
    : refunds.length ? { label: '退款记录不一致', state: 'failed', count: refunds.length }
      : pending('refund.create', '退款未执行')
  const noticeValid = notices.length > 0 && refundValid && notices.every((row) => row.status === 'SENT'
    && row.template_id === 'REFUND_SUCCESS' && refunds.some((item) => item.refund_id === row.related_business_effect_id)
    && (row.customer_id === undefined || row.customer_id === snapshot?.task.customer_id)
    && bound(row.execution_id, row.notification_id, 'notification.send_template'))
    && new Set(notices.map((row) => row.notification_id)).size === notices.length
  const notification: BusinessResultState = noticeValid
    ? { label: '通知已发送', state: 'completed', count: notices.length }
    : notices.length ? { label: '通知记录不一致', state: 'failed', count: notices.length }
      : pending('notification.send_template', refundValid ? '通知未执行' : '等待退款确认')
  return { refund, notification }
}

/** A tool request being allowed is not evidence that a refund was committed. */
export function businessOutcome(snapshot: TaskSnapshot | null): BusinessOutcome {
  if (!snapshot) return { status: 'NOT_RUN', label: '尚未执行', detail: '尚未读取任务快照', refundFen: 0, notificationCount: 0 }
  const results = workflowBusinessResults(snapshot)
  const ticket = snapshot.business_context?.ticket
  const verification = ticket?.business_verification
  const factBased = ticket?.source === 'facts' || Boolean(ticket?.business_facts)
  const rejected = verification?.status === 'REJECTED' || !factBased
    && (ticket?.verification_status === 'REJECTED' || ticket?.payment_verification_status === 'REJECTED')
  const refundFen = results.refund.amountFen ?? 0
  const notificationCount = results.notification.count
  if (results.refund.state === 'completed') {
    return { status: 'COMPLETED', label: '退款已提交', detail: `退款已提交 ${refundFen / 100} 元${notificationCount ? `，客户通知已发送 ${notificationCount} 条` : '，客户通知尚未发送'}`, refundFen, notificationCount }
  }
  if (rejected) {
    return { status: 'BUSINESS_STOPPED', label: '退款未执行', detail: verification?.reason ? `${verification.reason} 未提交退款，客户通知未发送` : '业务核验未通过，未提交退款；客户通知未发送', refundFen: 0, notificationCount: 0 }
  }
  if (verification?.status === 'PENDING') {
    if (verification.reason_code === 'MULTIPLE_EXTRA_PAYMENTS') {
      return { status: 'BUSINESS_STOPPED', label: '多笔重复付款需人工核验，未自动退款',
        detail: `${verification.reason} 当前自动流程不支持在同一任务中安全拆分多笔退款，请人工逐笔核验后再处理；未提交退款，客户通知未发送`, refundFen: 0, notificationCount: 0 }
    }
    return { status: 'BUSINESS_STOPPED', label: '资料待核验，未退款', detail: `${verification.reason} 未提交退款，客户通知未发送`, refundFen: 0, notificationCount: 0 }
  }
  if (results.refund.state === 'failed' || results.notification.state === 'failed') {
    return { status: 'INCONSISTENT', label: '业务记录关联异常，待核对', detail: '已发现业务记录，但无法与受控执行完整关联；退款与通知结果待核对', refundFen: 0, notificationCount: 0 }
  }
  if (results.refund.state === 'unknown') {
    return { status: 'UNKNOWN', label: '退款结果待确认', detail: '已有退款请求，但尚未取得可信业务回执；请勿重复办理', refundFen, notificationCount }
  }
  if (results.refund.state === 'denied') {
    return { status: 'DENIED', label: '退款权限被拒绝', detail: '网关拒绝了退款请求，未提交退款；客户通知未发送', refundFen: 0, notificationCount: 0 }
  }
  if (workflowIsRunning(activeWorkflow(snapshot))) {
    return { status: 'RUNNING', label: '退款处理中', detail: '协作流程仍在运行，尚未形成最终业务结果', refundFen: 0, notificationCount: 0 }
  }
  if (activeWorkflow(snapshot)?.reason_code === 'PLANNER_DECLINED') {
    const plan = [...(activeWorkflow(snapshot)?.events ?? [])].reverse().find((event) => event.action === 'plan' && event.details.decision === 'decline')
    if (verification?.status === 'VERIFIED' && verification.refundable_amount_fen > snapshot.task.refund_total_fen) {
      return { status: 'NO_EFFECT', label: '授权额度不足，未提交退款',
        detail: `核对应退 ${(verification.refundable_amount_fen / 100).toFixed(2)} 元，本任务仅授权 ${(snapshot.task.refund_total_fen / 100).toFixed(2)} 元。请重新授权足够额度后办理；本次未提交退款，客户通知未发送。`, refundFen: 0, notificationCount: 0 }
    }
    return { status: 'NO_EFFECT', label: '本次办理已停止，未提交退款',
      detail: `${typeof plan?.details.summary === 'string' ? plan.details.summary : '本次未形成可执行的退款方案。'}${verification?.status === 'VERIFIED' ? ' 独立业务核验可退，但未提交退款，客户通知未发送。' : ' 未提交退款，客户通知未发送。'}`, refundFen: 0, notificationCount: 0 }
  }
  if (snapshot.executions.length > 0) {
    return { status: 'NO_EFFECT', label: '退款未执行', detail: '已完成受控执行，但没有形成退款业务效果；客户通知未发送', refundFen: 0, notificationCount: 0 }
  }
  if (snapshot.task.status === 'PENDING_AUTHORIZATION') {
    return { status: 'NOT_RUN', label: '待授权', detail: '任务尚未获得根授权，未执行退款或通知', refundFen: 0, notificationCount: 0 }
  }
  return { status: 'NOT_RUN', label: '尚未执行', detail: '尚未执行退款或通知', refundFen: 0, notificationCount: 0 }
}

export function workflowStageStates(snapshot: TaskSnapshot | null, events: WorkflowEvent[], replay = false) {
  return WORKFLOW_STAGES.map((stage) => {
    const own = events.filter((event) => event.agent_id === stage.agentId
      && (event.details.stage === stage.id || stage.id === 'knowledge_read' && event.details.stage === 'knowledge_summary'))
    const failure = [...own].reverse().find((event) => workflowEventState(event) !== null)
    const latest = own[own.length - 1]
    const state: NodeState = failure ? workflowEventState(failure)!
      : latest?.action === 'plan_started' ? 'active'
        : stage.tool ? toolNodeState(stage.tool, events, snapshot, replay)
        : own.some((event) => event.action === 'plan' && event.status === 'COMPLETED') ? 'completed' : own.length ? 'active' : 'waiting'
    const event = [...events].reverse().find((item) => item.agent_id === stage.agentId
      && (item.details.stage === stage.id || stage.id === 'knowledge_read' && item.details.stage === 'knowledge_summary'
        || stage.tool && item.details.tool === stage.tool))
    return { ...stage, state: state === 'waiting' && own.length ? 'active' as const : state, event }
  })
}

export function workflowActiveRequest(events: WorkflowEvent[]): WorkflowEvent | undefined {
  const last = events[events.length - 1]
  return last?.action === 'gateway_request' && last.status === 'RUNNING' ? last : undefined
}

export function agentNodeState(agentId: string, events: WorkflowEvent[], snapshot: TaskSnapshot | null, interrupted = false, replay = false): NodeState {
  const own = events.filter((event) => event.agent_id === agentId)
  if (!own.length) return visibleCredentials(snapshot, events, replay).some((credential) => credential.holder_agent_id === agentId) ? 'authorized' : 'waiting'
  const failure = [...own].reverse().find((event) => workflowEventState(event) !== null)
  if (failure) return workflowEventState(failure)!
  const executionIds = new Set(own.map((event) => event.details.execution_id))
  if (visibleExecutions(snapshot, events, replay).some((execution) => executionIds.has(execution.execution_id) && executionNodeState(execution) === 'unknown')) return 'unknown'
  if (own.some((event) => event.action === 'agent_finished' && event.status === 'COMPLETED')) return 'completed'
  return interrupted ? 'failed' : 'active'
}

export function eventTitle(event: WorkflowEvent): string {
  const details = event.details
  switch (event.action) {
    case 'agent_started': return `${agentLabel(event.agent_id)}接手任务`
    case 'agent_finished': return `${agentLabel(event.agent_id)}${event.status === 'COMPLETED' ? '完成处理' : '停止处理'}`
    case 'plan_started': return `${STAGE_LABELS[String(details.stage)] ?? '角色规划'}开始`
    case 'plan': return `${STAGE_LABELS[String(details.stage)] ?? '角色规划'}${workflowEventState(event) === 'stopped' ? '停止后续办理' : event.status === 'COMPLETED' ? '完成' : '未通过'}`
    case 'delegate': return `委托${agentLabel(String(details.child_agent_id))}`
    case 'knowledge_result': return details.injection_applied ? '收到含附加指令的关联文档' : '收到工单关联知识'
    case 'business_verification': return details.status === 'VERIFIED' ? '独立业务核验通过，等待受控执行' : details.status === 'PENDING' ? '独立业务核验：资料待核验' : '独立业务核验：不符合退款条件'
    case 'gateway_request': return `${toolLabel(String(details.tool))}请求网关准入`
    case 'gateway_decision': return workflowEventState(event) === 'stopped' ? '业务条件未满足，停止办理'
      : workflowEventState(event) === 'unknown' ? `${toolLabel(String(details.tool))}结果未确认`
        : event.status === 'DENIED' ? reasonLabel(String(details.reason_code))
          : event.status === 'FAILED' ? `${toolLabel(String(details.tool))}请求未完成` : `${toolLabel(String(details.tool))}已获准并提交`
    case 'call_tool': return `${toolLabel(String(details.tool))}结果已受控重取`
    case 'planner_declined': return '规划决定停止后续办理'
    default: return event.action
  }
}

export function eventSummary(event: WorkflowEvent): string {
  if (typeof event.details.reason === 'string') return event.details.reason
  if (typeof event.details.summary === 'string') return event.details.summary
  if (typeof event.details.reason_code === 'string') return reasonLabel(event.details.reason_code)
  if (typeof event.details.tool === 'string') return toolLabel(event.details.tool)
  if (event.action === 'knowledge_result' && event.details.injection_applied) return '本次读取快照包含附加指令，原始文档保留用于核对'
  return AGENT_DUTIES[event.agent_id] ?? ''
}

export function toolNodeState(tool: string, events: WorkflowEvent[], snapshot: TaskSnapshot | null, replay: boolean): NodeState {
  const mentioned = events.filter((event) => event.details.tool === tool)
  const last = mentioned[mentioned.length - 1]
  const executions = visibleExecutions(snapshot, events, replay).filter((execution) => execution.tool_name === tool)
  if (executions.some((execution) => execution.decision === 'DENY')) return 'denied'
  if (executions.some((execution) => executionNodeState(execution) === 'unknown')) return 'unknown'
  if (executions.some((execution) => executionNodeState(execution) === 'failed')) return 'failed'
  if (executions.some((execution) => executionNodeState(execution) === 'stopped')) return 'stopped'
  if (last && workflowEventState(last)) return workflowEventState(last)!
  if (last?.action === 'gateway_request') return 'active'
  if (executions.some((execution) => execution.state === 'COMMITTED')) {
    if (tool === 'refund.create') return workflowBusinessResults(snapshot, events, replay).refund.state
    if (tool === 'notification.send_template') return workflowBusinessResults(snapshot, events, replay).notification.state
    return 'completed'
  }
  if (executions.length) return executionNodeState(executions[executions.length - 1])
  return 'waiting'
}

export function gatewayNodeState(events: WorkflowEvent[], snapshot: TaskSnapshot | null, replay: boolean): NodeState {
  const own = events.filter((event) => ['gateway_request', 'gateway_decision'].includes(event.action))
  const last = own[own.length - 1]
  if (last && workflowEventState(last)) return workflowEventState(last)!
  if (last?.action === 'gateway_request') return 'active'
  const executions = visibleExecutions(snapshot, events, replay)
  if (executions.some((execution) => executionNodeState(execution) === 'unknown')) return 'unknown'
  if (executions.some((execution) => executionNodeState(execution) === 'denied')) return 'denied'
  if (executions.some((execution) => executionNodeState(execution) === 'failed')) return 'failed'
  if (executions.some((execution) => executionNodeState(execution) === 'active')) return 'active'
  if (executions.some((execution) => executionNodeState(execution) === 'stopped')) return 'stopped'
  if (own.length || executions.length) return 'completed'
  return 'waiting'
}
