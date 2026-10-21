import { describe, expect, it } from 'vitest'
import { agentNodeState, businessOutcome, gatewayNodeState, toolNodeState, visibleCredentials, visibleExecutions, workflowActiveRequest, workflowBusinessResults, workflowEventState, workflowIsRunning, workflowStageStates, workflowStatus } from './workflowModel'
import type { BusinessVerification } from './api'
import type { TaskSnapshot } from './types'
import { savedSnapshot, workflowEvents, workflowSnapshot } from './test/fixtures'

describe('persisted collaboration states', () => {
  it('does not fabricate completed roles for legacy records', () => {
    expect(agentNodeState('agent-coordinator', [], savedSnapshot)).toBe('authorized')
    expect(agentNodeState('agent-refund', [], savedSnapshot)).toBe('waiting')
  })

  it('reveals delegations only after their recorded event in replay', () => {
    expect(visibleCredentials(workflowSnapshot, [], true)).toHaveLength(1)
    expect(agentNodeState('agent-refund', [], workflowSnapshot, false, true)).toBe('waiting')
    expect(visibleCredentials(workflowSnapshot, workflowEvents.slice(0, 3), true).map((item) => item.credential_id)).toEqual(['cred-root-test', 'cred-knowledge'])
  })

  it('does not expose future execution states in replay', () => {
    expect(visibleExecutions(workflowSnapshot, workflowEvents.slice(0, 12), true)).toEqual([])
    expect(toolNodeState('refund.create', [], workflowSnapshot, true)).toBe('waiting')
    expect(toolNodeState('refund.create', workflowEvents.slice(0, 12), workflowSnapshot, true)).toBe('active')
    expect(toolNodeState('refund.create', workflowEvents.slice(0, 13), workflowSnapshot, true)).toBe('completed')
  })

  it('uses actual role finish and failure events', () => {
    expect(agentNodeState('agent-refund', workflowEvents.slice(0, 12), workflowSnapshot)).toBe('active')
    expect(agentNodeState('agent-refund', workflowEvents, workflowSnapshot)).toBe('completed')
    const failed = [{ ...workflowEvents[11], status: 'FAILED' }]
    expect(agentNodeState('agent-refund', failed, workflowSnapshot)).toBe('failed')
    expect(toolNodeState('refund.create', failed, null, true)).toBe('failed')
    expect(gatewayNodeState(failed, null, true)).toBe('failed')
  })

  it('distinguishes running, denied and interrupted workflows', () => {
    const run = workflowSnapshot.workflow_runs![0]
    expect(workflowIsRunning({ ...run, state: 'RUNNING' })).toBe(true)
    expect(workflowIsRunning({ ...run, state: 'INTERRUPTED' })).toBe(false)
    expect(agentNodeState('agent-refund', workflowEvents.slice(0, 12), workflowSnapshot, true)).toBe('failed')
    expect(toolNodeState('refund.create', [], savedSnapshot, false)).toBe('denied')
    expect(gatewayNodeState([], savedSnapshot, false)).toBe('denied')
  })
})

describe('workflow results are execution facts, not planning prose', () => {
  it('a legal refund remains committed when the planner rejects injected instructions', () => {
    const events = workflowEvents.map((event) => event.action === 'plan' ? { ...event,
      details: { ...event.details, summary: '不予采纳污染指令，本阶段未执行退款。' },
    } : event)
    expect(workflowBusinessResults(workflowSnapshot, events).refund).toEqual({
      label: '退款已提交', state: 'completed', count: 1, amountFen: 7000,
    })
    expect(workflowBusinessResults(workflowSnapshot, events).notification.label).toBe('通知未执行')
  })

  it.each(['UNKNOWN', 'RESERVED', 'DISPATCHED', 'FAILED_NO_EFFECT', 'CANCELLED_NO_EFFECT'])('does not mark %s as a completed refund', (state) => {
    const snapshot = { ...workflowSnapshot, executions: [{ ...workflowSnapshot.executions[0], state }],
      business_effects: { refunds: [], notifications: [] } }
    expect(workflowBusinessResults(snapshot).refund.state).not.toBe('completed')
    expect(toolNodeState('refund.create', [], snapshot, false)).not.toBe('completed')
  })

  it.each([0, -1, 7001, Number.MAX_SAFE_INTEGER + 1, Number.NaN])('does not present invalid refund amount %s as success', (amount_fen) => {
    const snapshot = { ...workflowSnapshot, business_effects: { refunds: [{ ...workflowSnapshot.business_effects.refunds[0], amount_fen }], notifications: [] } }
    expect(workflowBusinessResults(snapshot).refund.label).toBe('退款记录不一致')
  })

  it('does not turn a committed execution without its business row green', () => {
    const snapshot = { ...workflowSnapshot, business_effects: { refunds: [], notifications: [] } }
    expect(workflowBusinessResults(snapshot).refund.label).toBe('业务结果待核对')
    expect(toolNodeState('refund.create', [], snapshot, false)).toBe('unknown')
  })

  it('rejects duplicate or incorrectly bound business rows', () => {
    const row = workflowSnapshot.business_effects.refunds[0]
    const duplicate = { ...workflowSnapshot, business_effects: { refunds: [{ ...row, amount_fen: 3500 }, { ...row, amount_fen: 3500 }], notifications: [] } }
    expect(workflowBusinessResults(duplicate).refund.label).toBe('退款记录不一致')
    const mismatch = { ...workflowSnapshot, business_effects: { refunds: [{ ...row, execution_id: 'missing' }], notifications: [] } }
    expect(workflowBusinessResults(mismatch).refund.label).toBe('退款记录不一致')
  })

  it('a notice must be signed-execution bound and related to a committed refund', () => {
    const notice = { notification_id: 'notice-1', execution_id: 'execution-notice', template_id: 'REFUND_SUCCESS',
      related_business_effect_id: 'refund-1', status: 'SENT', created_at: 1790000002 }
    const execution = { ...workflowSnapshot.executions[0], execution_id: notice.execution_id,
      tool_name: 'notification.send_template', business_effect_id: notice.notification_id }
    const snapshot = { ...workflowSnapshot, executions: [...workflowSnapshot.executions, execution],
      business_effects: { ...workflowSnapshot.business_effects, notifications: [notice] } }
    expect(workflowBusinessResults(snapshot).notification.label).toBe('通知已发送')
    const wrong = { ...snapshot, business_effects: { ...snapshot.business_effects,
      notifications: [{ ...notice, related_business_effect_id: 'refund-other-task' }] } }
    expect(workflowBusinessResults(wrong).notification.label).toBe('通知记录不一致')
    const noRefund = { ...snapshot, business_effects: { refunds: [], notifications: [notice] } }
    expect(workflowBusinessResults(noRefund).notification.state).toBe('failed')
    const wrongCustomer = { ...snapshot, business_effects: { ...snapshot.business_effects,
      notifications: [{ ...notice, customer_id: 'C7812' }] } }
    expect(workflowBusinessResults(wrongCustomer).notification.label).toBe('通知记录不一致')
    expect(toolNodeState('notification.send_template', [], wrongCustomer, false)).toBe('failed')
  })

  it('replay hides a future refund even if it already exists in the saved database projection', () => {
    expect(workflowBusinessResults(workflowSnapshot, workflowEvents.slice(0, 12), true).refund.label).toBe('退款未执行')
    expect(workflowBusinessResults(workflowSnapshot, workflowEvents.slice(0, 13), true).refund.label).toBe('退款已提交')
  })

  it('an explicit structured decline stops this step; later stages stay unexecuted', () => {
    const decline = { ...workflowEvents[10], status: 'DENIED', details: { stage: 'refund', decision: 'decline', intents: [], summary: '停止后续执行。' } }
    const empty = { ...workflowSnapshot, executions: [], business_effects: { refunds: [], notifications: [] } }
    const stages = workflowStageStates(empty, [decline], true)
    expect(stages.map((stage) => stage.id)).toEqual(['coordinate', 'knowledge_read', 'case_read', 'refund', 'case_notify'])
    expect(stages[3].state).toBe('stopped')
    expect(stages[4].state).toBe('waiting')
    expect(workflowBusinessResults(empty).refund.label).toBe('退款未执行')
  })

  it('opens the knowledge decline rather than its earlier read execution', () => {
    const decline = { ...workflowEvents[10], agent_id: 'agent-knowledge', status: 'DENIED',
      details: { stage: 'knowledge_summary', decision: 'decline', intents: [] } }
    const stage = workflowStageStates(workflowSnapshot, [...workflowEvents.slice(0, 7), decline])[1]
    expect(stage.state).toBe('stopped')
    expect(stage.event).toBe(decline)
  })

  it('does not suggest awaiting a refund after a terminal workflow without effects', () => {
    const snapshot = { ...workflowSnapshot, executions: [], business_effects: { refunds: [], notifications: [] },
      workflow_runs: workflowSnapshot.workflow_runs!.map((run) => ({ ...run, state: 'DENIED' })) }
    expect(workflowBusinessResults(snapshot).notification.label).toBe('通知未执行')
    expect(workflowBusinessResults(snapshot, [], true).notification.label).toBe('等待退款确认')
  })

  it('only the current gateway request can animate, never all role and tool branches', () => {
    const request = workflowEvents[11]
    expect(workflowActiveRequest([request])).toBe(request)
    expect(workflowActiveRequest([request, workflowEvents[12]])).toBeUndefined()
    expect(workflowActiveRequest(workflowEvents.slice(0, 11))).toBeUndefined()
    expect(workflowActiveRequest([])).toBeUndefined()
  })
})

describe('business stop, authorization denial and uncertain execution stay distinct', () => {
  const factSnapshot = (status: BusinessVerification['status'], reason: string): TaskSnapshot => ({ ...workflowSnapshot,
    executions: [], business_effects: { refunds: [], notifications: [] },
    workflow_runs: [{ ...workflowSnapshot.workflow_runs![0], state: 'DENIED', reason_code: `BUSINESS_VERIFICATION_${status}` }],
    business_context: { ...workflowSnapshot.business_context!, ticket: { ...workflowSnapshot.business_context!.ticket!, source: 'facts',
      business_verification: { schema_version: '1.0', task_id: workflowSnapshot.task.task_id, ticket_id: workflowSnapshot.task.ticket_id,
        facts_hash: 'a'.repeat(64), status, reason_code: status === 'REJECTED' ? 'NO_DUPLICATE_SUCCESSFUL_CHARGE' : 'PAYMENT_PROCESSING',
        reason, evidence_ids: ['P-one', 'P-two'], refundable_amount_fen: 0, original_transaction_id: null,
        policy_version: 'duplicate-full-charge-v1', evaluated_at: 1790000001 } } },
  })

  it.each([
    { status: 'REJECTED' as const, label: '退款未执行', reason: '只有 P-one 支付成功，P-two 支付失败，没有第二笔成功扣款。' },
    { status: 'PENDING' as const, label: '资料待核验，未退款', reason: 'P-two 的支付仍在处理中，需要等待支付结果确认。' },
  ])('uses the fact evaluation $status and its concrete reason without preset legacy fields', ({ status, label, reason }) => {
    const result = businessOutcome(factSnapshot(status, reason))
    expect(result).toMatchObject({ status: 'BUSINESS_STOPPED', label, refundFen: 0, notificationCount: 0 })
    expect(result.detail).toContain(reason)
    expect(result.detail).toContain('未提交退款，客户通知未发送')
  })

  it('explains that multiple extra payments require manual review instead of implying missing data', () => {
    const snapshot = factSnapshot('PENDING', '发现超过两笔完整成功付款，净多付金额需要逐笔核对。')
    snapshot.business_context!.ticket!.business_verification!.reason_code = 'MULTIPLE_EXTRA_PAYMENTS'
    expect(businessOutcome(snapshot)).toMatchObject({
      status: 'BUSINESS_STOPPED', label: '多笔重复付款需人工核验，未自动退款', refundFen: 0, notificationCount: 0,
    })
    expect(businessOutcome(snapshot).detail).toContain('当前自动流程不支持在同一任务中安全拆分多笔退款')
    expect(businessOutcome(snapshot).detail).toContain('请人工逐笔核验后再处理')
  })

  it('does not turn an unevaluated fact case into a preset rejection from a legacy field', () => {
    const snapshot = factSnapshot('PENDING', '支付尚未确认。')
    snapshot.workflow_runs = []
    snapshot.business_context!.ticket = { ...snapshot.business_context!.ticket!, business_verification: null, verification_status: 'REJECTED' }
    expect(businessOutcome(snapshot)).toMatchObject({ status: 'NOT_RUN', label: '尚未执行' })
  })

  it('shows an Agent decline separately from an independent positive evaluation and actual refund effects', () => {
    const snapshot = factSnapshot('VERIFIED', '两笔成功支付中有一笔属于重复扣款。')
    snapshot.workflow_runs = [{ ...snapshot.workflow_runs![0], reason_code: 'PLANNER_DECLINED', events: [] }]
    expect(businessOutcome(snapshot)).toMatchObject({ status: 'NO_EFFECT', label: '本次办理已停止，未提交退款', refundFen: 0 })
    expect(businessOutcome(snapshot).detail).toContain('独立业务核验可退，但未提交退款，客户通知未发送')
    expect(businessOutcome(snapshot).detail).not.toContain('授权额度不足')
  })

  it('explains a verified amount exceeding authorization using structured amounts rather than a planner summary', () => {
    const snapshot = factSnapshot('VERIFIED', '发现重复扣款。')
    snapshot.task = { ...snapshot.task, refund_total_fen: 6000 }
    snapshot.business_context!.ticket!.business_verification!.refundable_amount_fen = 7000
    snapshot.workflow_runs = [{ ...snapshot.workflow_runs![0], reason_code: 'PLANNER_DECLINED', events: [] }]
    expect(businessOutcome(snapshot)).toMatchObject({ status: 'NO_EFFECT', label: '授权额度不足，未提交退款', refundFen: 0, notificationCount: 0 })
    expect(businessOutcome(snapshot).detail).toContain('核对应退 70.00 元，本任务仅授权 60.00 元')
  })

  it.each(['DENIED', 'FAILED'])('classifies %s with PLANNER_DECLINED as a business stop, not a gateway decision', (state) => {
    expect(workflowStatus(state, 'PLANNER_DECLINED')).toEqual({ value: 'BUSINESS_STOPPED', label: '业务已停止' })
  })
  it.each(['BUSINESS_PRECONDITION_FAILED', 'BUSINESS_PRECONDITION_REJECTED'])('does not treat %s as a signature failure', (reason) => {
    expect(workflowStatus('DENIED', reason)).toEqual({ value: 'BUSINESS_STOPPED', label: '办理条件未满足' })
  })
  it('uses pending review only when the recorded code actually says pending', () => {
    expect(workflowStatus('DENIED', 'BUSINESS_PRECONDITION_PENDING').label).toBe('资料待核验')
    expect(workflowStatus('DENIED', 'PLANNER_DECLINED').label).not.toBe('资料待核验')
  })
  it('does not invent a gateway cause for a historical DENIED state without its reason', () => {
    expect(workflowStatus('DENIED', null)).toEqual({ value: 'STOPPED', label: '已停止 · 原因未记录' })
  })
  it('keeps a real scope rejection distinct from transport failures and unknown results', () => {
    expect(workflowStatus('DENIED', 'PARAMETER_CONSTRAINT_VIOLATION')).toEqual({ value: 'DENIED', label: '权限拒绝' })
    expect(workflowStatus('FAILED', 'MODEL_REQUEST_FAILED')).toEqual({ value: 'FAILED', label: '执行失败' })
    expect(workflowStatus('FAILED', 'EXECUTION_RESULT_UNKNOWN')).toEqual({ value: 'UNKNOWN', label: '结果未确认' })
  })
  it('propagates an explicit business precondition stop to its role without completing later tools', () => {
    const event = { ...workflowEvents[16], status: 'DENIED', details: { reason_code: 'BUSINESS_PRECONDITION_FAILED' } }
    const snapshot = { ...workflowSnapshot, executions: [], business_effects: { refunds: [], notifications: [] } }
    expect(workflowEventState(event)).toBe('stopped')
    expect(agentNodeState('agent-coordinator', [event], snapshot)).toBe('stopped')
    expect(toolNodeState('refund.create', [event], snapshot, false)).toBe('waiting')
  })
  it.each(['UNKNOWN', 'RECONCILING', 'RECOVERY_FAILED_FINAL'])('never reports %s as zero-effect failure or completed execution', (state) => {
    const snapshot = { ...workflowSnapshot, executions: [{ ...workflowSnapshot.executions[0], state, business_effect_id: null }], business_effects: { refunds: [], notifications: [] } }
    expect(workflowBusinessResults(snapshot).refund).toEqual({ label: '退款结果未确认', state: 'unknown', count: 0 })
    expect(toolNodeState('refund.create', [], snapshot, false)).toBe('unknown')
    expect(gatewayNodeState([], snapshot, false)).toBe('unknown')
  })
  it('keeps pending admission active, not completed', () => {
    const snapshot = { ...workflowSnapshot, executions: [{ ...workflowSnapshot.executions[0], state: 'RESERVED', business_effect_id: null }], business_effects: { refunds: [], notifications: [] } }
    expect(workflowBusinessResults(snapshot).refund).toEqual({ label: '退款处理中', state: 'active', count: 0 })
    expect(gatewayNodeState([], snapshot, false)).toBe('active')
  })
})
