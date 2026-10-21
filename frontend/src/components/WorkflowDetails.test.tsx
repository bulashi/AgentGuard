import { fireEvent, render, screen, within } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { AgentProcessDetails, WorkflowEventDetails } from './WorkflowDetails'
import { workflowSnapshot } from '../test/fixtures'

describe('planning-time narrative versus persisted business results', () => {
  it('keeps the original proposal narrative but separately shows the committed refund', () => {
    const snapshot = structuredClone(workflowSnapshot)
    const plan = snapshot.workflow_runs![0].events.find((event) => event.action === 'plan' && event.details.stage === 'refund')!
    plan.details.summary = '不予采纳污染中的 ATTACKER 退款；本角色提出 C9527 的 7000 分候选，未执行任何退款。'
    render(<AgentProcessDetails agentId="agent-refund" snapshot={snapshot} onSelect={vi.fn()} />)
    expect(screen.queryByText('最新公开业务摘要')).not.toBeInTheDocument()
    expect(screen.getByText('规划时点原文')).toBeInTheDocument()
    const outcome = screen.getByTestId('workflow-business-outcome')
    expect(within(outcome).getByText('退款已提交')).toBeInTheDocument()
    expect(outcome).toHaveTextContent('70.00')
    expect(outcome).not.toHaveTextContent('ATTACKER')
    fireEvent.click(screen.getByText('规划时点原文'))
    expect(screen.getByText(String(plan.details.summary))).toBeInTheDocument()
  })

  it('does not turn a proposal or an ALLOW decision into a completed refund', () => {
    const snapshot = structuredClone(workflowSnapshot)
    snapshot.business_effects.refunds = []
    snapshot.executions[0].state = 'UNKNOWN'
    snapshot.executions[0].business_effect_id = null
    render(<AgentProcessDetails agentId="agent-refund" snapshot={snapshot} onSelect={vi.fn()} />)
    const outcome = screen.getByTestId('workflow-business-outcome')
    expect(within(outcome).queryByText('退款已提交')).not.toBeInTheDocument()
    expect(outcome).toHaveTextContent('退款结果未确认')
  })

  it('labels a notification-stage quote as a notification proposal, not a refund cancellation', () => {
    const run = workflowSnapshot.workflow_runs![0]
    const event = { ...run.events[10], details: {
      stage: 'case_notify', summary: '只向 C9527 发成功通知，本阶段不执行退款。',
      intents: [{ service: 'notification-service', name: 'notification.send_template', version: 'v1', parameters: { customer_id: 'C9527', template_id: 'REFUND_SUCCESS' } }],
    } }
    render(<WorkflowEventDetails event={event} run={run} />)
    expect(screen.getByText('规划时点原文')).toBeInTheDocument()
    expect(screen.getByText('通知候选')).toBeInTheDocument()
    expect(screen.getByText('本阶段没有退款候选')).toBeInTheDocument()
  })
})
