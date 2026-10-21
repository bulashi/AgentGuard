import type { ReactNode } from 'react'
import { render, screen, within } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { LiveExecution } from './LiveExecution'
import { savedSnapshot, workflowSnapshot } from '../test/fixtures'
import type { TaskSnapshot } from '../types'

// Render the graph's real stage buttons without depending on jsdom layout.
// Browser acceptance separately checks React Flow layout at 1280px.
vi.mock('@xyflow/react', () => ({
  ReactFlow: ({ nodes, nodeTypes, children }: { nodes: Array<{ id: string; type: string; data: unknown }>; nodeTypes: Record<string, (props: { data: unknown }) => ReactNode>; children: ReactNode }) => <div>{nodes.map((node) => {
    const NodeComponent = nodeTypes[node.type]
    return <div key={node.id}><NodeComponent data={node.data} /></div>
  })}{children}</div>,
  Background: () => null, Controls: () => null, Handle: () => null,
  MarkerType: { ArrowClosed: 'arrowclosed' }, Position: { Left: 'left', Right: 'right' },
  useNodesInitialized: () => false, useReactFlow: () => ({ fitView: vi.fn() }), useStore: () => 0,
}))

function replay(snapshot: TaskSnapshot) {
  render(<LiveExecution snapshot={snapshot} demo={null} runState={{ phase: 'idle', kind: null, startedAt: null }} overview={null}
    onInspect={vi.fn()} onHistory={vi.fn()} observedAt={1790000005} />)
}

describe('LiveExecution business stop', () => {
  it('does not turn approved read calls into a gateway rejection or a completed refund stage', () => {
    const reason = '订单应付 70.00 元；成功支付 1 笔，失败支付 1 笔未扣款，没有多扣款可退。'
    replay({ ...workflowSnapshot,
      executions: [{ ...workflowSnapshot.executions[0], tool_name: 'ticket.read', tool_service: 'ticket-service', business_effect_id: null }],
      business_effects: { refunds: [], notifications: [] },
      business_context: { ticket: { ...workflowSnapshot.business_context!.ticket!, source: 'facts',
        business_verification: { schema_version: '1.0', task_id: workflowSnapshot.task.task_id, ticket_id: workflowSnapshot.task.ticket_id,
          facts_hash: 'f'.repeat(64), status: 'REJECTED', reason_code: 'NO_DUPLICATE_SUCCESSFUL_PAYMENT', reason,
          evidence_ids: ['PAYMENT:P1', 'PAYMENT:P2'], refundable_amount_fen: 0, original_transaction_id: null,
          policy_version: 'duplicate-full-charge-v1', evaluated_at: 1790000002 } }, documents: [] },
      workflow_runs: [{ ...workflowSnapshot.workflow_runs![0], state: 'DENIED', reason_code: 'BUSINESS_VERIFICATION_REJECTED' }],
    })
    const gateway = screen.getByTestId('stage-gateway')
    expect(gateway).toHaveTextContent('验签 · 原子准入 · 预算')
    expect(gateway).not.toHaveTextContent('存在拒绝记录')
    expect(gateway).toHaveClass('stage-complete')
    const tools = screen.getByTestId('stage-tools')
    expect(tools).toHaveTextContent('退款未执行')
    expect(tools).toHaveTextContent('业务核验未通过 · 未分发')
    expect(tools).not.toHaveClass('stage-complete')
    expect(screen.getByTestId('execution-decision')).toHaveTextContent(reason)
    expect(screen.getByRole('button', { name: /通知未发送\s*0\s*条/ })).toBeInTheDocument()
  })

  it('continues to show an actual gateway rejection as a rejection', () => {
    replay(savedSnapshot)
    const gateway = screen.getByTestId('stage-gateway')
    expect(gateway).toHaveTextContent('存在拒绝记录')
    expect(gateway).toHaveClass('stage-denied')
    expect(within(screen.getByTestId('execution-decision')).getByText('退款权限被拒绝')).toBeInTheDocument()
  })
})
