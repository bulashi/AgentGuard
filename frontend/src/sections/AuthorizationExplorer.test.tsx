import { workflowSnapshot } from '../test/fixtures'
import { render, screen, within } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { AuthorizationExplorer } from './AuthorizationExplorer'
import type { CredentialView, TaskSnapshot } from '../types'

function credential(overrides: Partial<CredentialView>): CredentialView {
  return {
    credential_id: 'cred-root-test',
    credential_type: 'ROOT',
    parent_credential_id: null,
    parent_credential_hash: null,
    signed_object_hash: 'a'.repeat(64),
    stored_hash_valid: true,
    source_verification: { schema_version: '1.0', profile: 'CREDENTIAL_ROW_BINDING_V1', schema_valid: true,
      stored_hash_valid: true, row_binding_valid: true, execution_binding_valid: null },
    issuer_subject_id: 'authorization-authority',
    issuer_key_id: 'auth-key-01',
    holder_agent_id: 'agent-coordinator',
    holder_key_id: 'agent-coordinator-key-01',
    not_before: 1_790_707_639,
    expires_at: 1_790_709_439,
    delegation_depth: 2,
    issued_at: 1_790_707_639,
    revoked_at: null,
    revocation_reason: null,
    capabilities: [
      { tool: 'ticket.read', service: 'ticket-service', version: 'v1' },
      { tool: 'refund.create', service: 'refund-service', version: 'v1' },
    ],
    budgets: [
      { quota_type: 'max_tool_calls', limit: 4, reserved: 0, committed: 1, remaining: 3, version: 2 },
    ],
    signature: {
      algorithm: 'SM2',
      key_id: 'auth-key-01',
      fingerprint_sm3: 'b'.repeat(24),
      valid: true,
    },
    ...overrides,
  }
}

describe('AuthorizationExplorer', () => {
  it('renders credential and shared-budget projections in the table', () => {
    const root = credential({})
    const child = credential({
      credential_id: 'cred-delegation-test',
      credential_type: 'DELEGATION',
      parent_credential_id: root.credential_id,
      parent_credential_hash: root.signed_object_hash,
      issuer_subject_id: 'agent-coordinator',
      issuer_key_id: 'agent-coordinator-key-01',
      holder_agent_id: 'agent-case',
      holder_key_id: 'agent-case-key-01',
      delegation_depth: 1,
      capabilities: [{ tool: 'ticket.read', service: 'ticket-service', version: 'v1' }],
      budgets: [
        { quota_type: 'max_tool_calls', limit: 1, reserved: 0, committed: 1, remaining: 0, version: 2 },
      ],
    })
    const snapshot: TaskSnapshot = {
      task: {
        task_id: 'TASK-auth-table',
        tenant_id: 'tenant-A',
        ticket_id: 'T10086',
        customer_id: 'C9527',
        refund_total_fen: 7000,
        max_tool_calls: 4,
        expires_at: 1_790_709_439,
        status: 'AUTHORIZED',
        created_at: 1_790_707_639,
        updated_at: 1_790_707_639,
      },
      credentials: [root, child],
      executions: [],
      receipts: [],
      business_effects: { refunds: [], notifications: [] },
      audit_events: [],
    }

    const { rerender } = render(<AuthorizationExplorer snapshot={snapshot} observedAt={root.expires_at} />)

    const table = screen.getByRole('table')
    expect(within(table).getByText('工单智能体')).toBeInTheDocument()
    expect(within(table).getByText('agent-coordinator')).toBeInTheDocument()
    expect(within(table).getAllByText('ticket.read@v1')).toHaveLength(2)
    expect(within(table).getAllByText('工具调用次数')).toHaveLength(2)
    expect(within(table).getByText('已占用 1 / 4 次')).toBeInTheDocument()
    expect(within(table).getByText('剩余 3 次').parentElement).toHaveTextContent('剩余 3 次 · 预留 0 次 · 已提交 1 次')
    expect(within(table).getAllByText('凭证已过期')).toHaveLength(2)
    expect(within(table).queryByText('生效中')).not.toBeInTheDocument()
    const revoked = { ...snapshot, credentials: [{ ...root, revoked_at: 0 }, child] }
    rerender(<AuthorizationExplorer snapshot={revoked} observedAt={root.not_before} />)
    expect(within(table).getByText('凭证已撤销')).toBeInTheDocument()
    expect(within(table).getByText('祖先凭证已撤销')).toBeInTheDocument()
  })
  it.each([
    [7000, 0, 0, 7000, 0],
    [7000, 1000, 2500, 3500, 50],
    [7000, 0, 7000, 0, 100],
    [0, 0, 0, 0, 0],
  ])('shows occupied refund budget with yuan units for limit=%s reserved=%s committed=%s', (limit, reserved, committed, remaining, percent) => {
    const value = { ...workflowSnapshot, credentials: [credential({ budgets: [
      { quota_type: 'refund_total_fen', limit, reserved, committed, remaining, version: 2 },
    ] })] }
    render(<AuthorizationExplorer snapshot={value} />)
    const table = screen.getByRole('table')
    expect(within(table).getByText(`已占用 ${((reserved + committed) / 100).toFixed(2)} / ${(limit / 100).toFixed(2)} 元`)).toBeInTheDocument()
    expect(within(table).getByText(`剩余 ${(remaining / 100).toFixed(2)} 元`).parentElement).toHaveTextContent(`剩余 ${(remaining / 100).toFixed(2)} 元 · 预留 ${(reserved / 100).toFixed(2)} 元 · 已提交 ${(committed / 100).toFixed(2)} 元`)
    expect(within(table).getByRole('progressbar')).toHaveAttribute('aria-valuenow', String(percent))
  })

})
