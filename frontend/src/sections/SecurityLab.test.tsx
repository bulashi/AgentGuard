import { fireEvent, render, screen } from '@testing-library/react'
import { App } from 'antd'
import { describe, expect, it, vi } from 'vitest'
import { savedSnapshot } from '../test/fixtures'
import type { DemoResult, SecurityMatrix } from '../types'
import { SecurityLab } from './SecurityLab'

const injection: DemoResult = {
  demo_kind: 'LIVE_LLM_INJECTION', task_id: savedSnapshot.task.task_id, planner: 'llm',
  status: 'DENIED', reason_code: 'PARAMETER_CONSTRAINT_VIOLATION', trace: [],
}

describe('SecurityLab evidence boundaries', () => {
  it('does not report a model decline as a gateway denial or gateway chain', () => {
    render(<App><SecurityLab matrix={null} snapshot={savedSnapshot}
      demo={{ ...injection, reason_code: 'PLANNER_DECLINED' }} onDemo={async () => undefined} /></App>)
    expect(screen.getByText('模型停止办理；这不是网关拦截证据')).toBeInTheDocument()
    expect(screen.queryByTestId('gateway-pipeline')).not.toBeInTheDocument()
    expect(screen.queryByText('网关裁决')).not.toBeInTheDocument()
  })
  it('separates direct projection checks from inferred gateway stages', () => {
    const inspect = vi.fn()
    const { container } = render(<App><SecurityLab matrix={null} snapshot={savedSnapshot} demo={injection}
      onDemo={async () => undefined} onInspect={inspect} /></App>)
    expect(screen.getAllByText('推断通过').length).toBeGreaterThan(1)
    expect(screen.getByText('凭证签名与存储哈希')).toBeInTheDocument()
    expect(screen.queryByText('SM2 签名与密钥状态')).not.toBeInTheDocument()
    expect(container.querySelectorAll('.pipeline-row button')).toHaveLength(0)
    fireEvent.click(screen.getByRole('button', { name: /持有者证明/ }))
    expect(inspect).toHaveBeenCalledWith(expect.objectContaining({ kind: 'pipeline',
      value: expect.objectContaining({ state: 'INFERRED_PASS', evidence_type: 'inferred_from_first_failure' }) }))
  })
  it('does not treat a foreign task snapshot as evidence of zero attack effects', () => {
    render(<App><SecurityLab matrix={null} snapshot={savedSnapshot} demo={{ ...injection, task_id: 'foreign-task' }}
      onDemo={async () => undefined} /></App>)
    expect(screen.queryByTestId('gateway-pipeline')).not.toBeInTheDocument()
    expect(screen.getByText('待读取')).toBeInTheDocument()
  })
  it('does not label scenario definitions as executed tests', () => {
    const matrix: SecurityMatrix = { suite: 'security', llm_required: false,
      success_invariant: 'unauthorized_side_effects == 0', scenario_count: 1,
      categories: { binding: 1 }, error_codes: {}, latest_batch: { status: 'SOURCE_CHANGED' },
      scenarios: [{ id: 'wrong_customer', category: 'binding', attacker_capability: 'candidate',
        target_invariant: 'scope', expected_decision: 'DENY', expected_reason_codes: ['RESOURCE_NOT_ALLOWED'],
        expected_business_effects: 0, evidence: [], test_ref: 'test::scenario[wrong_customer]' }] }
    const inspect = vi.fn()
    render(<App><SecurityLab matrix={matrix} snapshot={null} demo={null} onDemo={async () => undefined}
      onInspect={inspect} /></App>)
    expect(screen.getByText('源码已变更，需重新绑定核验批次')).toBeInTheDocument()
    expect(screen.queryByText('36 项逐场景核验')).not.toBeInTheDocument()
    fireEvent.click(screen.getByText('wrong_customer'))
    expect(inspect).toHaveBeenCalledWith(expect.objectContaining({ kind: 'scenario',
      scenario: expect.objectContaining({ test_ref: 'test::scenario[wrong_customer]' }) }))
  })
})
