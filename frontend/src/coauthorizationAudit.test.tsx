import { fireEvent, render, screen, within } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { EvidenceDrawer } from './components/EvidenceDrawer'
import { ExecutionEvidenceRail } from './components/ExecutionEvidenceRail'
import { AuditEvidence } from './sections/AuditEvidence'
import { auditChainIsConsistent, buildExecutionSteps, coauthorizationBindingStatus, coauthorizationRoot, isCoauthorizationAuditEvent, visibleAuditEvents } from './executionModel'
import type { EvidenceSelection } from './executionModel'
import { eventLabel } from './labels'
import { rootCredential, savedSnapshot } from './test/fixtures'
import type { AuditEventView, CoauthorizationApprovalPayload, CoauthorizationBundle, CredentialView, Overview, TaskSnapshot } from './types'

// Synthetic display fixtures only: signatures, hashes and backend validity flags are mocks, not SM2/SM3 proof.
const mockPayload: CoauthorizationApprovalPayload = {
  schema_version: '1.0', payload_type: 'COAUTHORIZATION_TASK_APPROVAL',
  approval_purpose: 'TASK_COAUTHORIZATION_APPROVAL_V1', verifier_audience: 'agentguard-root-authorization',
  tenant_id: savedSnapshot.task.tenant_id, task_id: savedSnapshot.task.task_id,
  ticket_id: savedSnapshot.task.ticket_id, customer_id: savedSnapshot.task.customer_id,
  capabilities_hash: '1'.repeat(64), quotas: { refund_total_fen: 7000, max_tool_calls: 4 },
  holder: { agent_id: rootCredential.holder_agent_id, key_id: rootCredential.holder_key_id },
  not_before: rootCredential.not_before, expires_at: rootCredential.expires_at, delegation_depth: 2,
  policy_revision: 'POLICY-display-mock', challenge_id: 'CHALLENGE-display-mock',
  required_signers: {
    enterprise_approver: { subject_id: 'ENTERPRISE-display-mock', key_id: 'enterprise-mock-key' },
    finance_approver: { subject_id: 'FINANCE-display-mock', key_id: 'finance-mock-key' },
  },
  approval_not_before: rootCredential.not_before, approval_expires_at: rootCredential.not_before + 300,
}
const mockBundle: CoauthorizationBundle = {
  payload: mockPayload,
  approvals: (['ENTERPRISE_APPROVER', 'FINANCE_APPROVER'] as const).map((role) => {
    const signer = role === 'ENTERPRISE_APPROVER' ? mockPayload.required_signers.enterprise_approver : mockPayload.required_signers.finance_approver
    return {
      statement: { schema_version: '1.0', statement_type: 'COAUTHORIZATION_APPROVAL_STATEMENT',
        approval_purpose: 'TASK_COAUTHORIZATION_APPROVAL_V1', approval_payload_hash: '2'.repeat(64),
        role, subject_id: signer.subject_id, key_id: signer.key_id, approved_at: rootCredential.issued_at },
      signature: { algorithm: 'SM2', key_id: signer.key_id, key_purpose: 'AUTHORIZATION_ROOT_SIGNING',
        encoding: 'SM2_RS_HEX_128_LOWERCASE', value: '3'.repeat(128), signed_at: rootCredential.issued_at },
    }
  }),
}
const mockEvidence: Record<string, unknown> = {
  schema_version: '1.0', record_type: 'COAUTH_ROOT_AUTHORIZED_V1',
  tenant_id: mockPayload.tenant_id, task_id: mockPayload.task_id, challenge_id: mockPayload.challenge_id,
  policy_revision: mockPayload.policy_revision, approval_payload_hash: '2'.repeat(64),
  bundle_hash: '4'.repeat(64), signed_bundle: mockBundle,
  root_credential_id: rootCredential.credential_id, root_credential_hash: rootCredential.signed_object_hash,
  credential: {
    payload: {
      schema_version: '1.0', credential_id: rootCredential.credential_id, credential_type: 'ROOT',
      issuer: { subject_id: rootCredential.issuer_subject_id, key_id: rootCredential.issuer_key_id },
      holder: mockPayload.holder, tenant_id: mockPayload.tenant_id, task_id: mockPayload.task_id,
      verifier_audience: 'secure-tool-gateway',
      capabilities: [{ ...rootCredential.capabilities[0], resources: { ticket_ids: [mockPayload.ticket_id], customer_ids: [mockPayload.customer_id] }, constraints: {} }],
      quotas: mockPayload.quotas, not_before: mockPayload.not_before, expires_at: mockPayload.expires_at,
      delegation_depth: mockPayload.delegation_depth, parent_credential_id: null, parent_credential_hash: null,
      issued_at: rootCredential.issued_at,
    },
    signature: { algorithm: 'SM2', key_id: rootCredential.issuer_key_id, key_purpose: 'AUTHORIZATION_ROOT_SIGNING',
      encoding: 'SM2_RS_HEX_128_LOWERCASE', value: '5'.repeat(128), signed_at: rootCredential.issued_at },
  },
  authorized_at: rootCredential.issued_at,
}
const mockEvent: AuditEventView = {
  ...savedSnapshot.audit_events[0], schema_version: '2.0', event_sequence: 9, event_id: 'audit-coauth-display-mock',
  execution_id: null, event_type: 'COAUTH_ROOT_AUTHORIZED', timestamp: rootCredential.issued_at,
  evidence_reference: rootCredential.credential_id, coauthorization_evidence: mockEvidence, evidence_binding_valid: true,
}
const mockSnapshot: TaskSnapshot = { ...savedSnapshot, audit_events: [mockEvent, ...savedSnapshot.audit_events] }

function mockAuditOverview(checkpointEnd: number | null, verification: Partial<Overview['audit']['verification']> = {}): Overview {
  return {
    tasks: {}, executions: [], business_effects: { refunds: 0, notifications: 0 },
    audit: {
      pending_outbox: 0, latest_event_sequence: 10, latest_event_hash: '6'.repeat(64), updated_at: rootCredential.issued_at + 2,
      verification: { valid: true, checked_events: 10, latest_event_sequence: 10, rollback_detected: false, first_invalid_sequence: null, ...verification },
      checkpoint: { status: checkpointEnd === null ? 'EMPTY' : 'AVAILABLE', checkpoint: checkpointEnd === null ? null : {
        payload: { checkpoint_sequence: 1, latest_event_sequence: checkpointEnd, latest_event_hash: '7'.repeat(64), timestamp: rootCredential.issued_at + 1 },
        signature: { algorithm: 'SM2', key_id: 'checkpoint-display-mock', fingerprint_sm3: '8'.repeat(24) },
      } },
    },
  }
}

const checkpointCases: Array<{ name: string; overview: Overview | null }> = [
  { name: 'older checkpoint', overview: mockAuditOverview(8) },
  { name: 'checkpoint ending at the event', overview: mockAuditOverview(9) },
  { name: 'checkpoint ending at the report tail', overview: mockAuditOverview(10) },
  { name: 'missing checkpoint', overview: mockAuditOverview(null) },
  { name: 'missing overview', overview: null },
  { name: 'checkpoint newer than verification', overview: mockAuditOverview(11) },
  { name: 'failed verification', overview: mockAuditOverview(10, { valid: false }) },
  { name: 'truthy non-boolean verification', overview: mockAuditOverview(10, { valid: 'true' as unknown as boolean }) },
  { name: 'omitted rollback result', overview: mockAuditOverview(10, { rollback_detected: undefined as unknown as boolean }) },
  { name: 'detected rollback', overview: mockAuditOverview(10, { rollback_detected: true }) },
  { name: 'reported invalid event', overview: mockAuditOverview(10, { first_invalid_sequence: 9 }) },
]

describe('coauthorization audit display with synthetic fixtures', () => {
  it('labels the stored event in Chinese and assigns it to authorization without an execution', () => {
    expect(eventLabel(mockEvent.event_type)).toBe('共同审批根授权')
    const step = buildExecutionSteps(mockSnapshot, null).find((item) => item.id === 'audit-9')
    expect(step).toMatchObject({ title: '共同审批根授权', subtitle: '根授权 · #9', stage: 'authorization', status: 'RECORDED',
      selection: { kind: 'audit', event: { execution_id: null } } })
    expect(step?.subtitle).not.toContain(savedSnapshot.executions[0].execution_id)
    expect(step?.stage).not.toBe('gateway')
    expect(step?.stage).not.toBe('tools')
  })

  it('does not let a null audit association hide an actual unaudited execution', () => {
    const steps = buildExecutionSteps({ ...mockSnapshot, audit_events: [mockEvent] }, null)
    expect(steps.find((step) => step.id === `execution-${savedSnapshot.executions[0].execution_id}`)).toBeDefined()
    expect(steps.filter((step) => step.selection.kind === 'execution')).toHaveLength(1)
  })

  it('preserves v1 denial steps and nullable evidence fields', async () => {
    const event = savedSnapshot.audit_events[0]
    expect(event).toMatchObject({ schema_version: '1.0', coauthorization_evidence: null, evidence_binding_valid: null })
    const steps = buildExecutionSteps(savedSnapshot, null)
    expect(steps).toHaveLength(4)
    expect(steps.find((step) => step.id === 'audit-10')).toMatchObject({ title: '授权被拒绝', stage: 'gateway', status: 'DENIED' })
    const inspect = vi.fn()
    render(<EvidenceDrawer selection={{ kind: 'audit', event }} snapshot={savedSnapshot} overview={null} onSelect={inspect} onClose={vi.fn()} />)
    const detail = await screen.findByTestId('evidence-detail')
    expect(within(detail).getByText('1.0')).toBeInTheDocument()
    expect(within(detail).queryByText('共同审批证据')).not.toBeInTheDocument()
    fireEvent.click(within(detail).getByRole('tab', { name: '关联记录' }))
    fireEvent.click(within(detail).getByRole('button', { name: /创建退款/ }))
    expect(inspect).toHaveBeenCalledWith({ kind: 'execution', execution: savedSnapshot.executions[0] })
  })

  it.each([
    { valid: true, evidence: mockEvidence, status: 'BINDING_CHECKED', label: '已核对' },
    { valid: false, evidence: mockEvidence, status: 'INVALID', label: '无效' },
    { valid: null, evidence: mockEvidence, status: 'NOT_CHECKED', label: '未核对' },
    { valid: true, evidence: null, status: 'NOT_CHECKED', label: '未核对' },
    { valid: null, evidence: null, status: 'NOT_CHECKED', label: '未核对' },
  ])('limits the mock binding status $status to structure and digest checks', async ({ valid, evidence, status, label }) => {
    const event: AuditEventView = { ...mockEvent, evidence_binding_valid: valid, coauthorization_evidence: evidence }
    expect(coauthorizationBindingStatus(event)).toBe(status)
    render(<EvidenceDrawer selection={{ kind: 'audit', event }} snapshot={{ ...mockSnapshot, audit_events: [event, ...savedSnapshot.audit_events] }} overview={null} onSelect={vi.fn()} onClose={vi.fn()} />)
    const detail = await screen.findByTestId('evidence-detail')
    if (valid === null) {
      expect(isCoauthorizationAuditEvent(event)).toBe(false)
      expect(within(detail).queryByText('共同审批证据')).not.toBeInTheDocument()
    } else {
      expect(isCoauthorizationAuditEvent(event)).toBe(true)
      expect(within(detail).getByText('结构与摘要绑定核对')).toBeInTheDocument()
      expect(within(detail).getByLabelText(`${label}（${status}）`)).toBeInTheDocument()
      expect(within(detail).getByText('未复验审批 SM2 签名及当前审批主体信任')).toBeInTheDocument()
      expect(within(detail).queryByText(/^(通过|已验证|有效|已锚定)$/)).not.toBeInTheDocument()
    }
    const step = buildExecutionSteps({ ...mockSnapshot, audit_events: [event] }, null).find((item) => item.id === 'audit-9')
    expect(step?.status).toBe(valid === false ? 'INVALID' : 'RECORDED')
  })

  it('shows both versions, challenge, policy and complete public evidence and links the referenced snapshot ROOT', async () => {
    const snapshot: TaskSnapshot = { ...mockSnapshot, credentials: [{ ...rootCredential, credential_id: 'unrelated-root' }, rootCredential] }
    const inspect = vi.fn()
    render(<EvidenceDrawer selection={{ kind: 'audit', event: mockEvent }} snapshot={snapshot} overview={null} onSelect={inspect} onClose={vi.fn()} />)
    const detail = await screen.findByTestId('evidence-detail')
    expect(within(detail).getByText('共同审批根授权')).toBeInTheDocument()
    expect(within(detail).getByText('2.0')).toBeInTheDocument()
    expect(within(detail).getByText('1.0')).toBeInTheDocument()
    expect(within(detail).getByText('COAUTH_ROOT_AUTHORIZED_V1')).toBeInTheDocument()
    expect(within(detail).getByText('无执行关联')).toBeInTheDocument()
    expect(within(detail).getByLabelText(mockPayload.challenge_id)).toBeInTheDocument()
    expect(within(detail).getByText(mockPayload.policy_revision)).toBeInTheDocument()
    expect(within(detail).getByText('审批载荷哈希')).toBeInTheDocument()
    expect(within(detail).getByText('审批包哈希')).toBeInTheDocument()
    expect(within(detail).getByText('根凭证哈希')).toBeInTheDocument()
    expect(JSON.parse(within(detail).getByTestId('coauthorization-evidence-json').textContent ?? 'null')).toEqual(mockEvidence)
    fireEvent.click(within(detail).getByRole('button', { name: /根授权 · 协调智能体/ }))
    expect(inspect).toHaveBeenCalledWith({ kind: 'credential', credential: rootCredential })
    expect(within(detail).queryByRole('tab', { name: '关联记录' })).not.toBeInTheDocument()
    expect(within(detail).queryByRole('button', { name: /创建退款/ })).not.toBeInTheDocument()
    fireEvent.click(within(detail).getByRole('tab', { name: '投影 JSON' }))
    expect(JSON.parse(within(detail).getByTestId('evidence-json').textContent ?? 'null')).toMatchObject({ event: mockEvent, verifier_report: null })
  })

  it.each(['missing-reference', 'delegation', 'no-snapshot'] as const)('does not manufacture a ROOT link for %s', async (kind) => {
    const event: AuditEventView = { ...mockEvent, evidence_reference: kind === 'missing-reference' ? 'absent-root' : mockEvent.evidence_reference }
    const credential: CredentialView = { ...rootCredential, credential_type: kind === 'delegation' ? 'DELEGATION' : 'ROOT' }
    const snapshot = kind === 'no-snapshot' ? null : { ...mockSnapshot, credentials: [credential], audit_events: [event, ...savedSnapshot.audit_events] }
    expect(coauthorizationRoot(event, snapshot?.credentials ?? [])).toBeUndefined()
    render(<EvidenceDrawer selection={{ kind: 'audit', event }} snapshot={snapshot} overview={null} onSelect={vi.fn()} onClose={vi.fn()} />)
    const detail = await screen.findByTestId('evidence-detail')
    expect(within(detail).getByText(kind === 'no-snapshot' ? '当前任务快照无法唯一关联所选记录' : '当前快照无匹配根凭证')).toBeInTheDocument()
    expect(within(detail).queryByRole('button', { name: /根授权 ·/ })).not.toBeInTheDocument()
  })

  it('does not link a ROOT when the event evidence hash differs from the current stored object', () => {
    const event: AuditEventView = {
      ...mockEvent,
      coauthorization_evidence: { ...mockEvidence, root_credential_hash: 'f'.repeat(64) },
    }
    expect(coauthorizationRoot(event, [rootCredential])).toBeUndefined()
  })

  it('refreshes an open approval event and removes its ROOT link when the current binding check fails', async () => {
    const props = { selection: { kind: 'audit' as const, event: mockEvent }, overview: null, onSelect: vi.fn(), onClose: vi.fn() }
    const { rerender } = render(<EvidenceDrawer {...props} snapshot={mockSnapshot} />)
    const detail = await screen.findByTestId('evidence-detail')
    expect(within(detail).getByLabelText('已核对（BINDING_CHECKED）')).toBeInTheDocument()
    const invalid = { ...mockEvent, evidence_binding_valid: false }
    rerender(<EvidenceDrawer {...props} snapshot={{ ...mockSnapshot, audit_events: [invalid, ...savedSnapshot.audit_events] }} />)
    expect(within(detail).getByLabelText('无效（INVALID）')).toBeInTheDocument()
    expect(within(detail).queryByRole('button', { name: /根授权 ·/ })).not.toBeInTheDocument()
    fireEvent.click(within(detail).getByRole('tab', { name: '投影 JSON' }))
    expect(within(detail).getByTestId('evidence-json')).toHaveTextContent('"evidence_binding_valid": false')
    expect(within(detail).getByTestId('evidence-json')).not.toHaveTextContent('"evidence_binding_valid": true')
  })

  it('does not select the first ROOT when its identity is duplicated or the hash-valid flag is not literal true', () => {
    expect(coauthorizationRoot(mockEvent, [rootCredential, { ...rootCredential, signed_object_hash: '0'.repeat(64) }])).toBeUndefined()
    expect(coauthorizationRoot(mockEvent, [{ ...rootCredential, stored_hash_valid: 'true' as unknown as boolean }])).toBeUndefined()
  })

  it.each([
    { schema_version: '1.0' as const, execution_id: null },
    { schema_version: '2.0' as const, execution_id: 'EXEC-UNEXPECTED' },
  ])('does not classify malformed coauthorization event metadata as a root authorization', (metadata) => {
    const event: AuditEventView = { ...mockEvent, ...metadata }
    expect(isCoauthorizationAuditEvent(event)).toBe(false)
    expect(coauthorizationRoot(event, [rootCredential])).toBeUndefined()
    expect(buildExecutionSteps({ ...mockSnapshot, audit_events: [event] }, null)
      .find((step) => step.id === 'audit-9')?.stage).toBe('gateway')
  })

  it('does not classify an older projection that omits the binding result', () => {
    const event: Partial<AuditEventView> = { ...mockEvent }
    delete event.evidence_binding_valid
    expect(isCoauthorizationAuditEvent(event as AuditEventView)).toBe(false)
    expect(coauthorizationRoot(event as AuditEventView, [rootCredential])).toBeUndefined()
  })

  it('keeps unassociated approval events hidden in replay until their actual ROOT is visible', () => {
    expect(visibleAuditEvents(mockSnapshot, [], savedSnapshot.executions, true)).toEqual(savedSnapshot.audit_events)
    expect(visibleAuditEvents(mockSnapshot, [rootCredential], [], true)).toEqual([mockEvent])
    expect(visibleAuditEvents(mockSnapshot, [{ ...rootCredential, credential_id: 'future-root' }], [], true)).toEqual([])
    expect(visibleAuditEvents(mockSnapshot, [{ ...rootCredential, credential_type: 'DELEGATION' }], [], true)).toEqual([])
    expect(visibleAuditEvents(mockSnapshot, [], [], false)).toEqual(mockSnapshot.audit_events)
    const unassociated: AuditEventView = { ...savedSnapshot.audit_events[0], execution_id: null, event_type: 'RAW_REQUEST_REJECTED' }
    expect(visibleAuditEvents({ ...savedSnapshot, audit_events: [unassociated] }, [rootCredential], savedSnapshot.executions, true)).toEqual([])
    expect(visibleAuditEvents(null, [], [], true)).toEqual([])
  })

  it('counts the visible approval as audit evidence without counting a tool allowance or a valid receipt', () => {
    const inspect = vi.fn()
    render(<ExecutionEvidenceRail snapshot={mockSnapshot} events={[]} credentials={[rootCredential]} executions={[]} replay onInspect={inspect} />)
    expect(screen.getByTestId('evidence-rail-gateway')).toHaveTextContent('0 允许 / 0 拒绝')
    expect(screen.getByTestId('evidence-rail-business')).toHaveTextContent('0 笔退款')
    expect(screen.getByTestId('evidence-rail-evidence')).toHaveTextContent('0 / 0 回执核对一致')
    expect(screen.getByTestId('evidence-rail-evidence')).toHaveTextContent('1 条审计事件')
    fireEvent.click(screen.getByTestId('evidence-rail-evidence'))
    expect(inspect).toHaveBeenCalledWith({ kind: 'stage', stage: 'evidence', auditEvents: [mockEvent] })
  })

  it.each(['authorization', 'evidence'] as const)('does not reveal future approval events when opening replay stage %s', async (stage) => {
    const inspect = vi.fn<(selection: EvidenceSelection) => void>()
    const { rerender } = render(<ExecutionEvidenceRail snapshot={mockSnapshot} events={[]} credentials={[]} executions={[]} replay onInspect={inspect} />)
    expect(screen.getByTestId('evidence-rail-evidence')).toHaveTextContent('0 条审计事件')
    fireEvent.click(screen.getByTestId(`evidence-rail-${stage}`))
    expect(inspect).toHaveBeenCalledWith({ kind: 'stage', stage, auditEvents: [] })
    rerender(<EvidenceDrawer selection={inspect.mock.calls[0][0]} snapshot={mockSnapshot} overview={null} onSelect={vi.fn()} onClose={vi.fn()} />)
    const detail = await screen.findByTestId('evidence-detail')
    expect(within(detail).queryByRole('button', { name: /共同审批根授权/ })).not.toBeInTheDocument()
    fireEvent.click(within(detail).getByRole('tab', { name: '投影 JSON' }))
    expect(within(detail).getByTestId('evidence-json')).not.toHaveTextContent('COAUTH_ROOT_AUTHORIZED')
    expect(within(detail).getByTestId('evidence-json')).not.toHaveTextContent(mockPayload.challenge_id)
  })

  it('opens audit details from the Chinese table row without making it a successful execution', () => {
    const inspect = vi.fn()
    render(<AuditEvidence snapshot={mockSnapshot} overview={null} onInspect={inspect} />)
    const label = screen.getByText('共同审批根授权')
    const row = label.closest('tr')!
    expect(within(row).getByText('无执行关联')).toBeInTheDocument()
    fireEvent.click(label)
    expect(inspect).toHaveBeenCalledWith({ kind: 'audit', event: mockEvent })
    fireEvent.click(screen.getByText('成功执行'))
    expect(screen.getByText('当前任务暂无匹配执行证据')).toBeInTheDocument()
    expect(screen.getByText('共同审批根授权')).toBeInTheDocument()
    expect(screen.queryByText('审计哈希链（Hash Chain）与独立检查点一致')).not.toBeInTheDocument()
  })

  it.each(checkpointCases)('does not infer precise event coverage from separate overview reads for $name', async ({ overview }) => {
    render(<>
      <AuditEvidence snapshot={mockSnapshot} overview={overview} onInspect={vi.fn()} />
      <EvidenceDrawer selection={{ kind: 'audit', event: mockEvent }} snapshot={mockSnapshot} overview={overview} onSelect={vi.fn()} onClose={vi.fn()} />
    </>)
    const rowLabel = within(screen.getByTestId('audit-evidence')).getByText('共同审批根授权')
    expect(rowLabel).toHaveAttribute('title', expect.stringContaining('结构与摘要绑定核对：已核对'))
    expect(rowLabel).toHaveAttribute('title', expect.stringContaining('逐事件覆盖未核验'))
    const detail = await screen.findByTestId('evidence-detail')
    expect(within(detail).getByLabelText('已核对（BINDING_CHECKED）')).toBeInTheDocument()
    expect(within(detail).getByLabelText('逐事件覆盖未核验（NOT_CHECKED）')).toBeInTheDocument()
    expect(within(detail).getByText('未复验审批 SM2 签名及当前审批主体信任')).toBeInTheDocument()
    expect(within(detail).queryByText('已验证')).not.toBeInTheDocument()
    expect(within(detail).queryByLabelText('已锚定（ANCHORED）')).not.toBeInTheDocument()
  })

  it('reports chain consistency and the old checkpoint end without claiming the approval tail is anchored', () => {
    render(<AuditEvidence snapshot={mockSnapshot} overview={mockAuditOverview(8)} onInspect={vi.fn()} />)
    expect(screen.getByText('审计哈希链（Hash Chain）报告自洽')).toBeInTheDocument()
    expect(screen.getByText('另读检查点末序号')).toBeInTheDocument()
    expect(screen.getByText('已检查 10 个事件 · 核对末事件序号 10')).toBeInTheDocument()
    expect(screen.getByText('共同审批根授权')).toHaveAttribute('title', expect.stringContaining('逐事件覆盖未核验'))
    expect(screen.getByText('共同审批根授权')).not.toHaveAttribute('title', expect.stringContaining('已锚定'))
    expect(screen.queryByText('审计哈希链（Hash Chain）与独立检查点一致')).not.toBeInTheDocument()
  })

  it.each([
    { valid: 'true' as unknown as boolean },
    { rollback_detected: undefined as unknown as boolean },
    { rollback_detected: true },
    { first_invalid_sequence: mockEvent.event_sequence },
  ])('does not display an incomplete or contradictory verification result as a consistent chain', (verification) => {
    render(<AuditEvidence snapshot={mockSnapshot} overview={mockAuditOverview(10, verification)} onInspect={vi.fn()} />)
    expect(screen.queryByText('审计哈希链（Hash Chain）报告自洽')).not.toBeInTheDocument()
    expect(screen.getByText('审计核对失败或结果不完整')).toBeInTheDocument()
    expect(screen.getByText('共同审批根授权')).not.toHaveAttribute('title', expect.stringContaining('已锚定'))
  })

  it.each([
    { valid: 'true' as unknown as boolean },
    { rollback_detected: undefined as unknown as boolean },
    { rollback_detected: true },
    { first_invalid_sequence: mockEvent.event_sequence },
  ])('keeps the shared consistency verdict and the evidence drawer nonpositive for incomplete verification', async (verification) => {
    const overview = mockAuditOverview(10, verification)
    expect(auditChainIsConsistent(overview)).toBe(false)
    expect(auditChainIsConsistent(null)).toBe(false)
    render(<EvidenceDrawer selection={{ kind: 'stage', stage: 'evidence' }} snapshot={mockSnapshot}
      overview={overview} onSelect={vi.fn()} onClose={vi.fn()} />)
    const detail = await screen.findByTestId('evidence-detail')
    const field = within(detail).getByText('审计链自洽核对').closest('tr')!
    expect(within(field).getByLabelText('投影不完整（INCOMPLETE）')).toBeInTheDocument()
    expect(within(field).queryByLabelText('有效（VALID）')).not.toBeInTheDocument()
  })

  it('keeps chain verification and checkpoint coverage separate in evidence stage details', async () => {
    render(<EvidenceDrawer selection={{ kind: 'stage', stage: 'evidence' }} snapshot={mockSnapshot} overview={mockAuditOverview(8)} onSelect={vi.fn()} onClose={vi.fn()} />)
    const detail = await screen.findByTestId('evidence-detail')
    expect(within(detail).getByText('审计链自洽核对')).toBeInTheDocument()
    expect(within(detail).getByText('核对末事件序号')).toBeInTheDocument()
    expect(within(detail).getByText('本次实际检查点')).toBeInTheDocument()
    expect(within(detail).queryByText('独立全链验证')).not.toBeInTheDocument()
    expect(within(detail).queryByLabelText('已锚定（ANCHORED）')).not.toBeInTheDocument()
  })
})
