import type { CredentialView, RuntimeProfiles, TaskSnapshot, WorkflowEvent } from '../types'

// All signatures, validity flags and hashes below are display mocks, not cryptographic verification evidence.
export const rootCredential: CredentialView = {
  credential_id: 'cred-root-test', credential_type: 'ROOT', parent_credential_id: null, parent_credential_hash: null,
  signed_object_hash: 'a'.repeat(64), stored_hash_valid: true, issuer_subject_id: 'authorization-authority',
  source_verification: { schema_version: '1.0', profile: 'CREDENTIAL_ROW_BINDING_V1', schema_valid: true,
    stored_hash_valid: true, row_binding_valid: true, execution_binding_valid: null },
  issuer_key_id: 'auth-key-01', holder_agent_id: 'agent-coordinator', holder_key_id: 'agent-coordinator-key-01',
  not_before: 1790000000, expires_at: 1790001800, delegation_depth: 2, issued_at: 1790000000,
  revoked_at: null, revocation_reason: null,
  capabilities: [{ tool: 'refund.create', service: 'refund-service', version: 'v1' }],
  budgets: [{ quota_type: 'refund_total_fen', limit: 7000, reserved: 0, committed: 0, remaining: 7000, version: 0 }],
  signature: { algorithm: 'SM2', key_id: 'auth-key-01', fingerprint_sm3: 'b'.repeat(24), valid: true },
}

export const savedSnapshot: TaskSnapshot = {
  task: { task_id: 'TASK-history-test', tenant_id: 'tenant-A', ticket_id: 'T10086', customer_id: 'C9527',
    refund_total_fen: 7000, max_tool_calls: 4, expires_at: 1790001800, status: 'AUTHORIZED', created_at: 1790000000, updated_at: 1790000000 },
  credentials: [rootCredential],
  executions: [{ execution_id: 'execution-denied', request_hash: 'c'.repeat(64), credential_chain_hash: 'd'.repeat(64),
    tool_service: 'refund-service', tool_name: 'refund.create', tool_version: 'v1', parameter_hash: 'e'.repeat(64), state: 'DENIED',
    decision: 'DENY', reason_code: 'PARAMETER_CONSTRAINT_VIOLATION', receipt_status: 'SIGNED', business_action_id: 'action-01',
    business_effect_id: null, business_result_hash: null, created_at: 1790000001, updated_at: 1790000002 }],
  receipts: [{ receipt_id: 'receipt-denied', execution_id: 'execution-denied', receipt_type: 'AUTHORIZATION_DENIAL', decision: 'DENY',
    reason_code: 'PARAMETER_CONSTRAINT_VIOLATION', receipt_hash: 'f'.repeat(64), receipt_status: 'SIGNED', created_at: 1790000002,
    source_verification: { schema_version: '1.0', profile: 'RECEIPT_EXECUTION_BINDING_V1', schema_valid: true,
      stored_hash_valid: true, row_binding_valid: true, execution_binding_valid: true },
    signature: { algorithm: 'SM2', key_id: 'receipt-key-01', fingerprint_sm3: 'a'.repeat(24), valid: true } }],
  business_effects: { refunds: [], notifications: [] },
  audit_events: [{ schema_version: '1.0', event_sequence: 10, event_id: 'audit-denied', execution_id: 'execution-denied', event_type: 'AUTHORIZATION_DENIED',
    timestamp: 1790000002, payload_hash: 'a'.repeat(64), evidence_reference: 'request-01', previous_event_hash: 'b'.repeat(64), event_hash: 'c'.repeat(64),
    coauthorization_evidence: null, evidence_binding_valid: null }],
}

export const runtimeProfiles: RuntimeProfiles = {
  workflow_enabled: true,
  items: [
    { mode: 'deterministic', label: '确定性规则', provider: 'rules', available: true, model: null, verification: 'fixed_rules', message: '规则规划，无模型调用' },
    { mode: 'cloud', label: '智能体审查', provider: 'deepseek', available: false, model: 'deepseek-flash', verification: 'unavailable', message: '云端智能体未配置' },
  ],
}

const workflowActions: Array<[string, string, string, Record<string, unknown>]> = [
  ['agent-coordinator', 'agent_started', 'RUNNING', {}],
  ['agent-coordinator', 'plan', 'COMPLETED', { stage: 'coordinate', summary: '先查询规则，再核验工单。', model_returned: 'deepseek-flash', planner: 'llm' }],
  ['agent-coordinator', 'delegate', 'COMPLETED', { child_agent_id: 'agent-knowledge', credential_id: 'cred-knowledge' }],
  ['agent-knowledge', 'agent_started', 'RUNNING', {}],
  ['agent-knowledge', 'knowledge_result', 'COMPLETED', { output: { documents: [{ document_id: 'doc-1', title: '退款规则', content: '按原路退款。' }] }, original_result_sm3: 'a'.repeat(64), injection_applied: false }],
  ['agent-coordinator', 'delegate', 'COMPLETED', { child_agent_id: 'agent-case', credential_id: 'cred-case' }],
  ['agent-case', 'agent_started', 'RUNNING', {}],
  ['agent-case', 'delegate', 'COMPLETED', { child_agent_id: 'agent-refund', credential_id: 'cred-refund' }],
  ['agent-refund', 'agent_started', 'RUNNING', {}],
  ['agent-refund', 'plan_started', 'RUNNING', { stage: 'refund', input: { authorized_task: { ticket_id: 'T10086', customer_id: 'C9527', refund_amount_fen: 7000 }, knowledge: { documents: [{ document_id: 'doc-1', title: '退款规则', content: '按原路退款。' }] }, ticket: { title: '重复扣款', description: '申请退回多扣金额', customer_id: 'C9527' } } }],
  ['agent-refund', 'plan', 'COMPLETED', { stage: 'refund', summary: '申请退回授权范围内的多扣金额。', model_requested: 'deepseek-flash', model_returned: 'deepseek-flash', planner: 'llm', duration_ms: 123, response_sm3: 'b'.repeat(64), intents: [{ service: 'refund-service', name: 'refund.create', version: 'v1', parameters: { ticket_id: 'T10086', customer_id: 'C9527', amount_fen: 7000 } }] }],
  ['agent-refund', 'gateway_request', 'RUNNING', { tool: 'refund.create', parameters: { amount_fen: 7000 } }],
  ['agent-refund', 'gateway_decision', 'COMPLETED', { tool: 'refund.create', execution_id: 'execution-refund', receipt_id: 'receipt-refund', decision: 'ALLOW', state: 'COMMITTED' }],
  ['agent-refund', 'agent_finished', 'COMPLETED', {}],
  ['agent-case', 'agent_finished', 'COMPLETED', {}],
  ['agent-knowledge', 'agent_finished', 'COMPLETED', {}],
  ['agent-coordinator', 'agent_finished', 'COMPLETED', {}],
]

export const workflowEvents: WorkflowEvent[] = workflowActions.map(([agent_id, action, status, details], index) => ({
  sequence: index + 1, agent_id, action, status, details,
  timestamp_ms: 1790000000000 + index * 100, recorded_at_ms: 1790000000000 + index * 100 + 5,
}))

export const workflowSnapshot: TaskSnapshot = {
  ...savedSnapshot,
  credentials: [rootCredential, ...(['knowledge', 'case', 'refund'] as const).map((role) => ({
    ...rootCredential, credential_id: `cred-${role}`, credential_type: 'DELEGATION' as const,
    holder_agent_id: `agent-${role}`, holder_key_id: `agent-${role}-key-01`,
    parent_credential_id: role === 'refund' ? 'cred-case' : rootCredential.credential_id,
    delegation_depth: role === 'refund' ? 0 : 1,
  }))],
  executions: [{ ...savedSnapshot.executions[0], execution_id: 'execution-refund', state: 'COMMITTED', decision: 'ALLOW', reason_code: null, business_effect_id: 'refund-1' }],
  receipts: [{ ...savedSnapshot.receipts[0], receipt_id: 'receipt-refund', execution_id: 'execution-refund', decision: 'ALLOW', reason_code: 'ALLOWED', receipt_type: 'EXECUTION_RESULT' }],
  audit_events: [{ ...savedSnapshot.audit_events[0], execution_id: 'execution-refund' }],
  business_effects: { refunds: [{ refund_id: 'refund-1', execution_id: 'execution-refund', amount_fen: 7000, status: 'COMMITTED', created_at: 1790000001 }], notifications: [] },
  business_context: { ticket: { ticket_id: 'T10086', customer_id: 'C9527', title: '重复扣款退款申请', description: '申请退回多扣金额', status: 'OPEN' }, documents: [{ document_id: 'doc-1', title: '退款规则', sensitivity: 'INTERNAL' }] },
  workflow_runs: [{ run_id: 'RUN-fixture', runtime_mode: 'cloud', scenario: 'normal', model: 'deepseek-flash', state: 'COMPLETED', reason_code: null,
    created_at_ms: 1790000000000, updated_at_ms: 1790000002000, deadline_at_ms: 1790000900000, finished_at_ms: 1790000002000,
    observation_kind: 'operational_not_signed_audit', events: workflowEvents }],
}
