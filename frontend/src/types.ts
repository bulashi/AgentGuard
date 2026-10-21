import type { BusinessFactsRecord, BusinessVerification } from './api'

export type Decision = 'ALLOW' | 'DENY' | null

export interface CoauthorizationStatus {
  schema_version: '1.0'
  enabled: boolean
  policy_source: 'SERVER_REGISTERED_PUBLIC_KEYS'
  signing: 'EXTERNAL_APPROVERS_ONLY'
}

export interface CoauthorizationCapability {
  service: string
  tool: string
  version: string
  resources: { ticket_ids?: string[]; customer_ids?: string[] }
  constraints: { single_max_fen?: number; template_ids?: string[] }
}

export interface CoauthorizationApprovalPayload {
  schema_version: '1.0'
  payload_type: 'COAUTHORIZATION_TASK_APPROVAL'
  approval_purpose: 'TASK_COAUTHORIZATION_APPROVAL_V1'
  verifier_audience: 'agentguard-root-authorization'
  tenant_id: string
  task_id: string
  ticket_id: string
  customer_id: string
  capabilities_hash: string
  quotas: { refund_total_fen: number; max_tool_calls: number }
  holder: { agent_id: string; key_id: string }
  not_before: number
  expires_at: number
  delegation_depth: number
  policy_revision: string
  challenge_id: string
  required_signers: {
    enterprise_approver: { subject_id: string; key_id: string }
    finance_approver: { subject_id: string; key_id: string }
  }
  approval_not_before: number
  approval_expires_at: number
}

export interface CoauthorizationChallenge {
  schema_version: '1.0'
  challenge_status: 'PENDING'
  payload: CoauthorizationApprovalPayload
  approval_payload_hash: string
  task_capabilities: CoauthorizationCapability[]
  signature_domain: 'AGENTGUARD|TASK_COAUTHORIZATION_APPROVAL|V1'
}

export interface CoauthorizationBundle {
  payload: CoauthorizationApprovalPayload
  approvals: Array<{
    statement: {
      schema_version: '1.0'
      statement_type: 'COAUTHORIZATION_APPROVAL_STATEMENT'
      approval_purpose: 'TASK_COAUTHORIZATION_APPROVAL_V1'
      approval_payload_hash: string
      role: 'ENTERPRISE_APPROVER' | 'FINANCE_APPROVER'
      subject_id: string
      key_id: string
      approved_at: number
    }
    signature: {
      algorithm: 'SM2'
      key_id: string
      key_purpose: 'AUTHORIZATION_ROOT_SIGNING'
      encoding: 'SM2_RS_HEX_128_LOWERCASE'
      value: string
      signed_at: number
    }
  }>
}

export interface CoauthorizationHistoryEntry {
  challenge_id: string
  challenge_status: 'PENDING' | 'CONSUMED' | 'REVOKED'
  window_state: 'NOT_YET_VALID' | 'OPEN' | 'EXPIRED'
  issued_at: number
  expires_at: number
  consumed_at: number | null
  revoked_at: number | null
  payload: CoauthorizationApprovalPayload
  approval_payload_hash: string
  task_capabilities: CoauthorizationCapability[]
  bundle_hash: string | null
  signed_bundle: CoauthorizationBundle | null
  root_credential_id: string | null
  root_credential_hash: string | null
}

export interface CoauthorizationTaskReview {
  schema_version: '1.0'
  observation_kind: 'STORED_EVIDENCE_NOT_REVALIDATED'
  task_id: string
  task_status: 'PENDING_AUTHORIZATION' | 'AUTHORIZED' | 'CLOSED'
  observed_at: number
  offset: number
  limit: 20
  has_more: boolean
  items: CoauthorizationHistoryEntry[]
  signature_domain: 'AGENTGUARD|TASK_COAUTHORIZATION_APPROVAL|V1'
}

export interface CoauthorizationResult {
  schema_version: '1.0'
  challenge_id: string
  approval_payload_hash: string
  bundle_hash: string
  root_credential_id: string
  root_credential_hash: string
  reused: boolean
  credential: Record<string, unknown>
}

export interface Overview {
  tasks: Record<string, number>
  executions: Array<{ decision: string; state: string; count: number }>
  business_effects: { refunds: number; notifications: number }
  audit: {
    pending_outbox: number
    latest_event_sequence: number
    latest_event_hash: string
    updated_at: number
    verification: {
      valid: boolean
      checked_events: number
      latest_event_sequence: number
      rollback_detected: boolean
      first_invalid_sequence: number | null
    }
    checkpoint: {
      status: 'EMPTY' | 'AVAILABLE'
      checkpoint: {
        payload: {
          checkpoint_sequence: number
          latest_event_sequence: number
          latest_event_hash: string
          timestamp: number
        }
        signature: { algorithm: string; key_id: string; fingerprint_sm3: string | null }
      } | null
    }
  }
}

export interface TaskSummary {
  task_id: string
  tenant_id: string
  ticket_id: string
  customer_id: string
  refund_total_fen: number
  max_tool_calls: number
  expires_at: number
  status: string
  created_at: number
  updated_at: number
  credential_count: number
  execution_count: number
  workflow_state?: string | null
  workflow_reason_code?: string | null
  runtime_mode?: RuntimeMode | null
  model?: string | null
  business_verification_status?: string | null
  business_payment_verification_status?: string | null
  refund_count?: number
  notification_count?: number
}

export interface BudgetState {
  quota_type: string
  limit: number
  reserved: number
  committed: number
  remaining: number
  version: number
}

export interface SourceVerification {
  schema_version: '1.0'
  profile: 'CREDENTIAL_ROW_BINDING_V1' | 'RECEIPT_EXECUTION_BINDING_V1'
  schema_valid: boolean
  stored_hash_valid: boolean
  row_binding_valid: boolean
  execution_binding_valid: boolean | null
}

export interface CredentialView {
  credential_id: string
  credential_type: 'ROOT' | 'DELEGATION'
  parent_credential_id: string | null
  parent_credential_hash: string | null
  signed_object_hash: string
  stored_hash_valid: boolean
  source_verification?: SourceVerification
  issuer_subject_id: string
  issuer_key_id: string
  holder_agent_id: string
  holder_key_id: string
  not_before: number
  expires_at: number
  delegation_depth: number
  issued_at: number
  revoked_at: number | null
  revocation_reason: string | null
  revoked_by?: string | null
  capabilities: Array<{
    tool: string; service: string; version: string
    resources?: { ticket_ids?: string[]; customer_ids?: string[]; document_ids?: string[] }
    constraints?: { single_max_fen?: number; template_ids?: string[] }
  }>
  budgets: BudgetState[]
  signature: {
    algorithm: string
    key_id: string
    fingerprint_sm3: string
    valid: boolean
  }
}

export interface ExecutionView {
  execution_id: string
  request_hash: string
  credential_chain_hash: string
  tool_service: string
  tool_name: string
  tool_version: string
  parameter_hash: string
  state: string
  decision: Decision
  reason_code: string | null
  receipt_status: string
  business_action_id: string | null
  business_effect_id: string | null
  business_result_hash: string | null
  created_at: number
  updated_at: number
}

export interface ReceiptView {
  receipt_id: string
  execution_id: string
  receipt_type: string
  decision: Exclude<Decision, null>
  reason_code: string
  receipt_hash: string
  receipt_status: string
  created_at: number
  source_verification?: SourceVerification
  signature: {
    algorithm: string
    key_id: string
    fingerprint_sm3: string
    valid: boolean
  }
}

export interface AuditEventView {
  schema_version: '1.0' | '2.0' | '3.0' | '4.0'
  event_sequence: number
  event_id: string
  execution_id: string | null
  event_type: string
  timestamp: number
  payload_hash: string
  evidence_reference: string
  previous_event_hash: string
  event_hash: string
  coauthorization_evidence: Record<string, unknown> | null
  revocation_evidence?: Record<string, unknown> | null
  credential_revocation_evidence?: Record<string, unknown> | null
  // v3 requires a Boolean binding result; legacy unreviewed events may use null.
  evidence_binding_valid: boolean | null
}

export interface TaskSnapshot {
  task: Omit<TaskSummary, 'credential_count' | 'execution_count'>
  credentials: CredentialView[]
  executions: ExecutionView[]
  receipts: ReceiptView[]
  business_effects: {
    refunds: Array<{
      refund_id: string
      execution_id: string
      amount_fen: number
      status: string
      created_at: number
    }>
    notifications: Array<{
      notification_id: string
      execution_id: string
      template_id: string
      customer_id?: string
      template_version?: string
      content?: string
      related_business_effect_id: string
      status: string
      created_at: number
    }>
  }
  audit_events: AuditEventView[]
  dispatch_cancellations?: Array<{
    cancellation_id: string
    execution_id: string
    denial_execution_id: string
    request_id: string
    request_hash: string
    credential_chain_hash: string
    reason_code: string
    cancelled_at: number
    evidence: Record<string, unknown>
  }>
  business_context?: {
    ticket: {
      ticket_id: string; customer_id: string; title: string; description: string; status: string
      tenant_id?: string
      cloud_shareable?: boolean
      verification_status?: 'VERIFIED' | 'PENDING' | 'REJECTED' | 'UNKNOWN'
      payment_verification_status?: 'VERIFIED' | 'PENDING' | 'REJECTED' | 'UNKNOWN'
      original_transaction_id?: string | null
      refund_reason_code?: string | null
      refundable_amount_fen?: number | null
      evidence_reference?: string | null
      transaction_remaining_fen?: number | null
      already_processed?: boolean
      in_progress?: boolean
      can_refund?: boolean
      refund_verifications?: TrustedRefundVerification[]
      source?: string
      business_facts?: BusinessFactsRecord
      facts_hash?: string
      business_verification?: BusinessVerification | null
      verification_reason?: string | null
    } | null
    documents: Array<{ document_id: string; title: string; sensitivity: string }>
    notification_templates?: Array<{ template_id: string; version: string; title: string; content_template: string }>
  }
  workflow_runs?: WorkflowRun[]
}

export interface TrustedRefundVerification {
  trusted_action_slot: string
  verification_status: 'VERIFIED' | 'PENDING' | 'REJECTED'
  original_transaction_id: string | null
  refund_reason_code: string | null
  refundable_amount_fen: number | null
  evidence_reference: string | null
  verified_at: number | null
  payment_verification_status: string | null
  transaction_refundable_amount_fen: number | null
}

export type RuntimeMode = 'deterministic' | 'local' | 'cloud'
export type WorkflowScenario = 'normal' | 'policy_injection'

export interface RuntimeProfile {
  mode: RuntimeMode
  label: string
  provider: string
  model: string | null
  available: boolean
  verification: string
  message: string
  generation?: { response_format: string; thinking_mode: string; max_tokens: number; temperature: number }
}

export interface RuntimeProfiles {
  workflow_enabled: boolean
  items: RuntimeProfile[]
}

export type ModelApiMode = 'chat_completions' | 'responses' | 'anthropic_messages'

export interface ModelConfiguration {
  id: string
  name: string
  provider_id: string
  base_url: string
  api_mode: ModelApiMode
  model: string
  timeout_seconds: number
  enabled: boolean
  has_key: boolean
  is_default: boolean
}

export interface ModelConfigurations {
  items: ModelConfiguration[]
  default_id: string | null
  supported_api_modes: ModelApiMode[]
}

export interface ModelConfigurationInput {
  name: string
  provider_id: string
  base_url: string
  api_mode: ModelApiMode
  model: string
  timeout_seconds: number
  enabled: boolean
  api_key?: string
  set_default?: boolean
}

export interface ModelConnectionTest {
  status: 'PASS' | 'FAIL'
  model_requested: string | null
  model_returned?: string | null
  duration_ms?: number | null
  reason_code?: string | null
  message?: string | null
}

export interface WorkflowEvent extends TraceStep {
  timestamp_ms: number
  recorded_at_ms: number
}

export interface WorkflowRun {
  run_id: string
  runtime_mode: RuntimeMode
  scenario: WorkflowScenario
  model: string | null
  state: string
  reason_code: string | null
  created_at_ms: number
  updated_at_ms: number
  deadline_at_ms: number
  finished_at_ms: number | null
  observation_kind: 'operational_not_signed_audit'
  events: WorkflowEvent[]
}

export interface WorkflowStarted {
  run_id: string
  task_id: string
  state: string
  runtime_mode: RuntimeMode
}

export interface TraceStep {
  sequence: number
  agent_id: string
  action: string
  status: string
  details: Record<string, unknown>
}

export interface DemoResult {
  demo_kind: string
  task_id: string
  planner: 'deterministic' | 'llm'
  status: string
  reason_code: string | null
  trace: TraceStep[]
}

export interface SecurityScenario {
  id: string
  category: string
  attacker_capability: string
  target_invariant: string
  expected_decision: string
  expected_reason_codes: string[]
  expected_business_effects: number | string
  evidence: string[]
  test_ref?: string
  latest_result?: SecurityScenarioResult | null
}

export interface SecurityScenarioResult {
  scenario_id: string
  nodeid: string
  test_ref: string
  status: string
  run_id: string
  source_snapshot_sha256: string
  started_at?: string
  finished_at?: string
  execution_layer?: string
  evidence_scope?: Record<string, unknown>
  before: { budget?: ProofBudget[]; counts?: Record<string, number>; global_counts?: Record<string, number>; scope?: Record<string, unknown> }
  after: { budget?: ProofBudget[]; counts?: Record<string, number>; global_counts?: Record<string, number>; scope?: Record<string, unknown> }
  execution_ids?: string[] | { status: string; reason: string }
  receipt_ids?: string[] | { status: string; reason: string }
  assertions: Array<{ name: string; result: string; expected?: unknown; observed?: unknown }>
  observations: Array<{ kind?: string; label?: string; status_code?: number; body?: { decision?: string; state?: string; reason_code?: string; execution_id?: string } }>
}

export interface ProofBudget {
  credential_id: string
  quota_type: string
  limit: number
  reserved: number
  committed: number
  remaining: number
  version: number
}

export interface ProofObservation {
  observed_at_ms: number
  scope: { type: 'task'; task_id: string }
  budgets: ProofBudget[]
  refund_rows: number
  notification_rows: number
  refund_amount_fen: number
}

export interface ProofAttempt {
  kind: string
  request: Record<string, unknown>
  http_status: number
  gateway: { decision?: string; state?: string; reason_code?: string; execution_id?: string; receipt?: unknown }
  holder_proof_valid: boolean
  chain_valid: boolean
  receipt_valid: boolean
  record_binding_valid: boolean
  budget_unchanged: boolean
  before: ProofObservation
  after: ProofObservation
  refund_delta: number
  notification_delta: number
}

export interface SecurityProofReport {
  schema_version: '1.0'
  proof_id: string
  profile: 'AGENTGUARD_DETERMINISTIC_SECURITY_PROOF_V1'
  candidate_origin: 'deterministic_security_probe'
  llm_required: false
  observation_kind: string
  created_at_ms: number
  kind: 'wrong_customer' | 'over_amount'
  task_id: string
  tenant_id: string
  ticket_id: string
  customer_id: string
  refund_limit_fen: number
  status: 'PASS' | 'FAIL'
  attack: ProofAttempt
  control: ProofAttempt | null
  checks: { denied_without_effect: boolean; legal_control_committed: boolean }
}

export interface SecurityMatrix {
  suite: string
  llm_required: boolean
  success_invariant: string
  scenario_count: number
  categories: Record<string, number>
  scenarios: SecurityScenario[]
  error_codes: unknown
  latest_batch?: { status: string; scope?: string; run_id?: string; verified_at?: string; source_snapshot_sha256?: string; ledger_sha256?: string }
}

export interface BenchmarkLatencyStats {
  count: number
  min_ms: number
  max_ms: number
  mean_ms: number
  p50_ms: number
  p95_ms: number
  p99_ms: number
}

export interface BenchmarkSystemMeasurement {
  name: string
  legitimate_accepted: number
  legitimate_attempts: number
  legitimate_request_acceptance_rate: number
  normal_task_attempts: number
  normal_tasks_completed: number
  normal_task_completion_rate: number
  latency_ms: BenchmarkLatencyStats
  throughput_rps: number
  attack_outcome: {
    attack: string
    decision: string
    http_status: number
    reason_code: string
    unauthorized_side_effects: number
  }
  revocation: {
    denied: boolean
    latency_ms: number
    reason_code: string
  }
  concurrent_consistency: {
    allowed: number
    denied: number
    budget_safe: boolean
    committed_refund_fen: number
    configured_limit_fen: number
    denial_reason_codes?: string[]
  }
  state_storage: {
    logical_bytes: number
    tables: Record<string, number>
  }
  component_timings_ms?: Record<string, number>
}

export interface BenchmarkAblation {
  name: string
  isolated: boolean
  [key: string]: unknown
}

export interface BenchmarkAecCheck {
  name: string
  passed: boolean
  checks: Record<string, number>
  boundary?: string
}

export interface BenchmarkSummary {
  schema_version?: string
  status: string
  message?: string
  run_id?: string
  generated_at?: string
  started_at?: string
  duration_seconds?: number
  source_provenance?: {
    status: 'MATCH' | 'SOURCE_CHANGED' | 'UNVERIFIED'
    recorded_snapshot_sha256: string | null
    current_snapshot_sha256: string | null
  }
  environment?: {
    deployment?: string
    python?: string
    machine?: string
    cpu_count?: number
    memory_bytes_visible_to_runner?: number | null
    postgresql?: { server_version?: string; main?: { server_version?: string } }
    model?: { provider?: string; model_requested?: string; requested?: string; seed?: number; temperature?: number }
  }
  protocol?: {
    latency_samples?: number
    throughput_requests?: number
    concurrency?: number
    warmup_samples?: number
    normal_task_samples?: number
    primary_chain_length?: number
    crypto_samples?: number
    random_seed?: number
    performance_threshold?: number | null
  }
  metrics?: {
    legitimate_request_acceptance_rate?: number
    normal_task_completion_rate?: number
    unauthorized_side_effects?: number
    latency_p95_ms?: number
    throughput_rps?: Record<string, number>
    latency_distribution_ms?: Record<string, BenchmarkLatencyStats>
    revocation_latency_ms?: Record<string, BenchmarkSystemMeasurement['revocation']>
    credential_size_bytes?: {
      agentguard_by_chain_length?: Record<string, { chain_bytes: number; credential_bytes: number[] }>
      conventional_rbac?: number
      shared_static_credential?: number
    }
    state_storage_bytes?: Record<string, BenchmarkSystemMeasurement['state_storage']>
    component_latency_ms?: Record<string, unknown>
  }
  agentguard?: BenchmarkSystemMeasurement & {
    live_llm?: {
      normal?: { status?: string; committed_effects?: number }
      prompt_injection?: { status?: string; reason_code?: string; unauthorized_side_effects?: number }
    }
  }
  baselines?: BenchmarkSystemMeasurement[]
  ablations?: BenchmarkAblation[]
  aec?: Record<string, BenchmarkAecCheck>
  audit?: {
    valid?: boolean
    checked_events?: number
    latest_event_sequence?: number
    pending_outbox?: number
    checkpoint_sequence?: number
  }
  acceptance?: {
    passed?: boolean
    checks?: Record<string, boolean>
    note?: string
  }
}
