import type {
  BenchmarkSummary,
  DemoResult,
  Overview,
  SecurityMatrix,
  TaskSnapshot,
  TaskSummary,
  RuntimeMode,
  RuntimeProfiles,
  WorkflowScenario,
  WorkflowStarted,
  CoauthorizationStatus,
  CoauthorizationTaskReview,
  CoauthorizationChallenge,
  CoauthorizationResult,
  ModelConfigurations,
  ModelConfiguration,
  ModelConfigurationInput,
  ModelConnectionTest,
  SecurityProofReport,
} from './types'
import type { AuditEventCore } from './auditPrefixBinding'
import type { CredentialRevocationRequest, CredentialRevocationResult, RevocationVerificationResult } from './sections/CredentialRevocationPanel'

export type PaymentStatus = 'SUCCESS' | 'FAILED' | 'PROCESSING'

export interface BusinessPaymentFact {
  transaction_id: string
  amount_fen: number
  status: PaymentStatus
  refunded_amount_fen: number
}

export interface BusinessFactsRecord {
  schema_version: '1.0'
  order: { order_id: string; amount_fen: number; currency: 'CNY' }
  payments: BusinessPaymentFact[]
  claim_text: string
}

export interface BusinessVerification {
  schema_version: '1.0'
  task_id: string
  ticket_id: string
  facts_hash: string
  status: 'VERIFIED' | 'PENDING' | 'REJECTED'
  reason_code: string
  reason: string
  evidence_ids: string[]
  refundable_amount_fen: number
  original_transaction_id: string | null
  policy_version: string
  evaluated_at: number
}

export interface BusinessCaseInput {
  tenant_id: string
  customer_id: string
  ticket_id: string
  order_id: string
  order_amount_fen: number
  claim_text: string
  payments: BusinessPaymentFact[]
  cloud_shareable: boolean
}

export interface BusinessCaseResult {
  ticket_id: string
  tenant_id: string
  customer_id: string
  facts_hash: string
  business_facts: BusinessFactsRecord
}

export interface BusinessTicket {
  ticket_id: string; tenant_id: string; customer_id: string; title: string
  status?: string
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
  source?: 'facts' | string
  business_facts?: BusinessFactsRecord
  facts_hash?: string
  business_verification?: BusinessVerification | null
  verification_reason?: string | null
}

interface ApiErrorBody {
  reason_code?: string
  message?: string
  field_errors?: Record<string, string>
  detail?: { reason_code?: string; message?: string } | Array<{ loc?: unknown[]; type?: string }>
}

export class ApiError extends Error {
  readonly reasonCode: string
  readonly status: number
  readonly fieldErrors: Record<string, string>

  constructor(status: number, reasonCode: string, message: string, fieldErrors: Record<string, string> = {}) {
    super(message)
    this.name = 'ApiError'
    this.reasonCode = reasonCode
    this.status = status
    this.fieldErrors = fieldErrors
  }
}

const READ_TIMEOUT_MS = 15000
const AUDIT_READ_TIMEOUT_MS = 90000
let overviewInFlight: Promise<Overview> | null = null
let operatorBootstrap: Promise<void> | null = null

export const OPERATOR_START_MESSAGE = '请从“启动AgentGuard”进入控制台；已打开的浏览器需要重新取得本机启动授权。'

export function isOperatorSessionError(error: unknown): boolean {
  return error instanceof ApiError && (error.status === 401 || error.reasonCode.startsWith('OPERATOR_'))
}

function bootstrapOperatorSession(): Promise<void> {
  if (operatorBootstrap) return operatorBootstrap
  const url = new URL(window.location.href)
  const fragment = new URLSearchParams(url.hash.slice(1))
  if (!fragment.has('launch_token')) return Promise.resolve()
  const tokens = fragment.getAll('launch_token')
  // Remove the bearer token before any asynchronous work or navigation effects.
  url.hash = ''
  window.history.replaceState(null, '', `${url.pathname}${url.search}`)
  operatorBootstrap = (async () => {
    try {
      if (tokens.length !== 1 || !/^[0-9a-f]{64}$/.test(tokens[0])) throw new Error('Invalid launch token')
      const result = await request<{ authenticated?: unknown }>('/api/operator-session', {
        method: 'POST', body: JSON.stringify({ launch_token: tokens[0] }), cache: 'no-store', redirect: 'error',
      })
      if (result.authenticated !== true) throw new Error('Operator session not authenticated')
    } catch {
      throw new ApiError(401, 'OPERATOR_SESSION_REQUIRED', OPERATOR_START_MESSAGE)
    }
  })()
  return operatorBootstrap
}

function readOverview() {
  if (overviewInFlight) return overviewInFlight
  const pending = request<Overview>('/api/overview', undefined, { timeoutMs: AUDIT_READ_TIMEOUT_MS })
  overviewInFlight = pending
  const clear = () => { if (overviewInFlight === pending) overviewInFlight = null }
  void pending.then(clear, clear)
  return pending
}

async function request<T>(path: string, init?: RequestInit, options?: { readOnly?: boolean; timeoutMs?: number }): Promise<T> {
  const readOnly = (init?.method ?? 'GET').toUpperCase() === 'GET' || options?.readOnly === true
  const timeoutMs = options?.timeoutMs ?? READ_TIMEOUT_MS
  const controller = readOnly ? new AbortController() : null
  let timedOut = false
  const abortRead = () => controller?.abort()
  if (controller && init?.signal) {
    if (init.signal.aborted) abortRead()
    else init.signal.addEventListener('abort', abortRead, { once: true })
  }
  // Only abandon reads; a timed-out mutation may already have committed remotely.
  const timer = controller ? setTimeout(() => {
    timedOut = true
    controller.abort()
  }, timeoutMs) : null
  try {
    const response = await fetch(path, {
      ...init,
      credentials: 'same-origin',
      signal: controller?.signal ?? init?.signal,
      headers: { 'Content-Type': 'application/json', ...init?.headers },
    })
    if (!response.ok) {
      let body: ApiErrorBody = {}
      try {
        body = (await response.json()) as ApiErrorBody
      } catch {
        body = {}
      }
      if (Array.isArray(body.detail)) {
        const labels: Record<string, string> = {
          tenant_id: '租户', ticket_id: '工单', customer_id: '客户', refund_total_fen: '退款预算',
          max_tool_calls: '工具调用预算', expires_in_seconds: '有效期',
        }
        const errors: Record<string, string> = {}
        for (const error of body.detail) {
          const field = error?.loc?.at(-1)
          if (typeof field === 'string' && labels[field]) errors[field] = `${labels[field]}格式或取值不正确`
        }
        throw new ApiError(response.status, 'REQUEST_SCHEMA_INVALID', '请检查请求字段的格式和取值', errors)
      }
      const source = body.detail ?? body
      throw new ApiError(
        response.status,
        source.reason_code ?? 'HTTP_ERROR',
        source.message ?? `HTTP ${response.status}`,
        body.field_errors ?? {},
      )
    }
    return (await response.json()) as T
  } catch (error) {
    if (timedOut) throw new ApiError(408, 'UI_READ_TIMEOUT', `只读请求超过 ${timeoutMs / 1000} 秒，未获得新的数据`)
    throw error
  } finally {
    if (timer !== null) clearTimeout(timer)
    init?.signal?.removeEventListener('abort', abortRead)
  }
}

export const api = {
  bootstrapOperatorSession,
  revokeCredential: (taskId: string, credentialId: string, body: CredentialRevocationRequest) => request<CredentialRevocationResult>(
    `/api/tasks/${encodeURIComponent(taskId)}/credentials/${encodeURIComponent(credentialId)}/revoke`,
    { method: 'POST', body: JSON.stringify(body) },
  ),
  verifyRevokedCredential: (taskId: string, credentialId: string, body: { confirmed: true }) => request<RevocationVerificationResult>(
    `/api/tasks/${encodeURIComponent(taskId)}/credentials/${encodeURIComponent(credentialId)}/verify-revoked`,
    { method: 'POST', body: JSON.stringify(body) },
  ),
  businessTickets: () => request<{ items: BusinessTicket[] }>('/api/business/tickets'),
  createBusinessCase: (body: BusinessCaseInput) => request<BusinessCaseResult>('/api/business/cases', {
    method: 'POST', body: JSON.stringify(body),
  }),
  auditPrefix: (taskId: string, events: AuditEventCore[], signal?: AbortSignal) => request<unknown>(
    `/api/extensions/audit-prefix-binding/v1/tasks/${encodeURIComponent(taskId)}/verify-events`,
    { method: 'POST', body: JSON.stringify({ schema_version: '1.0', task_id: taskId, events }), signal },
    { readOnly: true, timeoutMs: AUDIT_READ_TIMEOUT_MS },
  ),
  coauthorizationStatus: () => request<CoauthorizationStatus>('/api/extensions/coauthorization/v1/status'),
  coauthorizationTask: (taskId: string, offset = 0) => request<CoauthorizationTaskReview>(
    `/api/extensions/coauthorization/v1/tasks/${encodeURIComponent(taskId)}?offset=${offset}`,
  ),
  createCoauthorizationChallenge: (taskId: string, body: {
    holder_agent_id: string; holder_key_id: string; delegation_depth: number
  }) => request<CoauthorizationChallenge>(
    `/api/extensions/coauthorization/v1/tasks/${encodeURIComponent(taskId)}/challenges`,
    { method: 'POST', body: JSON.stringify(body) },
  ),
  authorizeCoauthorizationTask: (taskId: string, rawJson: string) => request<CoauthorizationResult>(
    `/api/extensions/coauthorization/v1/tasks/${encodeURIComponent(taskId)}/authorize`,
    { method: 'POST', body: rawJson },
  ),
  runtimeProfiles: () => request<RuntimeProfiles>('/api/runtime-profiles'),
  modelConfigurations: () => request<ModelConfigurations>('/api/model-configurations'),
  saveModelConfiguration: (id: string, body: ModelConfigurationInput) => request<ModelConfiguration>(
    `/api/model-configurations/${encodeURIComponent(id)}`,
    { method: 'PUT', headers: { 'X-AgentGuard-Configuration': '1' }, body: JSON.stringify(body) },
  ),
  testModelConfiguration: (id: string) => request<ModelConnectionTest>(
    `/api/model-configurations/${encodeURIComponent(id)}/test`,
    { method: 'POST', headers: { 'X-AgentGuard-Configuration': '1' }, body: JSON.stringify({ confirm_cloud_call: true }) },
  ),
  deleteModelConfiguration: (id: string) => request<unknown>(
    `/api/model-configurations/${encodeURIComponent(id)}`,
    { method: 'DELETE', headers: { 'X-AgentGuard-Configuration': '1' } },
  ),
  setDefaultModelConfiguration: (id: string) => request<unknown>(
    '/api/model-configurations/default',
    { method: 'PATCH', headers: { 'X-AgentGuard-Configuration': '1' }, body: JSON.stringify({ id }) },
  ),
  startWorkflow: (runtimeMode: RuntimeMode, scenario: WorkflowScenario, cloudDataConfirmed = false, customInjectionText?: string) =>
    request<WorkflowStarted>('/api/workflows', {
      method: 'POST', body: JSON.stringify({ runtime_mode: runtimeMode, scenario, cloud_data_confirmed: cloudDataConfirmed, ...(customInjectionText === undefined ? {} : { custom_injection_text: customInjectionText }) }),
    }),
  startAuthorizedWorkflow: (taskId: string, runtimeMode: RuntimeMode, scenario: WorkflowScenario, cloudDataConfirmed = false, customInjectionText?: string) =>
    request<WorkflowStarted>(`/api/tasks/${encodeURIComponent(taskId)}/workflow`, {
      method: 'POST', body: JSON.stringify({ runtime_mode: runtimeMode, scenario, cloud_data_confirmed: cloudDataConfirmed, ...(customInjectionText === undefined ? {} : { custom_injection_text: customInjectionText }) }),
    }),
  overview: readOverview,
  tasks: (options: { offset?: number; search?: string; status?: string } = {}) => {
    const params = new URLSearchParams({ limit: '40', offset: String(options.offset ?? 0) })
    if (options.search) params.set('search', options.search)
    if (options.status) params.set('status', options.status)
    return request<{ items: TaskSummary[]; has_more?: boolean }>(`/api/tasks?${params}`)
  },
  task: (taskId: string) => request<TaskSnapshot>(`/api/tasks/${taskId}`),
  createTask: (body: object) =>
    request<{ task_id: string; status: string }>('/api/tasks', {
      method: 'POST',
      body: JSON.stringify(body),
    }),
  authorizeTask: (taskId: string, body: object) =>
    request<Record<string, unknown>>(`/api/tasks/${taskId}/authorize`, {
      method: 'POST',
      body: JSON.stringify(body),
    }),
  runTask: (taskId: string, promptText = '') =>
    request<DemoResult>(`/api/tasks/${taskId}/run`, {
      method: 'POST',
      body: JSON.stringify({ prompt_text: promptText }),
    }),
  normalDemo: () =>
    request<DemoResult>('/api/demos/normal', { method: 'POST', body: '{}' }),
  injectionDemo: (promptText: string) =>
    request<DemoResult>('/api/demos/prompt-injection', {
      method: 'POST',
      body: JSON.stringify({ prompt_text: promptText }),
    }),
  matrix: () => request<SecurityMatrix>('/api/security/matrix'),
  securityProofs: () => request<{ items: SecurityProofReport[] }>('/api/security/proofs'),
  securityProof: (kind: SecurityProofReport['kind']) => request<SecurityProofReport>(
    '/api/security/proofs', { method: 'POST', body: JSON.stringify({ kind, confirmed: true }) },
  ),
  benchmarks: () => request<BenchmarkSummary>('/api/benchmarks'),
}
