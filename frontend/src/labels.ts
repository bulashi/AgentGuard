const STATUS_LABELS: Record<string, string> = {
  ACTIVE: '生效中',
  ADMITTED: '已准入',
  ANCHORED: '已锚定',
  ALLOW: '允许',
  AVAILABLE: '可用',
  AUTHORIZED: '已授权',
  BINDING_CHECKED: '已核对',
  CHECK: '校验中',
  COMMITTED: '已提交',
  COMPLETED: '已完成',
  COMPROMISED: '已失陷',
  DENIED: '已拒绝',
  DENY: '拒绝',
  DISPATCHED: '已分发',
  FAILED: '失败',
  FAIL: '失败',
  FAILED_RETRYABLE: '失败，可重试',
  INVALID: '无效',
  INFERRED_PASS: '推断通过',
  NONE: '无',
  NOT_REACHED: '未到达',
  NOT_REQUIRED: '无需回执',
  PENDING: '等待中',
  PENDING_PHASE_17: '等待正式评测',
  PENDING_AUTHORIZATION: '待授权',
  RECONCILING: '对账中',
  RECEIVED: '已接收',
  RECORDED: '已留证',
  RECOVERY_FAILED_FINAL: '恢复最终失败',
  RELEASED: '已释放',
  RETIRED: '已退役',
  REVOKED: '已撤销',
  SIGNED: '已签名',
  UNKNOWN: '未知',
  VALID: '有效',
  VERIFIED: '已验证',
  MISSING: '缺失',
  MONOTONIC: '单调收窄',
  PASS: '通过',
  PRESENT: '存在',
  REJECT_AT_PARSE: '解析阶段拒绝',
  REJECT_AT_SCHEMA: '结构校验拒绝',
  REJECTED: '不符合办理条件',
  ONE_ALLOW_ONE_DENY: '一次允许、一次拒绝',
  IDEMPOTENT_RETURN: '幂等返回',
  RECHECK_AUTHORIZATION: '重新校验授权',
  RECOVER: '恢复提交',
  LINEARIZED: '已线性化',
  TOOL_DENY: '工具拒绝',
  QUEUED: '等待运行',
  RUNNING: '运行中',
  INTERRUPTED: '运行中断',
  NOT_RECORDED: '未记录过程',
  NOT_CHECKED: '未核对',
  NOT_ANCHORED: '未锚定',
  UNANCHORED: '尚未覆盖',
  WINDOW_OPEN: '时间窗开放',
  NOT_YET_VALID: '尚未生效',
  EXPIRED: '已过期',
  ANCESTOR_REVOKED: '祖先已撤销',
  PARENT_LINK_INVALID: '父授权绑定异常',
  SOURCE_BINDING_INVALID: '签名来源绑定异常',
  INCOMPLETE: '投影不完整',
  BUSINESS_STOPPED: '业务已停止',
  STOPPED: '已停止',
  FAILED_NO_EFFECT: '失败 · 无业务效果',
  CANCELLED_NO_EFFECT: '已取消 · 无业务效果',
}

const AGENT_LABELS: Record<string, string> = {
  'agent-case': '工单智能体',
  'agent-coordinator': '协调智能体',
  'agent-knowledge': '知识智能体',
  'agent-refund': '退款智能体',
}

const ACTION_LABELS: Record<string, string> = {
  ADMISSION: '准入检查',
  AUTHORIZE: '签发授权',
  DELEGATE: '下发委托',
  EXECUTE: '执行工具',
  HOLD: '保留待查',
  PLAN: '生成候选动作',
  RECEIPT: '签发执行回执',
  START: '接收任务',
  VERIFY: '验签与校验',
  'CALL TOOL': '调用工具',
  CALL_TOOL: '调用工具',
  GATEWAY_DECISION: '网关裁决',
}

const EVENT_LABELS: Record<string, string> = {
  COAUTH_ROOT_AUTHORIZED: '共同审批根授权',
  COAUTH_REVOCATION_APPLIED: '共同授权撤销已应用',
  CREDENTIAL_REVOKED: '授权凭证已撤销',
  RAW_REQUEST_REJECTED: '原始请求被拒绝',
  AUTHORIZATION_DENIED: '授权被拒绝',
  EXECUTION_ADMITTED: '执行已准入',
  EXECUTION_COMMITTED: '执行已提交',
  EXECUTION_RELEASED: '执行已释放',
  EXECUTION_UNKNOWN: '执行结果未知',
  EXECUTION_COMPLETED: '执行已完成',
  EXECUTION_DENIED: '执行被拒绝',
  EXECUTION_REQUESTED: '收到执行请求',
  RECEIPT_SIGNED: '签名回执已签发',
  RECEIPT_PENDING: '回执等待签发',
  TOOL_DISPATCHED: '工具请求已分发',
  RESULT_RETRIEVAL_ALLOWED: '结果重取获准',
  RESULT_RETRIEVAL_DENIED: '结果重取被拒绝',
  RECEIPT_ISSUED: '执行回执已签发',
}

const REVOCATION_SOURCE_LABELS: Record<string, string> = {
  APPROVAL_KEY_REVOKED: '审批公钥已撤销',
  APPROVAL_KEY_COMPROMISED: '审批公钥已失陷',
  APPROVAL_POLICY_REVOKED: '共同审批策略已撤销',
  AUTHORIZATION_WITHDRAWN: '单根授权主动撤回',
}

const REVOCATION_OBSERVATION_LABELS: Record<string, string> = {
  REGISTRY_STATUS_UPDATE: '注册表状态更新',
  MIGRATION_RECONCILIATION: '迁移核对补录观察',
  EXPLICIT_WITHDRAWAL: '显式撤回授权',
}

const REVOCATION_CAPTURE_LABELS: Record<string, string> = {
  TRANSACTIONAL_CAPTURE: '事务内捕获',
  LEGACY_OBSERVATION_LINK: '旧观察后续关联',
}

const QUOTA_LABELS: Record<string, string> = {
  refund_total_fen: '退款额度',
  max_refund_fen: '退款额度',
  max_tool_calls: '工具调用次数',
}

const AEC_LABELS: Record<string, string> = {
  'authorization-to-effect unique mapping': '授权到业务效果的唯一映射',
  'multi-level budget conservation': '多级共享预算守恒',
  'unknown-result safety': '未知结果安全性',
  'cross-checkable evidence': '证据交叉验证',
}

const SCENARIO_CATEGORY_LABELS: Record<string, string> = {
  raw_parse: '原始解析',
  schema: '结构校验',
  authorization: '授权链',
  holder_proof: '持有者证明',
  identity_binding: '身份绑定',
  capability: '能力范围',
  delegation: '委托收窄',
  revocation: '撤销传播',
  freshness: '时效校验',
  replay: '重放防护',
  parameter: '参数约束',
  budget: '共享预算',
  concurrency: '并发一致性',
  idempotency: '业务幂等',
  recovery: '故障恢复',
  tool_boundary: '工具边界',
  key_lifecycle: '密钥生命周期',
  retrieval: '结果重取',
  prompt_injection: '提示注入',
}

const SCENARIO_INVARIANT_LABELS: Record<string, string> = {
  'RAW_REQUEST_REJECTED is chained without an execution': '原始请求被拒绝并写入审计链，不能产生执行记录',
  'invalid bytes cannot establish RequestContext': '无效字节不能建立请求上下文',
  'ambiguous canonical input is rejected before authorization': '有歧义的规范化输入必须在授权前拒绝',
  'strict schema boundary rejects unknown security fields': '严格 Schema 边界拒绝未知安全字段',
  'persisted signed credential object and hash remain bound': '持久化签名凭证对象与哈希始终绑定',
  'Holder Proof signer must equal leaf holder': '持有者证明（Holder Proof）签名者必须等于叶子凭证持有者',
  'Holder Proof key identity is bound to leaf credential': '持有者证明（Holder Proof）密钥身份必须绑定叶子凭证',
  'credential tenant equals trusted task tenant': '凭证租户必须等于受信任务租户',
  'credential and RequestEnvelope task IDs remain equal': '凭证与请求信封（RequestEnvelope）的任务 ID 必须一致',
  'credential audience is secure-tool-gateway': '凭证受众必须是安全工具网关',
  'requested service must be in the leaf capability set': '请求服务必须属于叶子能力集合',
  'tool version is bound by capability and envelope': '工具版本必须由能力集合和执行信封共同绑定',
  'child capability is a monotone subset of parent': '子凭证能力必须是父凭证能力的单调子集',
  'child binds the actual persisted parent signed-object hash': '子凭证必须绑定持久化父签名对象的实际哈希',
  'issuer key subject equals parent holder': '签发者密钥主体必须等于父凭证持有者',
  'ancestor revocation invalidates descendants at admission': '祖先凭证撤销后，后代凭证在准入时失效',
  'credential/task lifetime is checked against gateway time': '凭证和任务有效期必须相对于网关时间校验',
  'issued_at is within the bounded gateway freshness window': '签发时间必须处于网关限定的新鲜度窗口内',
  'request_id is linearized exactly once': '同一请求 ID 必须且只能被线性化一次',
  'protected tool parameter domain is positive integer': '受保护工具参数必须是正整数',
  'canonical integer and business bound are enforced': '必须同时执行规范化整数和业务上限约束',
  'verified parameters equal executed parameters': '验签参数必须等于实际执行参数',
  'reserved + committed never exceeds every chain-level limit': '预留额加已提交额不得超过链路任一层级上限',
  'real effect and committed amount stay within root budget': '真实副作用和已提交金额必须处于根预算内',
  'same trusted action and parameters reuse one execution/effect': '相同可信动作和参数必须复用同一执行与副作用',
  'business action identity cannot be reused with a different parameter hash': '同一业务动作不能复用到不同参数哈希',
  'distinct trusted actions are evaluated independently but still share budget': '不同可信动作独立评估，但仍共享预算',
  'recovery commits observed effect once and preserves evidence': '恢复流程只提交一次已观测副作用并保留证据',
  'unknown outcome is reconciled without a second effect': '未知结果必须在不产生第二次副作用的情况下对账',
  'admission commit order is the revocation linearization boundary': '准入提交顺序是撤销线性化边界',
  'execution_attempt_id is unique at the protected-tool boundary': '执行尝试 ID 在受保护工具边界必须唯一',
  'protected Tool checks envelope TTL and gateway signature': '受保护工具必须检查信封 TTL 和网关签名',
  'compromised key cannot create a new admission': '已泄露密钥不能创建新的准入记录',
  'retrieval rechecks current chain and revocation': '结果重取必须重新检查当前凭证链和撤销状态',
  'retrieval replay is a separate read-only namespace': '结果重取重放属于独立的只读命名空间',
  'untrusted plan cannot exceed structured authorization': '不可信计划不能超出结构化授权范围',
}

export function statusLabel(value: string | null | undefined) {
  const raw = value ?? 'NONE'
  return STATUS_LABELS[raw] ?? raw
}

export function agentLabel(value: string) {
  return AGENT_LABELS[value] ?? value.replace(/^agent-/, '')
}

export function actionLabel(value: string) {
  const normalized = value.toUpperCase()
  return ACTION_LABELS[normalized] ?? value.replaceAll('_', ' ')
}

export function eventLabel(value: string) {
  return EVENT_LABELS[value] ?? value.replaceAll('_', ' ')
}

export function revocationSourceLabel(value: string) {
  return REVOCATION_SOURCE_LABELS[value] ?? value
}

export function revocationObservationLabel(value: string) {
  return REVOCATION_OBSERVATION_LABELS[value] ?? value
}

export function revocationCaptureLabel(value: string) {
  return REVOCATION_CAPTURE_LABELS[value] ?? value
}

export function quotaLabel(value: string) {
  return QUOTA_LABELS[value] ?? value
}

export function aecLabel(value: string) {
  return AEC_LABELS[value] ?? value
}

export function scenarioCategoryLabel(value: string) {
  return SCENARIO_CATEGORY_LABELS[value] ?? value.replaceAll('_', ' ')
}

export function scenarioInvariantLabel(value: string) {
  return SCENARIO_INVARIANT_LABELS[value] ?? value
}

export function credentialTypeLabel(value: string) {
  if (value === 'ROOT') return '根授权'
  if (value === 'DELEGATION') return '委托授权'
  return value
}

const TOOL_LABELS: Record<string, string> = {
  'ticket.read': '读取工单',
  'knowledge.read_associated': '查询关联知识',
  'refund.create': '创建退款',
  'notification.send_template': '发送退款通知',
}

export function toolLabel(value: string) {
  return TOOL_LABELS[value] ?? value
}

export function reasonLabel(value: string | null | undefined) {
  if (!value || value === 'ALLOW') return '未记录拒绝原因'
  const labels: Record<string, string> = {
    ALLOWED: '授权检查通过',
    PARAMETER_CONSTRAINT_VIOLATION: '请求参数超出授权范围',
    BUDGET_EXCEEDED: '共享预算不足',
    REPLAY_DETECTED: '请求已被处理',
    CREDENTIAL_REVOKED: '授权已被撤销',
    REQUEST_SCHEMA_INVALID: '请求结构不符合规范',
    WRONG_HOLDER: '请求持有者与授权不一致',
    DELEGATION_ESCALATION: '委托扩大了父级权限',
    CREDENTIAL_EXPIRED: '授权已过期',
    RESOURCE_NOT_ALLOWED: '请求资源不在授权范围',
    ANCESTOR_REVOKED: '祖先授权已被撤销',
    PLANNER_DECLINED: '规划未采纳请求并停止执行',
    LLM_OUTPUT_INVALID: '模型输出不符合角色契约，已停止且未降级',
    LLM_UPSTREAM_UNAVAILABLE: '模型服务不可用，已停止且未降级',
    MODEL_MODE_UNAVAILABLE: '所选模型模式当前不可用',
    WORKFLOW_RUNTIME_FAILED: '协作运行失败，需检查实际执行与业务记录',
    BUSINESS_RESULT_MISMATCH: '退款建议或执行结果未满足业务约束，已停止',
    BUSINESS_PRECONDITION_FAILED: '工单不满足办理条件，已停止退款和通知',
    BUSINESS_CONTEXT_MISMATCH: '工单与授权主体不一致，已停止退款委托',
    OBSERVATION_STORE_UNAVAILABLE: '协作过程记录不可用',
    CONTROLLED_RESULT_INVALID: '受控结果未通过校验',
    // 任务与业务读取路径的错误码，用于把内部枚举转换成可读说明。
    CROSS_TASK: '请求与当前任务不一致',
    CROSS_TENANT: '该记录不属于当前租户',
    WRONG_AUDIENCE: '请求的受众与授权不一致',
    SERVICE_NOT_ALLOWED: '请求的服务不在授权范围',
    TOOL_NOT_ALLOWED: '请求的工具不在授权范围',
    TOOL_VERSION_MISMATCH: '工具版本与授权不一致',
    INVALID_SIGNATURE: '签名校验未通过',
    UNKNOWN_KEY: '签名密钥未登记或不受信任',
    KEY_REVOKED: '签名密钥已被撤销',
    KEY_RETIRED_FOR_SIGNING: '签名密钥已退役，不能再签名',
    KEY_COMPROMISED: '签名密钥已失陷',
    DUPLICATE_FIELD: '请求存在重复字段，已拒绝',
    UNKNOWN_FIELD: '请求包含未知字段，已拒绝',
    INVALID_CANONICAL_ENCODING: '请求未使用确定性编码',
    MALFORMED_JSON: '请求不是合法 JSON',
    INVALID_UTF8: '请求不是合法 UTF-8 编码',
    REQUEST_STALE: '请求已过期，需重新生成',
    IDEMPOTENCY_CONFLICT: '相同业务请求的参数不一致',
    BUSINESS_ACTION_CONFLICT: '该业务动作已被占用或已办理',
    BUSINESS_ACTION_INVALID: '业务动作标识无效',
    EXECUTION_ENVELOPE_REPLAY: '执行信封已被重放',
    EXECUTION_ENVELOPE_EXPIRED: '执行信封已过期',
    RESULT_ACCESS_DENIED: '当前主体无权读取该结果',
    TOOL_EXECUTION_UNKNOWN: '工具执行结果未知，需对账',
    REQUEST_REJECTED: '请求被拒绝',
  }
  return labels[value] ?? value
}
