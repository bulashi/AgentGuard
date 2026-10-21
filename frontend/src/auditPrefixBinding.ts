import type { AuditEventView } from './types'
import { isBusinessIdentifier } from './businessIdentifiers'

export type AuditEventTypeV1 =
  | 'RAW_REQUEST_REJECTED'
  | 'AUTHORIZATION_DENIED'
  | 'EXECUTION_ADMITTED'
  | 'TOOL_DISPATCHED'
  | 'EXECUTION_COMMITTED'
  | 'EXECUTION_RELEASED'
  | 'EXECUTION_UNKNOWN'
  | 'RECEIPT_PENDING'
  | 'RECEIPT_SIGNED'
  | 'RESULT_RETRIEVAL_ALLOWED'
  | 'RESULT_RETRIEVAL_DENIED'

export interface AuditEventCore {
  readonly schema_version: '1.0' | '2.0' | '3.0' | '4.0'
  readonly event_sequence: number
  readonly event_id: string
  readonly execution_id: string | null
  readonly event_type: string
  readonly timestamp: number
  readonly payload_hash: string
  readonly evidence_reference: string
  readonly previous_event_hash: string
  readonly event_hash: string
}

export type VerifiedAuditEventCore = AuditEventCore & (
  | { readonly schema_version: '1.0'; readonly event_type: AuditEventTypeV1 }
  | { readonly schema_version: '2.0'; readonly execution_id: null; readonly event_type: 'COAUTH_ROOT_AUTHORIZED' }
  | { readonly schema_version: '3.0'; readonly execution_id: null; readonly event_type: 'COAUTH_REVOCATION_APPLIED' }
  | { readonly schema_version: '4.0'; readonly execution_id: null; readonly event_type: 'CREDENTIAL_REVOKED' }
)

export interface AuditPrefixRequest {
  readonly schema_version: '1.0'
  readonly task_id: string
  readonly events: readonly AuditEventCore[]
}

export interface AuditPrefixVerification {
  readonly valid: boolean
  readonly checked_events: number
  readonly latest_event_sequence: number
  readonly latest_event_hash: string
  readonly rollback_detected: boolean
  readonly first_invalid_sequence: number | null
}

export interface SignedAuditCheckpoint {
  readonly payload: {
    readonly schema_version: '1.0'
    readonly checkpoint_sequence: number
    readonly latest_event_sequence: number
    readonly latest_event_hash: string
    readonly timestamp: number
  }
  readonly signature: {
    readonly algorithm: 'SM2'
    readonly key_id: string
    readonly key_purpose: 'AUDIT_CHECKPOINT_SIGNING'
    readonly encoding: 'SM2_RS_HEX_128_LOWERCASE'
    readonly value: string
    readonly signed_at: number
  }
}

// "Verified" describes the server report; it is not a browser signature proof.
export interface VerifiedCheckpoint {
  readonly signed_checkpoint: SignedAuditCheckpoint
  readonly signed_object_hash: string
}

export interface AuditEventBinding {
  readonly event_sequence: number
  readonly event_id: string
  readonly event_hash: string
  readonly matched: boolean
  readonly covered: boolean
  readonly verified_event: VerifiedAuditEventCore | null
}

export interface AuditPrefixReport {
  readonly schema_version: '1.0'
  readonly task_id: string
  readonly verification: AuditPrefixVerification
  readonly checkpoint: VerifiedCheckpoint | null
  readonly event_bindings: readonly AuditEventBinding[]
}

export type AuditPrefixStatus = 'ANCHORED' | 'UNANCHORED' | 'INVALID' | 'NOT_CHECKED'

export interface AuditPrefixObservation {
  readonly status: AuditPrefixStatus
  readonly label: string
  readonly checkpoint?: VerifiedCheckpoint
}

export interface AuditPrefixSummary {
  readonly anchored: number
  readonly total: number
  readonly status: AuditPrefixStatus
  readonly label: string
}

const CORE_FIELDS = [
  'schema_version', 'event_sequence', 'event_id', 'execution_id', 'event_type',
  'timestamp', 'payload_hash', 'evidence_reference', 'previous_event_hash', 'event_hash',
] as const

const V1_EVENT_TYPES: readonly AuditEventTypeV1[] = [
  'RAW_REQUEST_REJECTED', 'AUTHORIZATION_DENIED', 'EXECUTION_ADMITTED',
  'TOOL_DISPATCHED', 'EXECUTION_COMMITTED', 'EXECUTION_RELEASED',
  'EXECUTION_UNKNOWN', 'RECEIPT_PENDING', 'RECEIPT_SIGNED',
  'RESULT_RETRIEVAL_ALLOWED', 'RESULT_RETRIEVAL_DENIED',
]

const LABELS: Record<AuditPrefixStatus, string> = {
  ANCHORED: '服务端核验：已覆盖',
  UNANCHORED: '服务端核验：尚未覆盖',
  INVALID: '服务端核验：未通过',
  NOT_CHECKED: '逐事件覆盖未核验',
}

const SUMMARY_LABELS: Record<AuditPrefixStatus, string> = {
  ANCHORED: '服务端核验：全部覆盖',
  UNANCHORED: '服务端核验：部分未覆盖',
  INVALID: '服务端核验：未通过',
  NOT_CHECKED: '存在未核验事件',
}

function observation(status: AuditPrefixStatus): AuditPrefixObservation {
  return { status, label: LABELS[status] }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function hasExactFields(value: unknown, fields: readonly string[]): value is Record<string, unknown> {
  if (!isRecord(value)) return false
  const prototype = Object.getPrototypeOf(value)
  if (prototype !== Object.prototype && prototype !== null) return false
  return Reflect.ownKeys(value).length === fields.length && fields.every((field) => {
    const property = Object.getOwnPropertyDescriptor(value, field)
    return property !== undefined && property.enumerable === true && 'value' in property
  })
}

function isSafeInteger(value: unknown, minimum: 0 | 1): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= minimum
}

function isIdentifier(value: unknown): value is string {
  return typeof value === 'string' && value.length >= 1 && value.length <= 128
    && /^[A-Za-z0-9]/.test(value) && !/[^A-Za-z0-9._:-]/.test(value)
}

function isLowerHex(value: unknown, length: 64 | 128): value is string {
  return typeof value === 'string' && value.length === length && !/[^0-9a-f]/.test(value)
}

function isVerifiedCore(value: unknown): value is VerifiedAuditEventCore {
  if (!hasExactFields(value, CORE_FIELDS)) return false
  if (!isSafeInteger(value.event_sequence, 1) || !isIdentifier(value.event_id)
    || !isSafeInteger(value.timestamp, 0) || !isLowerHex(value.payload_hash, 64)
    || !isIdentifier(value.evidence_reference) || !isLowerHex(value.previous_event_hash, 64)
    || !isLowerHex(value.event_hash, 64)) return false
  if (value.schema_version === '2.0') {
    return value.event_type === 'COAUTH_ROOT_AUTHORIZED' && value.execution_id === null
  }
  if (value.schema_version === '3.0') {
    return value.event_type === 'COAUTH_REVOCATION_APPLIED' && value.execution_id === null
  }
  if (value.schema_version === '4.0') {
    return value.event_type === 'CREDENTIAL_REVOKED' && value.execution_id === null
  }
  return value.schema_version === '1.0'
    && typeof value.event_type === 'string'
    && V1_EVENT_TYPES.some((eventType) => eventType === value.event_type)
    && (value.execution_id === null || isIdentifier(value.execution_id))
}

export function isCoauthorizationRevocationAuditEvent(event: AuditEventCore): boolean {
  return event.schema_version === '3.0' && event.event_type === 'COAUTH_REVOCATION_APPLIED'
    && event.execution_id === null
}

// This is a display boundary for a server projection, not signature or actor verification.
export function coauthorizationRevocationProjection(event: AuditEventView): {
  evidence: Record<string, unknown>; roots: Record<string, unknown>[]
} | null {
  const evidence = event.revocation_evidence
  if (!isCoauthorizationRevocationAuditEvent(event) || !hasExactFields(evidence, [
    'schema_version', 'record_type', 'revocation_event_id', 'tenant_id', 'source_kind', 'source_identifier',
    'observed_at', 'observation_context', 'database_actor', 'capture_kind', 'captured_at', 'page_number',
    'page_count', 'matched_root_count', 'created_root_revocation_count', 'roots',
  ])
    || evidence.schema_version !== '1.0' || evidence.record_type !== 'COAUTH_REVOCATION_APPLIED_V1'
    || !isSafeInteger(evidence.revocation_event_id, 1)
    || !isBusinessIdentifier(evidence.tenant_id) || !isIdentifier(evidence.source_identifier)
    || typeof evidence.database_actor !== 'string' || !evidence.database_actor || evidence.database_actor.length > 128
    || !['APPROVAL_KEY_REVOKED', 'APPROVAL_KEY_COMPROMISED', 'APPROVAL_POLICY_REVOKED', 'AUTHORIZATION_WITHDRAWN']
      .some((kind) => kind === evidence.source_kind)
    || !['REGISTRY_STATUS_UPDATE', 'MIGRATION_RECONCILIATION', 'EXPLICIT_WITHDRAWAL']
      .some((context) => context === evidence.observation_context)
    || !['TRANSACTIONAL_CAPTURE', 'LEGACY_OBSERVATION_LINK'].some((kind) => kind === evidence.capture_kind)
    || !isSafeInteger(evidence.observed_at, 0) || !isSafeInteger(evidence.captured_at, 0)
    || evidence.captured_at < evidence.observed_at
    || !isSafeInteger(evidence.page_number, 1) || !isSafeInteger(evidence.page_count, 1)
    || evidence.page_number > evidence.page_count
    || !isSafeInteger(evidence.matched_root_count, 0) || !isSafeInteger(evidence.created_root_revocation_count, 0)
    || evidence.created_root_revocation_count > evidence.matched_root_count
    || !Array.isArray(evidence.roots) || evidence.roots.length > 32
    || evidence.roots.length > evidence.matched_root_count) return null
  if (evidence.page_count !== Math.max(1, Math.ceil(evidence.matched_root_count / 32))
    || evidence.roots.length !== Math.min(32, Math.max(0, evidence.matched_root_count - (evidence.page_number - 1) * 32))
    || (evidence.source_kind === 'AUTHORIZATION_WITHDRAWN') !== (evidence.observation_context === 'EXPLICIT_WITHDRAWAL')
    || (evidence.source_kind === 'AUTHORIZATION_WITHDRAWN' && evidence.matched_root_count !== 1)) return null
  const roots: Record<string, unknown>[] = []
  let previousRoot = ''
  for (const root of evidence.roots) {
    if (!hasExactFields(root, [
      'root_credential_id', 'root_credential_hash', 'task_id', 'challenge_id', 'policy_revision',
      'approval_payload_hash', 'bundle_hash', 'enterprise_key_id', 'finance_key_id',
      'root_revocation_created', 'revoked_at', 'revoked_by', 'revocation_reason',
    ]) || !['root_credential_id', 'task_id', 'challenge_id', 'policy_revision', 'enterprise_key_id', 'finance_key_id']
      .every((field) => isIdentifier(root[field]))
      || !['root_credential_hash', 'approval_payload_hash', 'bundle_hash'].every((field) => isLowerHex(root[field], 64))
      || typeof root.root_credential_id !== 'string' || root.root_credential_id <= previousRoot
      || typeof root.revoked_by !== 'string' || !root.revoked_by || root.revoked_by.length > 256
      || typeof root.revocation_reason !== 'string' || !root.revocation_reason || root.revocation_reason.length > 512
      || root.enterprise_key_id === root.finance_key_id || typeof root.root_revocation_created !== 'boolean'
      || !isSafeInteger(root.revoked_at, 0) || root.revoked_at > evidence.observed_at) return null
    if ((['APPROVAL_KEY_REVOKED', 'APPROVAL_KEY_COMPROMISED'].some((kind) => kind === evidence.source_kind)
      && evidence.source_identifier !== root.enterprise_key_id && evidence.source_identifier !== root.finance_key_id)
      || (evidence.source_kind === 'APPROVAL_POLICY_REVOKED' && evidence.source_identifier !== root.policy_revision)
      || (evidence.source_kind === 'AUTHORIZATION_WITHDRAWN' && evidence.source_identifier !== root.root_credential_id)
      || (root.root_revocation_created === true && (root.revoked_at !== evidence.observed_at
        || root.revoked_by !== `COAUTH_REGISTRY:${evidence.database_actor}`
        || root.revocation_reason !== `${evidence.source_kind}:${evidence.source_identifier}`))) return null
    previousRoot = root.root_credential_id
    roots.push(root)
  }
  if (roots.filter((root) => root.root_revocation_created === true).length > evidence.created_root_revocation_count) return null
  return { evidence, roots }
}

export function coauthorizationRevocationBindingStatus(event: AuditEventView): 'BINDING_CHECKED' | 'INVALID' | 'NOT_CHECKED' {
  if (!isCoauthorizationRevocationAuditEvent(event)) return 'INVALID'
  if (typeof event.evidence_binding_valid !== 'boolean') return 'NOT_CHECKED'
  if (event.evidence_binding_valid === false) return 'INVALID'
  if (event.revocation_evidence === null || event.revocation_evidence === undefined) return 'NOT_CHECKED'
  return coauthorizationRevocationProjection(event) ? 'BINDING_CHECKED' : 'INVALID'
}

function isVerification(value: unknown): value is AuditPrefixVerification {
  return hasExactFields(value, [
    'valid', 'checked_events', 'latest_event_sequence', 'latest_event_hash',
    'rollback_detected', 'first_invalid_sequence',
  ]) && typeof value.valid === 'boolean' && isSafeInteger(value.checked_events, 0)
    && isSafeInteger(value.latest_event_sequence, 0) && isLowerHex(value.latest_event_hash, 64)
    && typeof value.rollback_detected === 'boolean'
    && (value.first_invalid_sequence === null || isSafeInteger(value.first_invalid_sequence, 1))
}

function verificationSucceeded(value: AuditPrefixVerification): boolean {
  return value.valid === true && value.rollback_detected === false
    && value.first_invalid_sequence === null && value.checked_events === value.latest_event_sequence
}

function parseCheckpoint(value: unknown): VerifiedCheckpoint | null {
  if (!hasExactFields(value, ['signed_checkpoint', 'signed_object_hash'])
    || !isLowerHex(value.signed_object_hash, 64)
    || !hasExactFields(value.signed_checkpoint, ['payload', 'signature'])) return null
  const { payload, signature } = value.signed_checkpoint
  if (!hasExactFields(payload, [
    'schema_version', 'checkpoint_sequence', 'latest_event_sequence', 'latest_event_hash', 'timestamp',
  ]) || payload.schema_version !== '1.0' || !isSafeInteger(payload.checkpoint_sequence, 1)
    || !isSafeInteger(payload.latest_event_sequence, 1) || !isLowerHex(payload.latest_event_hash, 64)
    || !isSafeInteger(payload.timestamp, 0)) return null
  if (!hasExactFields(signature, ['algorithm', 'key_id', 'key_purpose', 'encoding', 'value', 'signed_at'])
    || signature.algorithm !== 'SM2' || !isIdentifier(signature.key_id)
    || signature.key_purpose !== 'AUDIT_CHECKPOINT_SIGNING'
    || signature.encoding !== 'SM2_RS_HEX_128_LOWERCASE' || !isLowerHex(signature.value, 128)
    || !isSafeInteger(signature.signed_at, 0) || signature.signed_at !== payload.timestamp) return null
  return Object.freeze({
    signed_checkpoint: Object.freeze({
      payload: Object.freeze({
        schema_version: '1.0',
        checkpoint_sequence: payload.checkpoint_sequence,
        latest_event_sequence: payload.latest_event_sequence,
        latest_event_hash: payload.latest_event_hash,
        timestamp: payload.timestamp,
      }),
      signature: Object.freeze({
        algorithm: 'SM2',
        key_id: signature.key_id,
        key_purpose: 'AUDIT_CHECKPOINT_SIGNING',
        encoding: 'SM2_RS_HEX_128_LOWERCASE',
        value: signature.value,
        signed_at: signature.signed_at,
      }),
    }),
    signed_object_hash: value.signed_object_hash,
  })
}

function parseBinding(value: unknown): AuditEventBinding | null {
  if (!hasExactFields(value, [
    'event_sequence', 'event_id', 'event_hash', 'matched', 'covered', 'verified_event',
  ]) || !isSafeInteger(value.event_sequence, 1) || !isIdentifier(value.event_id)
    || !isLowerHex(value.event_hash, 64) || typeof value.matched !== 'boolean'
    || typeof value.covered !== 'boolean') return null
  const verified = value.verified_event
  if (verified === null) {
    if (value.matched || value.covered) return null
  } else {
    if (!isVerifiedCore(verified) || value.event_sequence !== verified.event_sequence
      || value.event_id !== verified.event_id
      || (value.matched && value.event_hash !== verified.event_hash)) return null
  }
  if (value.covered && !value.matched) return null
  return Object.freeze({
    event_sequence: value.event_sequence,
    event_id: value.event_id,
    event_hash: value.event_hash,
    matched: value.matched,
    covered: value.covered,
    verified_event: verified === null ? null : Object.freeze({ ...verified }),
  })
}

/** Selects wire fields only; validation happens when interpreting a server report. */
export function auditEventCore(event: AuditEventView): AuditEventCore {
  return {
    schema_version: event.schema_version,
    event_sequence: event.event_sequence,
    event_id: event.event_id,
    execution_id: event.execution_id,
    event_type: event.event_type,
    timestamp: event.timestamp,
    payload_hash: event.payload_hash,
    evidence_reference: event.evidence_reference,
    previous_event_hash: event.previous_event_hash,
    event_hash: event.event_hash,
  }
}

/** Parses the whole report atomically and returns an immutable, detached snapshot. */
export function parseAuditPrefixReport(report: unknown): AuditPrefixReport | null {
  try {
    if (!hasExactFields(report, [
      'schema_version', 'task_id', 'verification', 'checkpoint', 'event_bindings',
    ]) || report.schema_version !== '1.0' || !isIdentifier(report.task_id)
      || !isVerification(report.verification)) return null
    const verification = report.verification
    const succeeded = verificationSucceeded(verification)
    if (verification.valid && !succeeded) return null
    const checkpoint = report.checkpoint === null ? null : parseCheckpoint(report.checkpoint)
    if (report.checkpoint !== null && checkpoint === null) return null
    if (verification.valid && checkpoint === null) return null
    if (checkpoint !== null && !succeeded) return null
    const checkpointHead = checkpoint?.signed_checkpoint.payload
    if (checkpointHead && (checkpointHead.latest_event_sequence > verification.latest_event_sequence
      || (checkpointHead.latest_event_sequence === verification.latest_event_sequence
        && checkpointHead.latest_event_hash !== verification.latest_event_hash))) return null
    const entries = report.event_bindings
    if (!Array.isArray(entries) || entries.length < 1 || entries.length > 100
      || Reflect.ownKeys(entries).length !== entries.length + 1) return null
    const sequences = new Set<number>()
    const ids = new Set<string>()
    const bindings: AuditEventBinding[] = []
    for (let index = 0; index < entries.length; index += 1) {
      const property = Object.getOwnPropertyDescriptor(entries, String(index))
      if (!property || !property.enumerable || !('value' in property)) return null
      const binding = parseBinding(property.value)
      if (binding === null || sequences.has(binding.event_sequence) || ids.has(binding.event_id)) return null
      sequences.add(binding.event_sequence)
      ids.add(binding.event_id)
      if (succeeded && binding.verified_event !== null) {
        if (binding.event_sequence > verification.latest_event_sequence) return null
        if (binding.event_sequence === verification.latest_event_sequence
          && binding.verified_event.event_hash !== verification.latest_event_hash) return null
        if (checkpointHead && binding.event_sequence === checkpointHead.latest_event_sequence
          && binding.verified_event.event_hash !== checkpointHead.latest_event_hash) return null
      }
      if (binding.covered && (!succeeded || !checkpointHead
        || binding.event_sequence > checkpointHead.latest_event_sequence)) return null
      bindings.push(binding)
    }
    return Object.freeze({
      schema_version: '1.0',
      task_id: report.task_id,
      verification: Object.freeze({ ...verification }),
      checkpoint,
      event_bindings: Object.freeze(bindings),
    })
  } catch {
    return null
  }
}

/** Observes server verification and exact event binding; no hashes or signatures are recomputed. */
export function auditPrefixObservation<Event extends AuditEventCore>(
  taskId: string, event: Event, report: unknown,
): AuditPrefixObservation {
  if (report === null || report === undefined) return observation('NOT_CHECKED')
  try {
    if (isRecord(report) && isIdentifier(report.task_id) && report.task_id !== taskId) {
      return observation('NOT_CHECKED')
    }
    const parsed = parseAuditPrefixReport(report)
    if (parsed === null) return observation('INVALID')
    const binding = parsed.event_bindings.find((entry) =>
      entry.event_sequence === event.event_sequence && entry.event_id === event.event_id)
    if (!binding) return observation('NOT_CHECKED')
    if (binding.event_hash !== event.event_hash) return observation('NOT_CHECKED')
    const verified = binding.verified_event
    if (verified !== null && !CORE_FIELDS.every((field) => event[field] === verified[field])) {
      return observation('NOT_CHECKED')
    }
    if (!verificationSucceeded(parsed.verification) || !binding.matched
      || verified === null || parsed.checkpoint === null) {
      return observation('INVALID')
    }
    const status = binding.covered ? 'ANCHORED' : 'UNANCHORED'
    return { status, label: LABELS[status], checkpoint: parsed.checkpoint }
  } catch {
    return observation('INVALID')
  }
}

export function auditPrefixSummary(
  taskId: string, events: AuditEventView[], report: unknown,
): AuditPrefixSummary {
  const observations = events.map((event) => auditPrefixObservation(taskId, event, report))
  const anchored = observations.filter((entry) => entry.status === 'ANCHORED').length
  const total = events.length
  const status: AuditPrefixStatus = observations.some((entry) => entry.status === 'INVALID')
    ? 'INVALID'
    : total === 0 || observations.some((entry) => entry.status === 'NOT_CHECKED')
      ? 'NOT_CHECKED'
      : anchored === total ? 'ANCHORED' : 'UNANCHORED'
  const label = total === 0
    ? '暂无审计事件'
    : SUMMARY_LABELS[status]
  return { anchored, total, status, label }
}
