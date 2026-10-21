import { describe, expect, it } from 'vitest'
import {
  auditEventCore, auditPrefixObservation, auditPrefixSummary, parseAuditPrefixReport,
} from './auditPrefixBinding'
import type {
  AuditEventCore, AuditEventTypeV1, AuditPrefixReport, AuditPrefixRequest, VerifiedAuditEventCore,
} from './auditPrefixBinding'
import type { AuditEventView } from './types'

// Synthetic wire fixtures only; no fixture proves SM2, SM3, or browser verification.
const TASK_ID = 'task-1'
const OTHER_HASH = 'b'.repeat(64)
const OMIT = Symbol('omit')
type FieldPath = readonly (string | number)[]

function makeEvent(sequence = 2, schemaVersion: '1.0' | '2.0' = '1.0'): AuditEventView {
  return {
    schema_version: schemaVersion,
    event_sequence: sequence,
    event_id: `event-${sequence}`,
    execution_id: schemaVersion === '2.0' ? null : `execution-${sequence}`,
    event_type: schemaVersion === '2.0' ? 'COAUTH_ROOT_AUTHORIZED' : 'EXECUTION_ADMITTED',
    timestamp: 1000,
    payload_hash: 'a'.repeat(64),
    evidence_reference: `evidence-${sequence}`,
    previous_event_hash: '0'.repeat(64),
    event_hash: sequence.toString(16).padStart(64, '0'),
    coauthorization_evidence: { ui_only: true },
    evidence_binding_valid: true,
  }
}

function makeReport(events: AuditEventView[] = [makeEvent()]): AuditPrefixReport {
  const head = events.reduce((latest, event) => event.event_sequence > latest.event_sequence ? event : latest)
  return {
    schema_version: '1.0',
    task_id: TASK_ID,
    verification: {
      valid: true,
      checked_events: head.event_sequence,
      latest_event_sequence: head.event_sequence,
      latest_event_hash: head.event_hash,
      rollback_detected: false,
      first_invalid_sequence: null,
    },
    checkpoint: {
      signed_checkpoint: {
        payload: {
          schema_version: '1.0',
          checkpoint_sequence: 1,
          latest_event_sequence: head.event_sequence,
          latest_event_hash: head.event_hash,
          timestamp: 1000,
        },
        signature: {
          algorithm: 'SM2',
          key_id: 'audit-key-1',
          key_purpose: 'AUDIT_CHECKPOINT_SIGNING',
          encoding: 'SM2_RS_HEX_128_LOWERCASE',
          value: '0'.repeat(128),
          signed_at: 1000,
        },
      },
      signed_object_hash: 'f'.repeat(64),
    },
    event_bindings: events.map((event) => ({
      event_sequence: event.event_sequence,
      event_id: event.event_id,
      event_hash: event.event_hash,
      matched: true,
      covered: true,
      verified_event: auditEventCore(event) as VerifiedAuditEventCore,
    })),
  }
}

function withReportValue(path: FieldPath, value: unknown, source = makeReport()): unknown {
  const copy = structuredClone(source)
  let parent = copy as unknown as Record<string | number, unknown>
  for (const field of path.slice(0, -1)) parent = parent[field] as Record<string | number, unknown>
  const field = path[path.length - 1]
  if (value === OMIT) delete parent[field]
  else parent[field] = value
  return copy
}

function failedReport(): AuditPrefixReport {
  const report = makeReport()
  return {
    ...report,
    verification: { ...report.verification, valid: false, first_invalid_sequence: 2 },
    checkpoint: null,
    event_bindings: report.event_bindings.map((binding) => ({ ...binding, covered: false })),
  }
}

function partiallyCoveredReport(): AuditPrefixReport {
  const events = [makeEvent(1), makeEvent(2)]
  const report = makeReport(events)
  return {
    ...report,
    checkpoint: {
      ...report.checkpoint!,
      signed_checkpoint: {
        ...report.checkpoint!.signed_checkpoint,
        payload: {
          ...report.checkpoint!.signed_checkpoint.payload,
          latest_event_sequence: 1,
          latest_event_hash: events[0].event_hash,
        },
      },
    },
    event_bindings: report.event_bindings.map((binding) => ({
      ...binding, covered: binding.event_sequence === 1,
    })),
  }
}

function expectInvalid(report: unknown, event = makeEvent()): void {
  expect(parseAuditPrefixReport(report)).toBeNull()
  expect(auditPrefixObservation(TASK_ID, event, report).status).toBe('INVALID')
}

describe('audit-prefix-binding-v1 core and report schema', () => {
  it('projects exactly ten core fields for V1 and V2 without UI evidence', () => {
    for (const version of ['1.0', '2.0'] as const) {
      const event = makeEvent(2, version)
      const core = auditEventCore(event)
      expect(Object.keys(core)).toEqual([
        'schema_version', 'event_sequence', 'event_id', 'execution_id', 'event_type',
        'timestamp', 'payload_hash', 'evidence_reference', 'previous_event_hash', 'event_hash',
      ])
      expect(core).not.toHaveProperty('coauthorization_evidence')
      expect(core).not.toHaveProperty('evidence_binding_valid')
      const request: AuditPrefixRequest = { schema_version: '1.0', task_id: TASK_ID, events: [core] }
      expect(request.events[0]).toEqual(core)
    }
  })

  it.each(['1.0', '2.0'] as const)('accepts complete server reports for event schema %s', (version) => {
    const event = makeEvent(2, version)
    const report = makeReport([event])
    expect(parseAuditPrefixReport(report)).toEqual(report)
    const result = auditPrefixObservation(TASK_ID, event, report)
    expect(result.status).toBe('ANCHORED')
    expect(result.checkpoint).toEqual(report.checkpoint)
    expect(result.label).toBe('服务端核验：已覆盖')
  })

  const v1Types: AuditEventTypeV1[] = [
    'RAW_REQUEST_REJECTED', 'AUTHORIZATION_DENIED', 'EXECUTION_ADMITTED',
    'TOOL_DISPATCHED', 'EXECUTION_COMMITTED', 'EXECUTION_RELEASED',
    'EXECUTION_UNKNOWN', 'RECEIPT_PENDING', 'RECEIPT_SIGNED',
    'RESULT_RETRIEVAL_ALLOWED', 'RESULT_RETRIEVAL_DENIED',
  ]
  it.each(v1Types)('accepts the frozen V1 event type %s', (eventType) => {
    const event = { ...makeEvent(), event_type: eventType }
    expect(auditPrefixObservation(TASK_ID, event, makeReport([event])).status).toBe('ANCHORED')
  })

  it('preserves requested binding order instead of sorting by sequence', () => {
    const events = [makeEvent(2), makeEvent(1)]
    const report = makeReport(events)
    expect(parseAuditPrefixReport(report)?.event_bindings.map((binding) => binding.event_sequence)).toEqual([2, 1])
    expect(auditPrefixSummary(TASK_ID, events, report)).toMatchObject({
      anchored: 2, total: 2, status: 'ANCHORED',
    })
  })

  it('accepts one through 100 bindings and rejects empty, oversized, or sparse arrays', () => {
    expect(parseAuditPrefixReport(makeReport([makeEvent(1)]))).not.toBeNull()
    const hundred = makeReport(Array.from({ length: 100 }, (_, index) => makeEvent(index + 1)))
    expect(parseAuditPrefixReport(hundred)?.event_bindings).toHaveLength(100)
    expectInvalid(makeReport(Array.from({ length: 101 }, (_, index) => makeEvent(index + 1))))
    expectInvalid(withReportValue(['event_bindings'], []))
    expectInvalid(withReportValue(['event_bindings', 0], OMIT))
    expectInvalid(withReportValue(['event_bindings', 'extra'], true))
  })

  it('rejects duplicate sequence and duplicate id independently', () => {
    const report = makeReport([makeEvent(1), makeEvent(2)])
    const first = report.event_bindings[0]
    const second = report.event_bindings[1]
    expectInvalid({
      ...report,
      event_bindings: [first, {
        ...second, event_sequence: first.event_sequence,
        verified_event: { ...second.verified_event!, event_sequence: first.event_sequence },
      }],
    })
    expectInvalid({
      ...report,
      event_bindings: [first, {
        ...second, event_id: first.event_id,
        verified_event: { ...second.verified_event!, event_id: first.event_id },
      }],
    })
    expectInvalid({ ...report, event_bindings: [first, second, first] })
  })

  const objects: Array<[string, FieldPath, readonly string[]]> = [
    ['report', [], ['schema_version', 'task_id', 'verification', 'checkpoint', 'event_bindings']],
    ['verification', ['verification'], [
      'valid', 'checked_events', 'latest_event_sequence', 'latest_event_hash', 'rollback_detected', 'first_invalid_sequence',
    ]],
    ['checkpoint', ['checkpoint'], ['signed_checkpoint', 'signed_object_hash']],
    ['signed checkpoint', ['checkpoint', 'signed_checkpoint'], ['payload', 'signature']],
    ['checkpoint payload', ['checkpoint', 'signed_checkpoint', 'payload'], [
      'schema_version', 'checkpoint_sequence', 'latest_event_sequence', 'latest_event_hash', 'timestamp',
    ]],
    ['checkpoint signature', ['checkpoint', 'signed_checkpoint', 'signature'], [
      'algorithm', 'key_id', 'key_purpose', 'encoding', 'value', 'signed_at',
    ]],
    ['binding', ['event_bindings', 0], [
      'event_sequence', 'event_id', 'event_hash', 'matched', 'covered', 'verified_event',
    ]],
    ['verified event', ['event_bindings', 0, 'verified_event'], [
      'schema_version', 'event_sequence', 'event_id', 'execution_id', 'event_type',
      'timestamp', 'payload_hash', 'evidence_reference', 'previous_event_hash', 'event_hash',
    ]],
  ]
  it.each(objects)('rejects extra fields and every missing field on %s', (_name, path, fields) => {
    expectInvalid(withReportValue([...path, 'extra'], true))
    for (const field of fields) {
      expectInvalid(withReportValue([...path, field], OMIT))
      expectInvalid(withReportValue([...path, field], undefined))
    }
    if (path.length > 0) expectInvalid(withReportValue(path, null))
  })

  const malformedReports: unknown[] = [false, 1, 'report', [], {}, { task_id: TASK_ID }, new Date(0)]
  it.each(malformedReports.map((report) => [report] as const))(
    'rejects malformed present reports: %j', (report) => expectInvalid(report),
  )

  it('rejects symbols, non-enumerable extras, accessors, and inherited required fields', () => {
    const symbolReport = { ...makeReport(), [Symbol('extra')]: true }
    expectInvalid(symbolReport)
    const hiddenReport = Object.defineProperty(makeReport(), 'extra', { value: true })
    expectInvalid(hiddenReport)
    const accessorReport = Object.defineProperty(makeReport(), 'verification', {
      enumerable: true, get: () => makeReport().verification,
    })
    expectInvalid(accessorReport)
    expectInvalid(Object.create(makeReport()))
  })

  const invalidVersions: Array<[FieldPath, unknown]> = [
    [['schema_version'], '2.0'],
    [['schema_version'], 1],
    [['task_id'], null],
    [['task_id'], 1],
    [['checkpoint', 'signed_checkpoint', 'payload', 'schema_version'], '2.0'],
    [['event_bindings', 0, 'verified_event', 'schema_version'], '3.0'],
    [['event_bindings', 0, 'verified_event', 'schema_version'], 1],
    [['event_bindings', 0, 'verified_event', 'event_type'], 'COAUTH_ROOT_AUTHORIZED'],
    [['event_bindings', 0, 'verified_event', 'event_type'], 'UNKNOWN'],
  ]
  it.each(invalidVersions)('rejects invalid versions or scalar types at %j', (path, value) => {
    expectInvalid(withReportValue(path, value))
  })

  it('enforces the V2 enum and null execution id, without admitting UI evidence into the core', () => {
    const report = makeReport([makeEvent(2, '2.0')])
    expectInvalid(withReportValue(['event_bindings', 0, 'verified_event', 'execution_id'], 'execution-2', report))
    expectInvalid(withReportValue(['event_bindings', 0, 'verified_event', 'event_type'], 'EXECUTION_ADMITTED', report))
    expectInvalid(withReportValue(['event_bindings', 0, 'verified_event', 'coauthorization_evidence'], {}, report))
    expectInvalid(withReportValue(['event_bindings', 0, 'verified_event', 'evidence_binding_valid'], true, report))
  })

  const integerFields: Array<[FieldPath, 0 | 1]> = [
    [['verification', 'checked_events'], 0],
    [['verification', 'latest_event_sequence'], 0],
    [['verification', 'first_invalid_sequence'], 1],
    [['checkpoint', 'signed_checkpoint', 'payload', 'checkpoint_sequence'], 1],
    [['checkpoint', 'signed_checkpoint', 'payload', 'latest_event_sequence'], 1],
    [['checkpoint', 'signed_checkpoint', 'payload', 'timestamp'], 0],
    [['checkpoint', 'signed_checkpoint', 'signature', 'signed_at'], 0],
    [['event_bindings', 0, 'event_sequence'], 1],
    [['event_bindings', 0, 'verified_event', 'event_sequence'], 1],
    [['event_bindings', 0, 'verified_event', 'timestamp'], 0],
  ]
  it.each(integerFields)('enforces safe integer types and bounds at %j', (path, minimum) => {
    for (const value of [true, false, '1', null, undefined, -1, 0.5, NaN, Infinity, -Infinity, Number.MAX_SAFE_INTEGER + 1]) {
      if (value === null && path[1] === 'first_invalid_sequence') continue
      expectInvalid(withReportValue(path, value))
    }
    if (minimum === 1) expectInvalid(withReportValue(path, 0))
  })

  it('accepts zero timestamps, maximum safe integers, and nullable V1 execution ids', () => {
    const event = { ...makeEvent(), timestamp: 0, execution_id: null }
    const report = makeReport([event])
    const boundary: AuditPrefixReport = {
      ...report,
      verification: {
        ...report.verification, checked_events: Number.MAX_SAFE_INTEGER,
        latest_event_sequence: Number.MAX_SAFE_INTEGER,
      },
      checkpoint: {
        ...report.checkpoint!,
        signed_checkpoint: {
          payload: {
            ...report.checkpoint!.signed_checkpoint.payload,
            checkpoint_sequence: Number.MAX_SAFE_INTEGER,
            latest_event_sequence: Number.MAX_SAFE_INTEGER,
            timestamp: 0,
          },
          signature: { ...report.checkpoint!.signed_checkpoint.signature, signed_at: 0 },
        },
      },
    }
    expect(auditPrefixObservation(TASK_ID, event, boundary).status).toBe('ANCHORED')
    const failure = failedReport()
    expect(parseAuditPrefixReport({
      ...failure,
      verification: {
        ...failure.verification, checked_events: 0, latest_event_sequence: 0,
        latest_event_hash: '0'.repeat(64), first_invalid_sequence: Number.MAX_SAFE_INTEGER,
      },
      event_bindings: failure.event_bindings.map((binding) => ({
        ...binding, matched: false, covered: false, verified_event: null,
      })),
    })).not.toBeNull()
  })

  const booleanFields: FieldPath[] = [
    ['verification', 'valid'], ['verification', 'rollback_detected'],
    ['event_bindings', 0, 'matched'], ['event_bindings', 0, 'covered'],
  ]
  it.each(booleanFields.map((path) => [path] as const))('rejects truthy, falsy, and missing boolean substitutes at %j', (path) => {
    for (const value of ['true', 'false', 1, 0, null, undefined, [], {}]) {
      expectInvalid(withReportValue(path, value))
    }
  })

  const hashFields: FieldPath[] = [
    ['verification', 'latest_event_hash'], ['checkpoint', 'signed_object_hash'],
    ['checkpoint', 'signed_checkpoint', 'payload', 'latest_event_hash'],
    ['event_bindings', 0, 'event_hash'], ['event_bindings', 0, 'verified_event', 'event_hash'],
    ['event_bindings', 0, 'verified_event', 'payload_hash'],
    ['event_bindings', 0, 'verified_event', 'previous_event_hash'],
  ]
  it.each(hashFields.map((path) => [path] as const))('accepts only complete lowercase hex64 at %j', (path) => {
    for (const value of ['A'.repeat(64), 'g'.repeat(64), 'a'.repeat(63), 'a'.repeat(65), 'a'.repeat(64) + '\n', 64, null]) {
      expectInvalid(withReportValue(path, value))
    }
  })

  const identifierFields: FieldPath[] = [
    ['task_id'],
    ['event_bindings', 0, 'event_id'], ['event_bindings', 0, 'verified_event', 'event_id'],
    ['event_bindings', 0, 'verified_event', 'execution_id'],
    ['event_bindings', 0, 'verified_event', 'evidence_reference'],
    ['checkpoint', 'signed_checkpoint', 'signature', 'key_id'],
  ]
  it.each(identifierFields.map((path) => [path] as const))('enforces the frozen identifier grammar at %j', (path) => {
    for (const value of ['', 'a'.repeat(129), '-start', '_start', 'a b', 'abc\n', 'abc\r', 'abc\u2028', true, 1]) {
      expectInvalid(withReportValue(path, value))
    }
  })

  it('accepts valid identifier punctuation and the 128-character boundary', () => {
    const event = { ...makeEvent(), execution_id: 'a'.repeat(128), evidence_reference: 'A9._:-' }
    const report = withReportValue(
      ['checkpoint', 'signed_checkpoint', 'signature', 'key_id'], 'K9._:-', makeReport([event]),
    )
    expect(auditPrefixObservation(TASK_ID, event, report).status).toBe('ANCHORED')
  })
})

describe('audit-prefix-binding-v1 checkpoint and whole-report consistency', () => {
  const invalidSignature: Array<[FieldPath, unknown]> = [
    [['checkpoint', 'signed_checkpoint', 'signature', 'algorithm'], 'ECDSA'],
    [['checkpoint', 'signed_checkpoint', 'signature', 'encoding'], 'DER'],
    [['checkpoint', 'signed_checkpoint', 'signature', 'key_purpose'], 'EXECUTION_RECEIPT_SIGNING'],
    [['checkpoint', 'signed_checkpoint', 'signature', 'value'], 'A'.repeat(128)],
    [['checkpoint', 'signed_checkpoint', 'signature', 'value'], 'a'.repeat(127)],
    [['checkpoint', 'signed_checkpoint', 'signature', 'value'], 'a'.repeat(129)],
    [['checkpoint', 'signed_checkpoint', 'signature', 'value'], 'g'.repeat(128)],
    [['checkpoint', 'signed_checkpoint', 'signature', 'signed_at'], 1001],
  ]
  it.each(invalidSignature)('rejects incompatible signature structure or signed time at %j', (path, value) => {
    expectInvalid(withReportValue(path, value))
  })

  it('rejects successful verification without a checkpoint even when nothing claims coverage', () => {
    const report = makeReport()
    expectInvalid({
      ...report, checkpoint: null,
      event_bindings: report.event_bindings.map((binding) => ({ ...binding, covered: false })),
    })
  })

  it('rejects non-null checkpoints on failed verification even when no event claims coverage', () => {
    const failure = failedReport()
    expectInvalid({ ...failure, checkpoint: makeReport().checkpoint })
    expectInvalid({
      ...failure, checkpoint: makeReport().checkpoint,
      verification: { ...failure.verification, rollback_detected: true },
    })
  })

  it('preserves valid negative rollback reports whose verified event hash differs from the reported head', () => {
    const failure = failedReport()
    const rollback: AuditPrefixReport = {
      ...failure,
      verification: {
        ...failure.verification, rollback_detected: true,
        first_invalid_sequence: null, latest_event_hash: OTHER_HASH,
      },
    }
    expect(parseAuditPrefixReport(rollback)).toEqual(rollback)
    const result = auditPrefixObservation(TASK_ID, makeEvent(), rollback)
    expect(result.status).toBe('INVALID')
    expect(result).not.toHaveProperty('checkpoint')
    expect(auditPrefixSummary(TASK_ID, [makeEvent()], rollback)).toMatchObject({
      anchored: 0, total: 1, status: 'INVALID',
    })
  })

  it('rejects a checkpoint beyond the verified head, or a different hash at the same head', () => {
    expectInvalid(withReportValue(['checkpoint', 'signed_checkpoint', 'payload', 'latest_event_sequence'], 3))
    expectInvalid(withReportValue(['checkpoint', 'signed_checkpoint', 'payload', 'latest_event_hash'], OTHER_HASH))
    expectInvalid(withReportValue(['verification', 'latest_event_hash'], OTHER_HASH))
  })

  it('checks checkpoint hashes at an older head and verified hashes at the latest head', () => {
    const report = partiallyCoveredReport()
    expect(parseAuditPrefixReport(report)).not.toBeNull()
    expectInvalid(withReportValue(
      ['checkpoint', 'signed_checkpoint', 'payload', 'latest_event_hash'], OTHER_HASH, report,
    ))
    expectInvalid(withReportValue(['verification', 'latest_event_hash'], OTHER_HASH, report))
  })

  const inconsistentSuccess: Array<[FieldPath, unknown]> = [
    [['verification', 'rollback_detected'], true],
    [['verification', 'first_invalid_sequence'], 2],
    [['verification', 'checked_events'], 1],
    [['verification', 'checked_events'], 3],
    [['event_bindings', 0, 'matched'], false],
    [['event_bindings', 0, 'verified_event'], null],
  ]
  it.each(inconsistentSuccess)('rejects contradictory success or coverage at %j', (path, value) => {
    expectInvalid(withReportValue(path, value))
  })

  it('rejects every covered flag on failed verification or a missing anchor', () => {
    expectInvalid(withReportValue(['verification', 'valid'], false))
    const failure = failedReport()
    expectInvalid({
      ...failure,
      event_bindings: failure.event_bindings.map((binding) => ({ ...binding, covered: true })),
    })
  })

  it('rejects coverage beyond the checkpoint and applies this to the entire report', () => {
    const report = partiallyCoveredReport()
    const invalid = {
      ...report,
      event_bindings: report.event_bindings.map((binding) => ({ ...binding, covered: true })),
    }
    expectInvalid(invalid, makeEvent(1))
    expectInvalid(invalid, makeEvent(3))
    expect(auditPrefixSummary(TASK_ID, [makeEvent(1), makeEvent(2)], invalid)).toMatchObject({
      anchored: 0, total: 2, status: 'INVALID',
    })
  })

  it('rejects matched events beyond the verified head even without coverage', () => {
    const report = partiallyCoveredReport()
    expectInvalid({
      ...report,
      verification: {
        ...report.verification, checked_events: 1, latest_event_sequence: 1,
        latest_event_hash: makeEvent(1).event_hash,
      },
    })
  })

  it('requires sequence, id, and matched hash to agree with verified_event', () => {
    expectInvalid(withReportValue(['event_bindings', 0, 'verified_event', 'event_sequence'], 1))
    expectInvalid(withReportValue(['event_bindings', 0, 'verified_event', 'event_id'], 'another-event'))
    expectInvalid(withReportValue(['event_bindings', 0, 'event_hash'], OTHER_HASH))
  })

  it('requires null verified_event to have both matched and covered false', () => {
    const report = makeReport()
    const nullBinding = { ...report.event_bindings[0], matched: false, covered: false, verified_event: null }
    const allowed = { ...report, event_bindings: [nullBinding] }
    expect(parseAuditPrefixReport(allowed)).not.toBeNull()
    expect(auditPrefixObservation(TASK_ID, makeEvent(), allowed).status).toBe('INVALID')
    expectInvalid({ ...report, event_bindings: [{ ...nullBinding, matched: true }] })
    expectInvalid({ ...report, event_bindings: [{ ...nullBinding, covered: true }] })
  })

  it('detaches and freezes every parsed object without freezing the input', () => {
    const report = makeReport()
    const parsed = parseAuditPrefixReport(report)!
    expect(parsed).toEqual(report)
    for (const object of [
      parsed, parsed.verification, parsed.event_bindings, parsed.event_bindings[0],
      parsed.event_bindings[0].verified_event, parsed.checkpoint, parsed.checkpoint!.signed_checkpoint,
      parsed.checkpoint!.signed_checkpoint.payload, parsed.checkpoint!.signed_checkpoint.signature,
    ]) expect(Object.isFrozen(object)).toBe(true)
    expect(Object.isFrozen(report)).toBe(false)
    expect(parsed.checkpoint!.signed_checkpoint).not.toBe(report.checkpoint!.signed_checkpoint)
    expect(parsed.event_bindings[0].verified_event).not.toBe(report.event_bindings[0].verified_event)
    const originalHash = parsed.event_bindings[0].verified_event!.event_hash
    const mutableCore = report.event_bindings[0].verified_event as unknown as Record<string, unknown>
    mutableCore.event_hash = OTHER_HASH
    const mutablePayload = report.checkpoint!.signed_checkpoint.payload as unknown as Record<string, unknown>
    mutablePayload.latest_event_hash = OTHER_HASH
    expect(parsed.event_bindings[0].verified_event!.event_hash).toBe(originalHash)
    expect(parsed.checkpoint!.signed_checkpoint.payload.latest_event_hash).toBe(originalHash)
  })
})

describe('audit-prefix-binding-v1 current event observations', () => {
  it.each([null, undefined])('treats absent reports as NOT_CHECKED: %j', (report) => {
    expect(auditPrefixObservation(TASK_ID, makeEvent(), report).status).toBe('NOT_CHECKED')
  })

  it('treats another task or a missing binding as NOT_CHECKED', () => {
    const report = makeReport()
    expect(auditPrefixObservation('another-task', makeEvent(), report).status).toBe('NOT_CHECKED')
    expect(auditPrefixObservation(TASK_ID, makeEvent(3), report).status).toBe('NOT_CHECKED')
    expect(auditPrefixObservation(TASK_ID, makeEvent(3), failedReport()).status).toBe('NOT_CHECKED')
    const malformedOtherTask = { ...report, task_id: 'another-task', checkpoint: {} }
    expect(auditPrefixObservation(TASK_ID, makeEvent(), malformedOtherTask).status).toBe('NOT_CHECKED')
  })

  const changedCore: Array<[keyof AuditEventCore, unknown]> = [
    ['schema_version', '2.0'], ['event_sequence', 1], ['event_id', 'replacement-event'],
    ['execution_id', null], ['event_type', 'TOOL_DISPATCHED'], ['timestamp', 1001],
    ['payload_hash', OTHER_HASH], ['evidence_reference', 'replacement-evidence'],
    ['previous_event_hash', OTHER_HASH], ['event_hash', OTHER_HASH],
  ]
  it.each(changedCore)('expires old reports when current %s changes, including the same sequence', (field, value) => {
    const event = { ...makeEvent(), [field]: value } as AuditEventView
    const result = auditPrefixObservation(TASK_ID, event, makeReport())
    expect(result.status).toBe('NOT_CHECKED')
    expect(result).not.toHaveProperty('checkpoint')
  })

  it('does not coerce current event integer types or reuse UI evidence as verification', () => {
    for (const value of [true, '1000', null]) {
      const event = { ...makeEvent(), timestamp: value } as unknown as AuditEventView
      expect(auditPrefixObservation(TASK_ID, event, makeReport()).status).toBe('NOT_CHECKED')
    }
    const event = { ...makeEvent(), coauthorization_evidence: { changed: true }, evidence_binding_valid: false }
    expect(auditPrefixObservation(TASK_ID, event, makeReport()).status).toBe('ANCHORED')
  })

  it('allows an unmatched requested hash to differ from the actual verified hash for stale observations', () => {
    const actual = makeEvent()
    const requested = { ...actual, event_hash: OTHER_HASH }
    const report = makeReport([actual])
    const stale: AuditPrefixReport = {
      ...report,
      event_bindings: [{
        ...report.event_bindings[0], event_hash: requested.event_hash, matched: false, covered: false,
      }],
    }
    expect(parseAuditPrefixReport(stale)).not.toBeNull()
    expect(auditPrefixObservation(TASK_ID, requested, stale).status).toBe('NOT_CHECKED')
    expect(auditPrefixObservation(TASK_ID, actual, stale).status).toBe('NOT_CHECKED')
    expectInvalid({
      ...stale, event_bindings: stale.event_bindings.map((binding) => ({ ...binding, matched: true })),
    })
  })

  it('reports explicit server failures as INVALID without attaching a checkpoint', () => {
    const failure = failedReport()
    expect(parseAuditPrefixReport(failure)).not.toBeNull()
    expect(auditPrefixObservation(TASK_ID, makeEvent(), failure)).toMatchObject({ status: 'INVALID' })
    const rollback = {
      ...failure, verification: { ...failure.verification, rollback_detected: true, first_invalid_sequence: null },
    }
    expect(auditPrefixObservation(TASK_ID, makeEvent(), rollback).status).toBe('INVALID')
    const unmatched = {
      ...makeReport(), event_bindings: [{ ...makeReport().event_bindings[0], matched: false, covered: false }],
    }
    expect(auditPrefixObservation(TASK_ID, makeEvent(), unmatched).status).toBe('INVALID')
    expect(auditPrefixObservation(TASK_ID, makeEvent(), failure)).not.toHaveProperty('checkpoint')
  })

  it('returns UNANCHORED for a matching event outside coverage and never infers covered from sequence alone', () => {
    const partial = partiallyCoveredReport()
    expect(auditPrefixObservation(TASK_ID, makeEvent(1), partial).status).toBe('ANCHORED')
    const result = auditPrefixObservation(TASK_ID, makeEvent(2), partial)
    expect(result.status).toBe('UNANCHORED')
    expect(result.checkpoint).toEqual(partial.checkpoint)
    expect(Object.isFrozen(result.checkpoint?.signed_checkpoint)).toBe(true)
    expect(auditPrefixObservation(TASK_ID, makeEvent(), withReportValue(
      ['event_bindings', 0, 'covered'], false,
    )).status).toBe('UNANCHORED')
  })

  it('uses the requested compact Chinese label for every observation', () => {
    const observations = [
      auditPrefixObservation(TASK_ID, makeEvent(), makeReport()),
      auditPrefixObservation(TASK_ID, makeEvent(2), partiallyCoveredReport()),
      auditPrefixObservation(TASK_ID, makeEvent(), failedReport()),
      auditPrefixObservation(TASK_ID, makeEvent(), null),
    ]
    expect(observations.map((entry) => entry.status)).toEqual(['ANCHORED', 'UNANCHORED', 'INVALID', 'NOT_CHECKED'])
    expect(observations.map((entry) => entry.label)).toEqual([
      '服务端核验：已覆盖', '服务端核验：尚未覆盖', '服务端核验：未通过', '逐事件覆盖未核验',
    ])
  })
})

describe('audit-prefix-binding-v1 retained event head limit', () => {
  it('rejects a nonnull core beyond a positive head even when marked unmatched and uncovered', () => {
    const event = makeEvent(3)
    const report = makeReport()
    const changed: AuditPrefixReport = { ...report, event_bindings: [{
      event_sequence: event.event_sequence, event_id: event.event_id, event_hash: event.event_hash,
      matched: false, covered: false, verified_event: auditEventCore(event) as VerifiedAuditEventCore,
    }] }
    expect(parseAuditPrefixReport(changed)).toBeNull()
    expect(auditPrefixObservation(TASK_ID, event, changed).status).toBe('INVALID')
  })
})

describe('audit-prefix-binding-v1 summary observations', () => {
  it.each([null, makeReport(), { malformed: true }])('keeps empty events NOT_CHECKED for any report: %j', (report) => {
    const result = auditPrefixSummary(TASK_ID, [], report)
    expect(result).toMatchObject({ anchored: 0, total: 0, status: 'NOT_CHECKED' })
    expect(result.label).toBe('暂无审计事件')
  })

  it('requires every event to be ANCHORED, including a mixture of V1 and V2', () => {
    const events = [makeEvent(1), makeEvent(2, '2.0')]
    expect(auditPrefixSummary(TASK_ID, events, makeReport(events))).toMatchObject({
      anchored: 2, total: 2, status: 'ANCHORED',
    })
  })

  it('returns UNANCHORED for a mixture of anchored and uncovered events', () => {
    expect(auditPrefixSummary(TASK_ID, [makeEvent(1), makeEvent(2)], partiallyCoveredReport())).toMatchObject({
      anchored: 1, total: 2, status: 'UNANCHORED',
    })
  })

  it('gives NOT_CHECKED priority over UNANCHORED while preserving the anchored count', () => {
    expect(auditPrefixSummary(
      TASK_ID, [makeEvent(1), makeEvent(2), makeEvent(3)], partiallyCoveredReport(),
    )).toMatchObject({ anchored: 1, total: 3, status: 'NOT_CHECKED' })
    const events = [makeEvent(1), makeEvent(2)]
    expect(auditPrefixSummary(TASK_ID, [events[0], { ...events[1], event_hash: OTHER_HASH }], makeReport(events)))
      .toMatchObject({ anchored: 1, total: 2, status: 'NOT_CHECKED' })
    expect(auditPrefixSummary('another-task', events, makeReport(events)))
      .toMatchObject({ anchored: 0, total: 2, status: 'NOT_CHECKED' })
    expect(auditPrefixSummary(TASK_ID, events, null))
      .toMatchObject({ anchored: 0, total: 2, status: 'NOT_CHECKED' })
  })

  it('gives INVALID priority over NOT_CHECKED and UNANCHORED', () => {
    const events = [makeEvent(1), makeEvent(2), makeEvent(3)]
    const report = makeReport(events)
    const mixed: AuditPrefixReport = {
      ...report,
      checkpoint: partiallyCoveredReport().checkpoint,
      event_bindings: report.event_bindings.map((binding) => ({
        ...binding, matched: binding.event_sequence !== 2, covered: binding.event_sequence === 1,
      })),
    }
    expect(auditPrefixSummary(TASK_ID, [...events, makeEvent(4)], mixed)).toMatchObject({
      anchored: 1, total: 4, status: 'INVALID',
    })
    expect(auditPrefixSummary(TASK_ID, events, failedReport())).toMatchObject({
      anchored: 0, total: 3, status: 'INVALID',
    })
  })

  it('rejects overview fields and uses the requested compact summary labels', () => {
    const report = { ...makeReport(), overview: { audit_valid: true, checkpoint: makeReport().checkpoint } }
    expect(auditPrefixSummary(TASK_ID, [makeEvent()], report)).toMatchObject({
      anchored: 0, total: 1, status: 'INVALID',
    })
    const summaries = [
      auditPrefixSummary(TASK_ID, [makeEvent()], makeReport()),
      auditPrefixSummary(TASK_ID, [makeEvent(2)], partiallyCoveredReport()),
      auditPrefixSummary(TASK_ID, [makeEvent()], failedReport()),
      auditPrefixSummary(TASK_ID, [makeEvent()], null),
      auditPrefixSummary(TASK_ID, [], null),
    ]
    expect(summaries.map((summary) => summary.label)).toEqual([
      '服务端核验：全部覆盖', '服务端核验：部分未覆盖', '服务端核验：未通过', '存在未核验事件', '暂无审计事件',
    ])
  })
})
