import { describe, expect, it } from 'vitest'
import { observeCredential } from './credentialObservation'
import type { CredentialObservationCode } from './credentialObservation'
import type { CredentialView } from './types'

// Synthetic BFF projection vectors only; these flags are not cryptographic proof.
function credential(overrides: Record<string, unknown> = {}): CredentialView {
  return {
    credential_id: 'cred-root',
    credential_type: 'ROOT',
    parent_credential_id: null,
    parent_credential_hash: null,
    signed_object_hash: 'root-hash',
    stored_hash_valid: true,
    source_verification: { schema_version: '1.0', profile: 'CREDENTIAL_ROW_BINDING_V1', schema_valid: true,
      stored_hash_valid: true, row_binding_valid: true, execution_binding_valid: null },
    issuer_subject_id: 'authority',
    issuer_key_id: 'authority-key',
    holder_agent_id: 'agent-coordinator',
    holder_key_id: 'agent-coordinator-key',
    not_before: 100,
    expires_at: 200,
    delegation_depth: 2,
    issued_at: 100,
    revoked_at: null,
    revocation_reason: null,
    capabilities: [],
    budgets: [],
    signature: {
      algorithm: 'SM2',
      key_id: 'authority-key',
      fingerprint_sm3: 'fingerprint',
      valid: true,
    },
    ...overrides,
  } as CredentialView
}

interface ObservationVector {
  name: string
  candidate: CredentialView | null | undefined
  credentials: readonly CredentialView[]
  nowSeconds: number
  code: CredentialObservationCode
}

const root = credential()
const intermediate = credential({
  credential_id: 'cred-intermediate',
  credential_type: 'DELEGATION',
  parent_credential_id: root.credential_id,
  parent_credential_hash: root.signed_object_hash,
  signed_object_hash: 'intermediate-hash',
})
const leaf = credential({
  credential_id: 'cred-leaf',
  credential_type: 'DELEGATION',
  parent_credential_id: intermediate.credential_id,
  parent_credential_hash: intermediate.signed_object_hash,
  signed_object_hash: 'leaf-hash',
})
const first = credential({
  credential_id: 'cred-first', credential_type: 'DELEGATION',
  signed_object_hash: 'first-hash',
  parent_credential_id: 'cred-second', parent_credential_hash: 'second-hash',
})
const second = credential({
  credential_id: 'cred-second', credential_type: 'DELEGATION',
  signed_object_hash: 'second-hash',
  parent_credential_id: 'cred-first', parent_credential_hash: 'first-hash',
})

const vectors: ObservationVector[] = [
  { name: 'old BFF without source verification', candidate: credential({ source_verification: undefined }), credentials: [], nowSeconds: 150, code: 'INCOMPLETE' },
  { name: 'mismatched signed row', candidate: credential({ source_verification: { ...root.source_verification, row_binding_valid: false } }), credentials: [], nowSeconds: 150, code: 'SOURCE_BINDING_INVALID' },
  { name: 'null credential', candidate: null, credentials: [], nowSeconds: 150, code: 'MISSING' },
  { name: 'undefined credential', candidate: undefined, credentials: [], nowSeconds: 150, code: 'MISSING' },
  { name: 'root lower boundary inclusive', candidate: root, credentials: [], nowSeconds: 100, code: 'WINDOW_OPEN' },
  { name: 'root within window', candidate: root, credentials: [], nowSeconds: 199.5, code: 'WINDOW_OPEN' },
  { name: 'root before lower boundary', candidate: root, credentials: [], nowSeconds: 99, code: 'NOT_YET_VALID' },
  { name: 'root upper boundary exclusive', candidate: root, credentials: [], nowSeconds: 200, code: 'EXPIRED' },
  { name: 'root after upper boundary', candidate: root, credentials: [], nowSeconds: 201, code: 'EXPIRED' },
  { name: 'two delegation levels', candidate: leaf, credentials: [leaf, intermediate, root], nowSeconds: 150, code: 'WINDOW_OPEN' },
  { name: 'current revoked at zero', candidate: credential({ revoked_at: 0 }), credentials: [], nowSeconds: 150, code: 'REVOKED' },
  { name: 'current revoked at nonzero', candidate: credential({ revoked_at: 125 }), credentials: [], nowSeconds: 150, code: 'REVOKED' },
  { name: 'intermediate ancestor revoked at zero', candidate: leaf, credentials: [credential({ ...intermediate, revoked_at: 0 }), root], nowSeconds: 150, code: 'ANCESTOR_REVOKED' },
  { name: 'root ancestor revoked', candidate: leaf, credentials: [intermediate, credential({ revoked_at: 125 })], nowSeconds: 150, code: 'ANCESTOR_REVOKED' },
  { name: 'missing parent', candidate: intermediate, credentials: [], nowSeconds: 150, code: 'PARENT_LINK_INVALID' },
  { name: 'missing grandparent', candidate: leaf, credentials: [intermediate], nowSeconds: 150, code: 'PARENT_LINK_INVALID' },
  { name: 'parent hash mismatch', candidate: credential({ ...intermediate, parent_credential_hash: 'wrong-hash' }), credentials: [root], nowSeconds: 150, code: 'PARENT_LINK_INVALID' },
  { name: 'parent hash case mismatch', candidate: credential({ ...intermediate, parent_credential_hash: 'ROOT-HASH' }), credentials: [root], nowSeconds: 150, code: 'PARENT_LINK_INVALID' },
  { name: 'grandparent hash mismatch', candidate: leaf, credentials: [credential({ ...intermediate, parent_credential_hash: 'wrong-hash' }), root], nowSeconds: 150, code: 'PARENT_LINK_INVALID' },
  { name: 'self cycle', candidate: credential({ ...intermediate, parent_credential_id: intermediate.credential_id, parent_credential_hash: intermediate.signed_object_hash }), credentials: [intermediate], nowSeconds: 150, code: 'PARENT_LINK_INVALID' },
  { name: 'two node cycle', candidate: first, credentials: [first, second], nowSeconds: 150, code: 'PARENT_LINK_INVALID' },
  { name: 'ancestor not yet valid', candidate: intermediate, credentials: [credential({ not_before: 160 })], nowSeconds: 150, code: 'NOT_YET_VALID' },
  { name: 'ancestor expired at boundary', candidate: intermediate, credentials: [credential({ expires_at: 150 })], nowSeconds: 150, code: 'EXPIRED' },
]

for (const value of [false, 'true', 1, null, undefined]) {
  vectors.push(
    { name: `signature valid must be true: ${String(value)}`, candidate: credential({ signature: { ...root.signature, valid: value } }), credentials: [], nowSeconds: 150, code: 'SIGNATURE_INVALID' },
    { name: `stored hash must be true: ${String(value)}`, candidate: credential({ stored_hash_valid: value }), credentials: [], nowSeconds: 150, code: 'SIGNATURE_INVALID' },
  )
}

for (const value of [undefined, '0', false, Number.NaN, Number.POSITIVE_INFINITY]) {
  vectors.push(
    { name: `unreliable revocation: ${String(value)}`, candidate: credential({ revoked_at: value }), credentials: [], nowSeconds: 150, code: 'INCOMPLETE' },
    { name: `unreliable ancestor revocation: ${String(value)}`, candidate: intermediate, credentials: [credential({ revoked_at: value })], nowSeconds: 150, code: 'INCOMPLETE' },
  )
}

for (const value of [Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY]) {
  vectors.push({ name: `nonfinite observation time: ${String(value)}`, candidate: root, credentials: [], nowSeconds: value, code: 'INCOMPLETE' })
}

for (const field of ['not_before', 'expires_at']) {
  for (const value of [undefined, null, '100', Number.NaN, Number.POSITIVE_INFINITY]) {
    vectors.push({ name: `unreliable ${field}: ${String(value)}`, candidate: credential({ [field]: value }), credentials: [], nowSeconds: 150, code: 'INCOMPLETE' })
  }
}

for (const field of ['parent_credential_id', 'parent_credential_hash']) {
  for (const value of [undefined, false, 0, '', {}]) {
    vectors.push(
      { name: `unreliable root ${field}: ${String(value)}`, candidate: credential({ [field]: value }), credentials: [], nowSeconds: 150, code: 'INCOMPLETE' },
      { name: `unreliable ancestor ${field}: ${String(value)}`, candidate: intermediate, credentials: [credential({ [field]: value })], nowSeconds: 150, code: 'INCOMPLETE' },
    )
  }
}

vectors.push(
  { name: 'ROOT must not have a parent', candidate: credential({ parent_credential_id: 'cred-parent', parent_credential_hash: 'parent-hash' }), credentials: [credential({ credential_id: 'cred-parent', signed_object_hash: 'parent-hash' })], nowSeconds: 150, code: 'PARENT_LINK_INVALID' },
  { name: 'ROOT with only parent ID', candidate: credential({ parent_credential_id: 'cred-parent' }), credentials: [], nowSeconds: 150, code: 'PARENT_LINK_INVALID' },
  { name: 'ROOT with only parent hash', candidate: credential({ parent_credential_hash: 'parent-hash' }), credentials: [], nowSeconds: 150, code: 'PARENT_LINK_INVALID' },
  { name: 'DELEGATION must not be parentless', candidate: credential({ credential_type: 'DELEGATION' }), credentials: [], nowSeconds: 150, code: 'PARENT_LINK_INVALID' },
  { name: 'DELEGATION with null parent ID', candidate: credential({ ...intermediate, parent_credential_id: null }), credentials: [root], nowSeconds: 150, code: 'PARENT_LINK_INVALID' },
  { name: 'DELEGATION with null parent hash', candidate: credential({ ...intermediate, parent_credential_hash: null }), credentials: [root], nowSeconds: 150, code: 'PARENT_LINK_INVALID' },
  { name: 'ancestor ROOT must not have a parent', candidate: intermediate, credentials: [credential({ parent_credential_id: 'unexpected', parent_credential_hash: 'unexpected-hash' })], nowSeconds: 150, code: 'PARENT_LINK_INVALID' },
  { name: 'unknown credential kind', candidate: credential({ credential_type: 'UNKNOWN' }), credentials: [], nowSeconds: 150, code: 'INCOMPLETE' },
  { name: 'missing signature object', candidate: credential({ signature: undefined }), credentials: [], nowSeconds: 150, code: 'INCOMPLETE' },
  { name: 'array signature', candidate: credential({ signature: [] }), credentials: [], nowSeconds: 150, code: 'INCOMPLETE' },
  { name: 'missing ancestor hash', candidate: intermediate, credentials: [credential({ signed_object_hash: undefined })], nowSeconds: 150, code: 'INCOMPLETE' },
  { name: 'unreliable ancestor signature flag', candidate: intermediate, credentials: [credential({ signature: { ...root.signature, valid: 'true' } })], nowSeconds: 150, code: 'SIGNATURE_INVALID' },
  { name: 'unreliable ancestor stored hash flag', candidate: intermediate, credentials: [credential({ stored_hash_valid: 'true' })], nowSeconds: 150, code: 'SIGNATURE_INVALID' },
  { name: 'empty time interval', candidate: credential({ expires_at: 100 }), credentials: [], nowSeconds: 150, code: 'INCOMPLETE' },
  { name: 'inverted time interval', candidate: credential({ expires_at: 99 }), credentials: [], nowSeconds: 150, code: 'INCOMPLETE' },
  { name: 'duplicate parent ID', candidate: intermediate, credentials: [root, credential({})], nowSeconds: 150, code: 'INCOMPLETE' },
  { name: 'missing ID in collection', candidate: intermediate, credentials: [credential({ credential_id: undefined })], nowSeconds: 150, code: 'INCOMPLETE' },
  { name: 'nonobject credential', candidate: 0 as unknown as CredentialView, credentials: [], nowSeconds: 150, code: 'INCOMPLETE' },
  { name: 'nonarray collection', candidate: root, credentials: null as unknown as CredentialView[], nowSeconds: 150, code: 'INCOMPLETE' },
  { name: 'nonobject collection entry', candidate: intermediate, credentials: [null as unknown as CredentialView], nowSeconds: 150, code: 'INCOMPLETE' },
)

describe('observeCredential', () => {
  it.each(vectors)('$name', ({ candidate, credentials, nowSeconds, code }) => {
    const result = observeCredential(candidate, credentials, nowSeconds)
    expect(result.code).toBe(code)
    expect(result.windowOpen).toBe(code === 'WINDOW_OPEN')
    expect(result.label.length).toBeGreaterThan(0)
    expect(result.detail).toContain('未校验公钥、租户、全部任务约束及 Gateway 准入')
    expect(result).not.toHaveProperty('permissionEligible')
  })
})
