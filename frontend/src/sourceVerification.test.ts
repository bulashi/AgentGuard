import { describe, expect, it } from 'vitest'
import { observeReceipt, receiptEvidenceIsConsistent, sourceVerificationState } from './sourceVerification'
import { buildExecutionSteps } from './executionModel'
import { savedSnapshot } from './test/fixtures'
import type { SourceVerification } from './types'

// Display flags only. No vector here proves cryptographic validity or real effects.
const credentialSource: SourceVerification = {
  schema_version: '1.0', profile: 'CREDENTIAL_ROW_BINDING_V1', schema_valid: true,
  stored_hash_valid: true, row_binding_valid: true, execution_binding_valid: null,
}
const receiptSource: SourceVerification = {
  ...credentialSource, profile: 'RECEIPT_EXECUTION_BINDING_V1', execution_binding_valid: true,
}

describe('signed source observations', () => {
  it('accepts only complete matching profiles with strict booleans', () => {
    expect(sourceVerificationState(credentialSource, 'CREDENTIAL_ROW_BINDING_V1')).toBe('VERIFIED')
    expect(sourceVerificationState(receiptSource, 'RECEIPT_EXECUTION_BINDING_V1')).toBe('VERIFIED')
    expect(sourceVerificationState(credentialSource, 'RECEIPT_EXECUTION_BINDING_V1')).toBe('INCOMPLETE')
    expect(sourceVerificationState(receiptSource, 'CREDENTIAL_ROW_BINDING_V1')).toBe('INCOMPLETE')
  })

  it.each([null, undefined, [], 'true', {}, { ...receiptSource, schema_version: '2.0' }, { ...credentialSource, execution_binding_valid: true }])(
    'does not accept incomplete or incompatible source metadata: %j', (value) => {
      expect(sourceVerificationState(value, 'RECEIPT_EXECUTION_BINDING_V1')).toBe('INCOMPLETE')
    },
  )

  for (const field of ['schema_valid', 'stored_hash_valid', 'row_binding_valid', 'execution_binding_valid']) {
    it(`distinguishes explicit false from missing or truthy ${field}`, () => {
      expect(sourceVerificationState({ ...receiptSource, [field]: false }, 'RECEIPT_EXECUTION_BINDING_V1')).toBe('INVALID')
      for (const value of [undefined, null, 'true', 1, [], {}]) {
        expect(sourceVerificationState({ ...receiptSource, [field]: value }, 'RECEIPT_EXECUTION_BINDING_V1')).toBe('INCOMPLETE')
      }
    })
  }

  it('never accepts a valid signature alone as receipt binding evidence', () => {
    const receipt = savedSnapshot.receipts[0]
    expect(receiptEvidenceIsConsistent(receipt)).toBe(true)
    expect(observeReceipt({ ...receipt, source_verification: undefined }).status).toBe('INCOMPLETE')
    expect(receiptEvidenceIsConsistent({ ...receipt, source_verification: undefined })).toBe(false)
    expect(observeReceipt({ ...receipt, source_verification: { ...receiptSource, row_binding_valid: false } }).status).toBe('INVALID')
    expect(receiptEvidenceIsConsistent({ ...receipt, signature: { ...receipt.signature, valid: false } })).toBe(false)
    expect(receiptEvidenceIsConsistent({ ...receipt, receipt_status: 'PENDING' })).toBe(false)
  })

  it('uses the same binding requirement for the persisted receipt timeline', () => {
    const receipt = savedSnapshot.receipts[0]
    for (const [source, expected] of [[receiptSource, 'SIGNED'], [undefined, 'INCOMPLETE'], [{ ...receiptSource, row_binding_valid: false }, 'INVALID']] as const) {
      const snapshot = { ...savedSnapshot, receipts: [{ ...receipt, source_verification: source }] }
      expect(buildExecutionSteps(snapshot, null).find((step) => step.selection.kind === 'receipt')?.status).toBe(expected)
    }
  })
})
