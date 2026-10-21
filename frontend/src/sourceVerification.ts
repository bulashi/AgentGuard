import type { ReceiptView, SourceVerification } from './types'

export type SourceVerificationState = 'VERIFIED' | 'INVALID' | 'INCOMPLETE'

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

/** Observes explicit BFF flags only; this never performs client-side cryptography. */
export function sourceVerificationState(value: unknown, profile: SourceVerification['profile']): SourceVerificationState {
  if (!isRecord(value) || value.schema_version !== '1.0' || value.profile !== profile) return 'INCOMPLETE'
  const flags = [value.schema_valid, value.stored_hash_valid, value.row_binding_valid]
  if (profile === 'RECEIPT_EXECUTION_BINDING_V1') flags.push(value.execution_binding_valid)
  else if (value.execution_binding_valid !== null) return 'INCOMPLETE'
  if (flags.some((flag) => typeof flag !== 'boolean')) return 'INCOMPLETE'
  return flags.every((flag) => flag === true) ? 'VERIFIED' : 'INVALID'
}

export function observeReceipt(receipt: ReceiptView): { status: 'VALID' | 'INVALID' | 'INCOMPLETE'; label: string } {
  const sourceState = sourceVerificationState(receipt.source_verification, 'RECEIPT_EXECUTION_BINDING_V1')
  const valid = receipt.signature?.valid
  if (typeof valid !== 'boolean' || sourceState === 'INCOMPLETE') {
    return { status: 'INCOMPLETE', label: '核对信息不完整' }
  }
  if (valid !== true || sourceState !== 'VERIFIED' || receipt.receipt_status !== 'SIGNED') {
    return { status: 'INVALID', label: '核对未通过' }
  }
  return { status: 'VALID', label: '签名与绑定一致' }
}

export function receiptEvidenceIsConsistent(receipt: ReceiptView): boolean {
  return observeReceipt(receipt).status === 'VALID'
}
