import type { CredentialView } from './types'
import { sourceVerificationState } from './sourceVerification'

export type CredentialObservationCode =
  | 'MISSING'
  | 'SIGNATURE_INVALID'
  | 'SOURCE_BINDING_INVALID'
  | 'REVOKED'
  | 'NOT_YET_VALID'
  | 'EXPIRED'
  | 'ANCESTOR_REVOKED'
  | 'PARENT_LINK_INVALID'
  | 'WINDOW_OPEN'
  | 'INCOMPLETE'

export interface CredentialObservation {
  code: CredentialObservationCode
  label: string
  detail: string
  /** UI observation only, never an execution authorization decision. */
  windowOpen: boolean
}

type RuntimeCredential = Record<string, unknown>

const LABELS: Record<CredentialObservationCode, string> = {
  MISSING: '凭证缺失',
  SIGNATURE_INVALID: '签名或哈希未通过',
  SOURCE_BINDING_INVALID: '签名来源绑定未通过',
  REVOKED: '凭证已撤销',
  NOT_YET_VALID: '尚未生效',
  EXPIRED: '凭证已过期',
  ANCESTOR_REVOKED: '祖先凭证已撤销',
  PARENT_LINK_INVALID: '父链连接无效',
  WINDOW_OPEN: '当前时间窗开放',
  INCOMPLETE: '投影信息不完整',
}

function observation(code: CredentialObservationCode, detail: string): CredentialObservation {
  return {
    code,
    label: LABELS[code],
    detail: `${detail} 未校验公钥、租户、全部任务约束及 Gateway 准入。`,
    windowOpen: code === 'WINDOW_OPEN',
  }
}

function isRecord(value: unknown): value is RuntimeCredential {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function isFiniteNumber(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value)
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0
}

function projectionProblem(credential: RuntimeCredential): CredentialObservation | null {
  if (
    !isNonEmptyString(credential.credential_id) ||
    !isNonEmptyString(credential.signed_object_hash) ||
    !isFiniteNumber(credential.not_before) ||
    !isFiniteNumber(credential.expires_at) ||
    credential.expires_at <= credential.not_before ||
    (credential.revoked_at !== null && !isFiniteNumber(credential.revoked_at)) ||
    !isRecord(credential.signature)
  ) {
    return observation('INCOMPLETE', '凭证观测字段缺失、类型不可靠或时间区间无效。')
  }
  if (credential.signature.valid !== true || credential.stored_hash_valid !== true) {
    return observation('SIGNATURE_INVALID', 'BFF 签名或存储哈希标记不为严格 true；此处不执行客户端验签。')
  }
  const sourceState = sourceVerificationState(credential.source_verification, 'CREDENTIAL_ROW_BINDING_V1')
  if (sourceState === 'INCOMPLETE') {
    return observation('INCOMPLETE', '缺少完整的 BFF 签名来源核对结果，不能确认显示字段绑定到签名载荷。')
  }
  if (sourceState !== 'VERIFIED') {
    return observation('SOURCE_BINDING_INVALID', 'BFF 原文 Schema、存储哈希或数据库列绑定核对未通过。')
  }

  const parentId = credential.parent_credential_id
  const parentHash = credential.parent_credential_hash
  if (
    (parentId !== null && !isNonEmptyString(parentId)) ||
    (parentHash !== null && !isNonEmptyString(parentHash)) ||
    (credential.credential_type !== 'ROOT' && credential.credential_type !== 'DELEGATION')
  ) {
    return observation('INCOMPLETE', '凭证种类或父链字段缺失、类型不可靠。')
  }
  if (credential.credential_type === 'ROOT') {
    if (parentId !== null || parentHash !== null) {
      return observation('PARENT_LINK_INVALID', 'ROOT 的父凭证 ID 和父凭证哈希必须同时为 null。')
    }
  } else if (parentId === null || parentHash === null) {
    return observation('PARENT_LINK_INVALID', '委托凭证必须同时提供父凭证 ID 和父凭证哈希。')
  }
  return null
}

function indexCredentials(credentials: readonly CredentialView[]): Map<string, RuntimeCredential> | null {
  const indexed = new Map<string, RuntimeCredential>()
  for (const item of credentials) {
    if (!isRecord(item) || !isNonEmptyString(item.credential_id)) return null
    if (indexed.has(item.credential_id)) return null
    indexed.set(item.credential_id, item)
  }
  return indexed
}

/**
 * Observes the BFF's projected credential state at one local observation time.
 * This deliberately does not reimplement Gateway admission or cryptography.
 */
export function observeCredential(
  credential: CredentialView | null | undefined,
  credentials: readonly CredentialView[],
  nowSeconds: number,
): CredentialObservation {
  if (credential === null || credential === undefined) {
    return observation('MISSING', '没有可供界面观测的凭证投影；不得据此推断授权状态。')
  }
  if (!isFiniteNumber(nowSeconds) || !isRecord(credential)) {
    return observation('INCOMPLETE', '观测时间不是有限数值或凭证投影不是可靠对象。')
  }
  if (!Array.isArray(credentials)) {
    return observation('INCOMPLETE', '凭证集合不是可靠数组；父链无法完成观测。')
  }

  const indexed = indexCredentials(credentials)
  if (indexed === null) {
    return observation('INCOMPLETE', '凭证集合含有缺失或重复身份标识；父链观测无法可靠完成。')
  }
  const visited = new Set<string>()
  const chain: RuntimeCredential[] = []
  let current: RuntimeCredential = credential

  // Collect the entire projected chain before reporting its time-window state.
  while (true) {
    const problem = projectionProblem(current)
    if (problem) return problem
    const id = current.credential_id as string
    if (visited.has(id)) {
      return observation('PARENT_LINK_INVALID', '父凭证链出现环，无法可靠观测。')
    }
    visited.add(id)
    chain.push(current)
    if (current.credential_type === 'ROOT') break

    const parentId = current.parent_credential_id as string
    if (visited.has(parentId)) {
      return observation('PARENT_LINK_INVALID', '父凭证链出现环，无法可靠观测。')
    }
    const parent = indexed.get(parentId)
    if (!parent) {
      return observation('PARENT_LINK_INVALID', '投影集合中不存在所引用的父凭证。')
    }
    if (!isNonEmptyString(parent.signed_object_hash)) {
      return observation('INCOMPLETE', '父凭证的 signed_object_hash 缺失或类型不可靠。')
    }
    if (current.parent_credential_hash !== parent.signed_object_hash) {
      return observation('PARENT_LINK_INVALID', '父凭证哈希与父凭证 signed_object_hash 不完全相等。')
    }
    current = parent
  }

  if (chain[0].revoked_at !== null) {
    return observation('REVOKED', '当前凭证投影有明确的数值撤销时间（包括 0）。')
  }
  if (chain.slice(1).some((ancestor) => ancestor.revoked_at !== null)) {
    return observation('ANCESTOR_REVOKED', '父链中存在有明确数值撤销时间的祖先凭证。')
  }
  for (const [index, item] of chain.entries()) {
    const subject = index === 0 ? '当前凭证' : '祖先凭证'
    if (nowSeconds < (item.not_before as number)) {
      return observation('NOT_YET_VALID', `${subject}尚未进入时间窗 [not_before, expires_at)。`)
    }
    if (nowSeconds >= (item.expires_at as number)) {
      return observation('EXPIRED', `${subject}已离开时间窗 [not_before, expires_at)。`)
    }
  }
  return observation('WINDOW_OPEN', '当前凭证及父链的投影观测时间窗开放；BFF 校验标记为 true，未观测到撤销或连接异常。')
}
