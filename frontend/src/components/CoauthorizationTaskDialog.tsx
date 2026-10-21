import { useId, useLayoutEffect, useRef, useState } from 'react'
import { Checkbox, Descriptions, Input, InputNumber, Modal, Tag, Tooltip } from 'antd'
import { Building2, ChevronLeft, ChevronRight, CircleAlert, Download, Eye, FilePlus2, FileUp, History, RefreshCw, ShieldCheck, UsersRound, Wallet, X } from 'lucide-react'
import { api, ApiError } from '../api'
import type {
  CoauthorizationApprovalPayload, CoauthorizationCapability, CoauthorizationChallenge,
  CoauthorizationHistoryEntry, CoauthorizationResult, CoauthorizationStatus, CoauthorizationTaskReview,
} from '../types'
import { Fen, StatusTag, TimeValue } from './Evidence'
import { LiquidGlassButton } from './LiquidGlassButton'
import '../coauthorization-task.css'

const MAX_BUNDLE_BYTES = 32768
const HISTORY_PAGE_SIZE = 20
const MAX_HISTORY_OFFSET = 1_000_000
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]*$/
type Mutation = 'challenge' | 'authorize'
type Session = { taskId: string; sequence: number }

interface DialogState {
  open: boolean
  authority: CoauthorizationStatus | null
  review: CoauthorizationTaskReview | null
  challenge: CoauthorizationChallenge | null
  result: CoauthorizationResult | null
  authorityLoading: boolean
  historyLoading: boolean
  fileLoading: boolean
  requiresHistoryRefresh: boolean
  mutation: Mutation | null
  authorityError: string | null
  historyError: string | null
  mutationError: string | null
  inputError: string | null
  refreshError: string | null
  downloadError: string | null
  offset: number
  holderAgentId: string
  holderKeyId: string
  delegationDepth: number | null
  rawJson: string
  confirmed: boolean
}

function initialState(): DialogState {
  return {
    open: false, authority: null, review: null, challenge: null, result: null,
    authorityLoading: false, historyLoading: false, fileLoading: false, requiresHistoryRefresh: false, mutation: null,
    authorityError: null, historyError: null, mutationError: null, inputError: null,
    refreshError: null, downloadError: null, offset: 0,
    holderAgentId: 'agent-coordinator', holderKeyId: 'agent-coordinator-key-01', delegationDepth: 2,
    rawJson: '', confirmed: false,
  }
}

function failure(error: unknown, message: string) {
  return error instanceof ApiError ? `${message}（${error.reasonCode}，HTTP ${error.status}）` : message
}

function inputError(rawJson: string) {
  if (new TextEncoder().encode(rawJson).byteLength > MAX_BUNDLE_BYTES) return '签名包超过 32768 字节，不能提交。'
  return rawJson.trim() ? null : '签名包为空，不能提交。'
}

function validIdentifier(value: string) {
  return value.length <= 128 && IDENTIFIER.test(value)
}

function ErrorLine({ message }: { message: string | null }) {
  return message ? <div role="alert" className="coauth-task-error"><CircleAlert size={15} /><span>{message}</span></div> : null
}

function PayloadDetails({ payload, capabilities }: {
  payload: CoauthorizationApprovalPayload; capabilities: CoauthorizationCapability[]
}) {
  return <>
    <Descriptions column={1} size="small" colon={false} className="coauth-task-fields" items={[
      { key: 'task', label: '任务', children: <code>{payload.task_id}</code> },
      { key: 'tenant', label: '租户', children: <code>{payload.tenant_id}</code> },
      { key: 'ticket', label: '工单', children: <code>{payload.ticket_id}</code> },
      { key: 'customer', label: '客户', children: <code>{payload.customer_id}</code> },
      { key: 'quota', label: '任务额度', children: <span>退款 <Fen value={payload.quotas.refund_total_fen} /> · 工具调用 {payload.quotas.max_tool_calls} 次</span> },
      { key: 'holder', label: '持有者', children: <span><code>{payload.holder.agent_id}</code> / <code>{payload.holder.key_id}</code></span> },
      { key: 'depth', label: '委托深度', children: payload.delegation_depth },
      { key: 'policy', label: '策略修订', children: <code>{payload.policy_revision}</code> },
      { key: 'capability-hash', label: '能力摘要', children: <code>{payload.capabilities_hash}</code> },
      { key: 'validity', label: '授权时间范围', children: <span><TimeValue value={payload.not_before} /> 至 <TimeValue value={payload.expires_at} /></span> },
      { key: 'approval-window', label: '审批时间范围', children: <span><TimeValue value={payload.approval_not_before} /> 至 <TimeValue value={payload.approval_expires_at} /></span> },
    ]} />
    <div className="coauth-task-signers">
      {([
        ['enterprise_approver', '要求的企业审批主体', Building2],
        ['finance_approver', '要求的财务审批主体', Wallet],
      ] as const).map(([role, label, Icon]) => <div key={role}>
        <strong><Icon size={15} />{label}</strong>
        <code>{payload.required_signers[role].subject_id}</code>
        <code>{payload.required_signers[role].key_id}</code>
      </div>)}
    </div>
    <ul className="coauth-task-capabilities" aria-label="完整任务能力范围">
      {capabilities.map((capability, index) => <li key={`${capability.service}-${capability.tool}-${index}`}>
        <strong><code>{capability.service} / {capability.tool}@{capability.version}</code></strong>
        {capability.resources.ticket_ids ? <div>工单：<code>{capability.resources.ticket_ids.join('、')}</code></div> : null}
        {capability.resources.customer_ids ? <div>客户：<code>{capability.resources.customer_ids.join('、')}</code></div> : null}
        {capability.constraints.single_max_fen !== undefined ? <div>单笔上限：<Fen value={capability.constraints.single_max_fen} /></div> : null}
        {capability.constraints.template_ids ? <div>模板：<code>{capability.constraints.template_ids.join('、')}</code></div> : null}
      </li>)}
    </ul>
  </>
}

function HistoryRecord({ entry, disabled, onDownload }: {
  entry: CoauthorizationHistoryEntry; disabled: boolean; onDownload: (value: unknown, filename: string) => void
}) {
  const bundle = entry.challenge_status === 'CONSUMED' ? entry.signed_bundle : null
  const hasPair = bundle?.approvals.length === 2
    && bundle.approvals.some((approval) => approval.statement.role === 'ENTERPRISE_APPROVER')
    && bundle.approvals.some((approval) => approval.statement.role === 'FINANCE_APPROVER')
  return <article className="coauth-task-history-row">
    <div className="coauth-task-history-heading">
      <code>{entry.challenge_id}</code>
      <Tag color={entry.challenge_status === 'CONSUMED' ? 'blue' : entry.challenge_status === 'REVOKED' ? 'red' : 'orange'}>
        {({ PENDING: '待提交', CONSUMED: '已消费', REVOKED: '已撤销' })[entry.challenge_status]}
      </Tag>
      <Tag color={entry.window_state === 'EXPIRED' ? 'orange' : 'default'}>
        {({ NOT_YET_VALID: '读取时尚未生效', OPEN: '读取时开放', EXPIRED: '读取时已过期' })[entry.window_state]}（{entry.window_state}）
      </Tag>
    </div>
    <details className="coauth-task-details">
      <summary><Eye size={14} />查看挑战记录</summary>
      <Descriptions column={1} size="small" colon={false} className="coauth-task-fields" items={[
        { key: 'issued', label: '挑战签发', children: <TimeValue value={entry.issued_at} /> },
        { key: 'expires', label: '挑战到期', children: <TimeValue value={entry.expires_at} /> },
        { key: 'consumed', label: '消费时间', children: <TimeValue value={entry.consumed_at} /> },
        { key: 'revoked', label: '挑战撤销时间', children: <TimeValue value={entry.revoked_at} /> },
        { key: 'approval-hash', label: '审批载荷摘要', children: <code>{entry.approval_payload_hash}</code> },
        { key: 'bundle-hash', label: '双签包摘要', children: <code>{entry.bundle_hash ?? '未记录'}</code> },
        { key: 'credential', label: '根授权编号', children: <code>{entry.root_credential_id ?? '未记录'}</code> },
        { key: 'credential-hash', label: '根授权摘要', children: <code>{entry.root_credential_hash ?? '未记录'}</code> },
      ]} />
      <PayloadDetails payload={entry.payload} capabilities={entry.task_capabilities} />
      <details className="coauth-task-details">
        <summary><Eye size={14} />查看完整历史 JSON</summary>
        <pre className="coauth-task-json">{JSON.stringify(entry, null, 2)}</pre>
      </details>
      {hasPair && bundle ? <>
        <h4>存储的双签审批声明</h4>
        <div className="coauth-task-signers">
          {bundle.approvals.map(({ statement, signature }) => <div key={statement.role}>
            <strong>{statement.role === 'ENTERPRISE_APPROVER' ? <Building2 size={15} /> : <Wallet size={15} />}
              {statement.role === 'ENTERPRISE_APPROVER' ? '企业审批记录' : '财务审批记录'}</strong>
            <code>{statement.subject_id}</code><code>{statement.key_id}</code>
            <span>声明时间：<TimeValue value={statement.approved_at} /></span>
            <span>签名时间：<TimeValue value={signature.signed_at} /></span>
          </div>)}
        </div>
        <details className="coauth-task-details">
          <summary><Eye size={14} />查看历史签名包 JSON</summary>
          <pre className="coauth-task-json">{JSON.stringify(bundle, null, 2)}</pre>
        </details>
        <LiquidGlassButton icon={<Download size={15} />} disabled={disabled}
          onClick={() => onDownload(bundle, 'coauthorization-signed-bundle.json')}>下载历史双签包</LiquidGlassButton>
      </> : <p className="coauth-task-note">{entry.challenge_status === 'CONSUMED' ? '已消费记录未返回完整双签包。' : '未消费记录无已消费双签审批声明。'}</p>}
    </details>
  </article>
}

export function CoauthorizationTaskDialog({ taskId, taskStatus, onChanged }: {
  taskId: string | null
  taskStatus: string | null
  onChanged?: (taskId: string) => Promise<void>
}) {
  const [view, setView] = useState<DialogState>(initialState)
  const fieldId = useId()
  const sequence = useRef(0)
  const session = useRef<Session | null>(null)
  const authoritySequence = useRef(0)
  const historySequence = useRef(0)
  const fileSequence = useRef(0)
  const mutation = useRef<Mutation | null>(null)
  const fileLoading = useRef(false)
  const fileInput = useRef<HTMLInputElement>(null)

  function invalidate() {
    sequence.current += 1
    authoritySequence.current += 1
    historySequence.current += 1
    fileSequence.current += 1
    session.current = null
    mutation.current = null
    fileLoading.current = false
  }

  // Invalidate during the task-change commit, before an old promise can update the new task.
  useLayoutEffect(() => {
    invalidate()
    setView(initialState())
    return invalidate
  }, [taskId])

  const patch = (changes: Partial<DialogState>) => setView((current) => ({ ...current, ...changes }))
  const current = (opened: Session) => session.current === opened && sequence.current === opened.sequence

  async function readAuthority(opened: Session) {
    if (!current(opened)) return false
    const request = ++authoritySequence.current
    patch({ authority: null, authorityError: null, authorityLoading: true })
    try {
      const authority = await api.coauthorizationStatus()
      if (!current(opened) || authoritySequence.current !== request) return false
      if (authority.schema_version !== '1.0' || typeof authority.enabled !== 'boolean'
        || authority.policy_source !== 'SERVER_REGISTERED_PUBLIC_KEYS' || authority.signing !== 'EXTERNAL_APPROVERS_ONLY') {
        throw new Error('Unexpected Authority configuration response')
      }
      patch({ authority })
      return true
    } catch (error) {
      if (current(opened) && authoritySequence.current === request) {
        patch({ authority: null, authorityError: failure(error, 'Authority 配置读取失败，未判定为已启用或已审批。') })
      }
      return false
    } finally {
      if (current(opened) && authoritySequence.current === request) patch({ authorityLoading: false })
    }
  }

  async function readHistory(opened: Session, offset: number) {
    if (!current(opened)) return false
    const request = ++historySequence.current
    patch({ review: null, historyError: null, historyLoading: true, offset })
    try {
      const review = await api.coauthorizationTask(opened.taskId, offset)
      if (!current(opened) || historySequence.current !== request) return false
      if (review.observation_kind !== 'STORED_EVIDENCE_NOT_REVALIDATED'
        || review.task_id !== opened.taskId || review.offset !== offset || review.limit !== HISTORY_PAGE_SIZE
        || review.items.some((entry) => entry.payload.task_id !== opened.taskId
          || (entry.signed_bundle !== null && entry.signed_bundle.payload.task_id !== opened.taskId))) {
        throw new Error('History does not match the requested task or page')
      }
      setView((state) => ({ ...state, review,
        requiresHistoryRefresh: false,
        mutationError: state.requiresHistoryRefresh ? null : state.mutationError,
      }))
      return true
    } catch (error) {
      if (current(opened) && historySequence.current === request) {
        patch({ review: null, historyError: failure(error, '历史读取失败，旧记录已清空；未判定当前审批状态。') })
      }
      return false
    } finally {
      if (current(opened) && historySequence.current === request) patch({ historyLoading: false })
    }
  }

  function openDialog() {
    if (!taskId || mutation.current || session.current) return
    const opened = { taskId, sequence: ++sequence.current }
    session.current = opened
    setView({ ...initialState(), open: true })
    void readAuthority(opened)
    void readHistory(opened, 0)
  }

  function closeDialog() {
    if (mutation.current) return
    invalidate()
    setView(initialState())
  }

  const locked = Boolean(view.mutation)
  const reading = view.authorityLoading || view.historyLoading
  const ready = view.authority?.enabled === true && view.review !== null && !reading
  const closed = taskStatus === 'CLOSED' || view.review?.task_status === 'CLOSED'
  const canCreate = ready && !closed && !view.requiresHistoryRefresh
    && view.review?.task_status === 'PENDING_AUTHORIZATION' && taskStatus !== 'AUTHORIZED'
  const canSubmit = ready && !closed && !view.requiresHistoryRefresh && view.confirmed && !inputError(view.rawJson) && !view.inputError
  const validHolder = validIdentifier(view.holderAgentId) && validIdentifier(view.holderKeyId)
    && view.delegationDepth !== null && Number.isSafeInteger(view.delegationDepth)
    && view.delegationDepth >= 0 && view.delegationDepth <= 16

  async function createChallenge() {
    const opened = session.current
    if (!opened || !current(opened) || mutation.current || fileLoading.current || !canCreate || !validHolder) return
    mutation.current = 'challenge'
    patch({ mutation: 'challenge', mutationError: null, challenge: null, downloadError: null })
    try {
      const challenge = await api.createCoauthorizationChallenge(opened.taskId, {
        holder_agent_id: view.holderAgentId, holder_key_id: view.holderKeyId,
        delegation_depth: view.delegationDepth!,
      })
      if (!current(opened)) return
      if (challenge.payload.task_id !== opened.taskId) throw new Error('Challenge belongs to a different task')
      patch({ challenge })
      await readHistory(opened, 0)
    } catch (error) {
      if (current(opened)) patch({ mutationError: failure(error, '挑战生成未获得有效返回，请读取历史核对。') })
    } finally {
      if (current(opened)) {
        mutation.current = null
        patch({ mutation: null })
      }
    }
  }

  async function submitBundle() {
    const opened = session.current
    if (!opened || !current(opened) || mutation.current || fileLoading.current || !canSubmit) return
    const rawJson = view.rawJson
    mutation.current = 'authorize'
    patch({ mutation: 'authorize', mutationError: null, refreshError: null, result: null })
    try {
      // Keep duplicate members, whitespace and BOM intact for the server's strict parser.
      const result = await api.authorizeCoauthorizationTask(opened.taskId, rawJson)
      if (!current(opened)) return
      patch({ result, confirmed: false })
      const historyUpdated = await readHistory(opened, 0)
      if (!current(opened)) return
      let pageUpdated = true
      try {
        await onChanged?.(opened.taskId)
      } catch {
        pageUpdated = false
      }
      if (current(opened) && (!historyUpdated || !pageUpdated)) {
        patch({ refreshError: '授权已返回，但页面记录刷新失败。请刷新记录核对；此刷新错误不代表审批失败。' })
      }
    } catch (error) {
      if (current(opened)) {
        const unconfirmed = !(error instanceof ApiError && [400, 403, 404, 409].includes(error.status))
          || (error instanceof ApiError && error.reasonCode === 'COAUTH_RESULT_UNCONFIRMED')
        patch({ confirmed: false, requiresHistoryRefresh: unconfirmed,
          ...(unconfirmed ? { review: null } : {}), mutationError: unconfirmed
          ? 'COAUTH_RESULT_UNCONFIRMED：提交结果未确认，可能已签发根授权。请先刷新共同审批历史核对；本入口不会自动重提。'
          : failure(error, '提交未获得授权返回，请读取历史核对结果。') })
      }
    } finally {
      if (current(opened)) {
        mutation.current = null
        patch({ mutation: null })
      }
    }
  }

  function changeRawJson(rawJson: string) {
    if (mutation.current || view.requiresHistoryRefresh) return
    fileSequence.current += 1
    fileLoading.current = false
    patch({ rawJson, confirmed: false, fileLoading: false, inputError: rawJson ? inputError(rawJson) : null })
  }

  async function readFile(file: File) {
    const opened = session.current
    if (!opened || !current(opened) || mutation.current || view.requiresHistoryRefresh) return
    const request = ++fileSequence.current
    fileLoading.current = true
    patch({ rawJson: '', confirmed: false, inputError: null, fileLoading: true })
    try {
      if (file.size > MAX_BUNDLE_BYTES) throw new RangeError('Bundle exceeds the byte limit')
      const buffer = await file.arrayBuffer()
      if (!current(opened) || fileSequence.current !== request) return
      if (buffer.byteLength > MAX_BUNDLE_BYTES) throw new RangeError('Bundle exceeds the byte limit')
      const rawJson = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(buffer)
      patch({ rawJson, inputError: inputError(rawJson) })
    } catch (error) {
      if (current(opened) && fileSequence.current === request) {
        patch({ rawJson: '', inputError: error instanceof RangeError
          ? '签名包超过 32768 字节，未载入。' : '文件读取或严格 UTF-8 解码失败，未载入签名包。' })
      }
    } finally {
      if (current(opened) && fileSequence.current === request) {
        fileLoading.current = false
        patch({ fileLoading: false })
      }
    }
  }

  function download(value: unknown, filename: string) {
    if (!session.current || mutation.current) return
    let url: string | null = null
    let anchor: HTMLAnchorElement | null = null
    patch({ downloadError: null })
    try {
      url = URL.createObjectURL(new Blob([JSON.stringify(value, null, 2)], { type: 'application/json;charset=utf-8' }))
      anchor = document.createElement('a')
      anchor.href = url
      anchor.download = filename
      document.body.appendChild(anchor)
      anchor.click()
    } catch {
      patch({ downloadError: 'JSON 下载失败，未生成替代证据。' })
    } finally {
      anchor?.remove()
      if (url) {
        const objectUrl = url
        const revoke = URL.revokeObjectURL.bind(URL)
        setTimeout(() => revoke(objectUrl), 0)
      }
    }
  }

  return <>
    <LiquidGlassButton icon={<UsersRound size={15} />} disabled={!taskId || locked} onClick={openDialog}>
      共同审批
    </LiquidGlassButton>
    <Modal open={view.open} onCancel={closeDialog} closable={!locked} maskClosable={!locked} keyboard={!locked}
      title={<span className="coauth-task-title"><UsersRound size={17} />任务共同审批</span>}
      width={780} className="coauth-task-dialog" destroyOnHidden
      footer={<LiquidGlassButton icon={<X size={15} />} disabled={locked} onClick={closeDialog}>关闭</LiquidGlassButton>}>
      <div className="coauth-task-body" aria-busy={locked || reading || view.fileLoading}>
        <div className="coauth-task-context"><code>{taskId}</code><StatusTag value={taskStatus} /></div>
        <p className="coauth-task-boundary"><CircleAlert size={15} /><span>本机受信管理操作；不远程登录审批人。企业与财务在外部签名，此入口不持有密钥、不生成签名。</span></p>
        <section className="coauth-task-section" aria-label="Authority 配置">
          <div className="coauth-task-section-heading"><h3><ShieldCheck size={16} />Authority 配置</h3>
            <Tag color={view.authorityError ? 'red' : view.authority?.enabled ? 'orange' : 'default'}>
              {view.authorityLoading ? '读取中' : view.authorityError ? '无法读取' : view.authority ? view.authority.enabled ? '要求两方审批' : '未启用' : '未读取'}
            </Tag>
            <Tooltip title="刷新 Authority 配置与当前页历史">
              <LiquidGlassButton icon={<RefreshCw size={15} />} aria-label="刷新配置与历史" loading={reading}
                disabled={locked || reading} onClick={() => {
                  const opened = session.current
                  if (!opened || mutation.current) return
                  void readAuthority(opened)
                  void readHistory(opened, view.requiresHistoryRefresh ? 0 : view.offset)
                }} />
            </Tooltip>
          </div>
          <ErrorLine message={view.authorityError} />
          {view.authority && !view.authority.enabled ? <p className="coauth-task-note">当前 Authority 未启用共同审批，此入口不能生成挑战或提交双签包。</p> : null}
        </section>
        <ErrorLine message={view.mutationError} />
        <section className="coauth-task-section" aria-label="生成待签任务">
          <h3><FilePlus2 size={16} />待签任务</h3>
          <div className="coauth-task-holder">
            <div><label htmlFor={`${fieldId}-agent`}>持有者智能体</label><Input id={`${fieldId}-agent`} value={view.holderAgentId}
              disabled={locked} onChange={(event) => patch({ holderAgentId: event.target.value })} /></div>
            <div><label htmlFor={`${fieldId}-key`}>持有者密钥标识</label><Input id={`${fieldId}-key`} value={view.holderKeyId}
              disabled={locked} onChange={(event) => patch({ holderKeyId: event.target.value })} /></div>
            <div><label htmlFor={`${fieldId}-depth`}>委托深度</label><InputNumber<number> id={`${fieldId}-depth`} min={0} max={16} precision={0}
              value={view.delegationDepth} disabled={locked} onChange={(value) => patch({ delegationDepth: value })} /></div>
          </div>
          <div className="coauth-task-actions">
            <LiquidGlassButton icon={<FilePlus2 size={15} />} loading={view.mutation === 'challenge'}
              disabled={locked || view.fileLoading || !canCreate || !validHolder} onClick={() => void createChallenge()}>生成挑战</LiquidGlassButton>
            {view.challenge ? <LiquidGlassButton icon={<Download size={15} />} disabled={locked}
              onClick={() => download(view.challenge, 'coauthorization-pending-task.json')}>下载待签任务 JSON</LiquidGlassButton> : null}
          </div>
          {view.challenge ? <div className="coauth-task-challenge">
            <div className="coauth-task-context"><Tag color="orange">待提交</Tag><code>{view.challenge.payload.challenge_id}</code></div>
            <PayloadDetails payload={view.challenge.payload} capabilities={view.challenge.task_capabilities} />
            <details className="coauth-task-details"><summary><Eye size={14} />查看待签任务 JSON</summary>
              <pre className="coauth-task-json">{JSON.stringify(view.challenge, null, 2)}</pre>
            </details>
          </div> : null}
        </section>
        <section className="coauth-task-section" aria-label="提交外部双签包">
          <h3><FileUp size={16} />外部双签包</h3>
          <label className="coauth-task-input-label" htmlFor={`${fieldId}-bundle`}>原始双签 JSON 文本</label>
          <Input.TextArea id={`${fieldId}-bundle`} className="coauth-task-raw" value={view.rawJson} rows={7}
            disabled={locked || view.fileLoading || view.requiresHistoryRefresh} spellCheck={false} onChange={(event) => changeRawJson(event.target.value)}
            onPaste={(event) => {
              const input = event.currentTarget
              if (mutation.current || fileLoading.current || view.requiresHistoryRefresh || !event.clipboardData.types.includes('text/plain')) return
              if (input.selectionStart === 0 && input.selectionEnd === input.value.length) {
                event.preventDefault()
                changeRawJson(event.clipboardData.getData('text/plain'))
              }
            }} />
          <div className="coauth-task-actions">
            <input ref={fileInput} type="file" accept=".json,application/json" hidden aria-label="选择外部双签 JSON 文件"
              disabled={locked || view.fileLoading || view.requiresHistoryRefresh} onChange={(event) => {
                const file = event.target.files?.[0]
                event.target.value = ''
                if (file) void readFile(file)
              }} />
            <LiquidGlassButton icon={<FileUp size={15} />} loading={view.fileLoading} disabled={locked || view.fileLoading || view.requiresHistoryRefresh}
              onClick={() => fileInput.current?.click()}>选择 JSON 文件</LiquidGlassButton>
            <span className="coauth-task-note">{new TextEncoder().encode(view.rawJson).byteLength} / 32768 字节</span>
          </div>
          <ErrorLine message={view.inputError} />
          <Checkbox checked={view.confirmed} disabled={locked || view.fileLoading || view.requiresHistoryRefresh || !ready || closed || Boolean(inputError(view.rawJson))}
            onChange={(event) => patch({ confirmed: event.target.checked })}>提交后将签发根授权，不执行工具</Checkbox>
          <div className="coauth-task-actions">
            <LiquidGlassButton type="primary" icon={<ShieldCheck size={15} />} loading={view.mutation === 'authorize'}
              disabled={locked || view.fileLoading || !canSubmit} onClick={() => void submitBundle()}>提交外部双签包</LiquidGlassButton>
          </div>
          <ErrorLine message={view.refreshError} />
          {view.result ? <div className="coauth-task-result" role="status" aria-live="polite" data-task-id={taskId}>
            <h4><ShieldCheck size={16} />Authority 授权返回 <Tag color="blue">{view.result.reused ? '返回已有根授权' : '返回根授权'}</Tag></h4>
            <p className="coauth-task-note">当前请求的 Authority 返回；历史投影与后续撤销状态需另行核对。</p>
            <Descriptions column={1} size="small" colon={false} className="coauth-task-fields" items={[
              { key: 'request-task', label: '请求绑定任务', children: <code>{taskId}</code> },
              { key: 'challenge', label: '挑战编号', children: <code>{view.result.challenge_id}</code> },
              { key: 'payload-hash', label: '审批载荷摘要', children: <code>{view.result.approval_payload_hash}</code> },
              { key: 'bundle-hash', label: '双签包摘要', children: <code>{view.result.bundle_hash}</code> },
              { key: 'root', label: '根授权编号', children: <code>{view.result.root_credential_id}</code> },
              { key: 'root-hash', label: '根授权摘要', children: <code>{view.result.root_credential_hash}</code> },
            ]} />
            <details className="coauth-task-details"><summary><Eye size={14} />查看 Authority 返回 JSON</summary>
              <pre className="coauth-task-json">{JSON.stringify(view.result, null, 2)}</pre>
            </details>
          </div> : null}
        </section>
        <section className="coauth-task-section" aria-label="共同审批历史">
          <div className="coauth-task-section-heading"><h3><History size={16} />共同审批历史</h3>
            <span className="coauth-task-note">第 {view.offset / HISTORY_PAGE_SIZE + 1} 页 · 每页 20 条</span>
          </div>
          <p className="coauth-task-note">存储证据未重新验签；历史消费不代表根授权当前未撤销。时间窗口仅反映读取时状态。</p>
          {view.review ? <div className="coauth-task-context"><span>读取时间：<TimeValue value={view.review.observed_at} /></span>
            <span>读取时任务状态：<StatusTag value={view.review.task_status} /></span></div> : null}
          <ErrorLine message={view.historyError} />
          {view.historyLoading ? <p role="status" className="coauth-task-note">历史读取中</p> : null}
          {view.review?.items.length === 0 ? <p className="coauth-task-note">暂无挑战记录</p> : null}
          {view.review?.items.map((entry) => <HistoryRecord key={entry.challenge_id} entry={entry} disabled={locked} onDownload={download} />)}
          <div className="coauth-task-pagination">
            <Tooltip title="上一页历史"><LiquidGlassButton icon={<ChevronLeft size={15} />} aria-label="上一页共同审批历史"
              disabled={locked || reading || view.offset === 0} onClick={() => {
                const opened = session.current
                if (opened && !mutation.current) void readHistory(opened, Math.max(0, view.offset - HISTORY_PAGE_SIZE))
              }} /></Tooltip>
            <Tooltip title="下一页历史"><LiquidGlassButton icon={<ChevronRight size={15} />} aria-label="下一页共同审批历史"
              disabled={locked || reading || !view.review?.has_more || view.offset + HISTORY_PAGE_SIZE > MAX_HISTORY_OFFSET} onClick={() => {
                const opened = session.current
                const nextOffset = view.offset + HISTORY_PAGE_SIZE
                if (opened && !mutation.current && nextOffset <= MAX_HISTORY_OFFSET) void readHistory(opened, nextOffset)
              }} /></Tooltip>
          </div>
        </section>
        <ErrorLine message={view.downloadError} />
      </div>
    </Modal>
  </>
}
