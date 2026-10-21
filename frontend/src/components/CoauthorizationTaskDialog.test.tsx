import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { api, ApiError } from '../api'
import type {
  CoauthorizationApprovalPayload, CoauthorizationBundle, CoauthorizationChallenge,
  CoauthorizationHistoryEntry, CoauthorizationResult, CoauthorizationStatus, CoauthorizationTaskReview,
} from '../types'
import { CoauthorizationTaskDialog } from './CoauthorizationTaskDialog'

const enabled: CoauthorizationStatus = {
  schema_version: '1.0', enabled: true,
  policy_source: 'SERVER_REGISTERED_PUBLIC_KEYS', signing: 'EXTERNAL_APPROVERS_ONLY',
}
const signatureDomain = 'AGENTGUARD|TASK_COAUTHORIZATION_APPROVAL|V1' as const
const payload: CoauthorizationApprovalPayload = {
  schema_version: '1.0', payload_type: 'COAUTHORIZATION_TASK_APPROVAL',
  approval_purpose: 'TASK_COAUTHORIZATION_APPROVAL_V1', verifier_audience: 'agentguard-root-authorization',
  tenant_id: 'TENANT-fixture', task_id: 'TASK-A', ticket_id: 'TICKET-fixture', customer_id: 'CUSTOMER-fixture',
  capabilities_hash: 'c'.repeat(64), quotas: { refund_total_fen: 25000, max_tool_calls: 3 },
  holder: { agent_id: 'agent-coordinator', key_id: 'agent-coordinator-key-01' }, not_before: 1700000000, expires_at: 1700003600,
  delegation_depth: 2, policy_revision: 'POLICY-fixture', challenge_id: 'CHALLENGE-fixture',
  required_signers: {
    enterprise_approver: { subject_id: 'ENTERPRISE-fixture', key_id: 'ENTERPRISE-key-fixture' },
    finance_approver: { subject_id: 'FINANCE-fixture', key_id: 'FINANCE-key-fixture' },
  },
  approval_not_before: 1700000000, approval_expires_at: 1700000300,
}
const challenge: CoauthorizationChallenge = {
  schema_version: '1.0', challenge_status: 'PENDING', payload,
  approval_payload_hash: 'a'.repeat(64), signature_domain: signatureDomain,
  task_capabilities: [
    { service: 'ticket-service', tool: 'ticket.read', version: 'v1',
      resources: { ticket_ids: ['TICKET-fixture'] }, constraints: {} },
    { service: 'knowledge-service', tool: 'knowledge.read_associated', version: 'v1',
      resources: { ticket_ids: ['TICKET-fixture'] }, constraints: {} },
    { service: 'refund-service', tool: 'refund.create', version: 'v1',
      resources: { ticket_ids: ['TICKET-fixture'], customer_ids: ['CUSTOMER-fixture'] },
      constraints: { single_max_fen: 20000 } },
    { service: 'notification-service', tool: 'notification.send_template', version: 'v1',
      resources: { customer_ids: ['CUSTOMER-fixture'] }, constraints: { template_ids: ['REFUND_SUCCESS'] } },
  ],
}

// These are inert UI fixtures, not cryptographically valid approvals.
const bundle: CoauthorizationBundle = {
  payload,
  approvals: (['ENTERPRISE_APPROVER', 'FINANCE_APPROVER'] as const).map((role) => {
    const signer = role === 'ENTERPRISE_APPROVER' ? payload.required_signers.enterprise_approver : payload.required_signers.finance_approver
    return {
      statement: { schema_version: '1.0', statement_type: 'COAUTHORIZATION_APPROVAL_STATEMENT',
        approval_purpose: 'TASK_COAUTHORIZATION_APPROVAL_V1', approval_payload_hash: challenge.approval_payload_hash,
        role, subject_id: signer.subject_id, key_id: signer.key_id, approved_at: 1700000100 },
      signature: { algorithm: 'SM2', key_id: signer.key_id, key_purpose: 'AUTHORIZATION_ROOT_SIGNING',
        encoding: 'SM2_RS_HEX_128_LOWERCASE', value: 'b'.repeat(128), signed_at: 1700000100 },
    }
  }),
}
// ROOT envelope fields follow the service contract; hashes and signature values remain inert mocks.
const result: CoauthorizationResult = {
  schema_version: '1.0', challenge_id: payload.challenge_id, approval_payload_hash: challenge.approval_payload_hash,
  bundle_hash: 'd'.repeat(64), root_credential_id: 'ROOT-fixture', root_credential_hash: 'e'.repeat(64),
  reused: false, credential: {
    payload: {
      schema_version: '1.0', credential_id: 'ROOT-fixture', credential_type: 'ROOT',
      issuer: { subject_id: 'AUTHORITY-fixture', key_id: 'AUTHORITY-key-fixture' },
      holder: payload.holder, tenant_id: payload.tenant_id, task_id: payload.task_id,
      verifier_audience: 'secure-tool-gateway', capabilities: challenge.task_capabilities, quotas: payload.quotas,
      not_before: payload.not_before, expires_at: payload.expires_at, delegation_depth: payload.delegation_depth,
      parent_credential_id: null, parent_credential_hash: null, issued_at: 1700000150,
    },
    signature: {
      algorithm: 'SM2', key_id: 'AUTHORITY-key-fixture', key_purpose: 'AUTHORIZATION_ROOT_SIGNING',
      encoding: 'SM2_RS_HEX_128_LOWERCASE', value: 'f'.repeat(128), signed_at: 1700000150,
    },
  },
}

function review(taskId = 'TASK-A', items: CoauthorizationHistoryEntry[] = [], offset = 0, hasMore = false): CoauthorizationTaskReview {
  return { schema_version: '1.0', observation_kind: 'STORED_EVIDENCE_NOT_REVALIDATED', task_id: taskId,
    task_status: 'PENDING_AUTHORIZATION', observed_at: 1700000200, offset, limit: 20, has_more: hasMore,
    items, signature_domain: signatureDomain }
}

function historyEntry(overrides: Partial<CoauthorizationHistoryEntry> = {}): CoauthorizationHistoryEntry {
  const challengeId = overrides.challenge_id ?? payload.challenge_id
  const status = overrides.challenge_status ?? 'PENDING'
  const storedPayload = overrides.payload ?? { ...payload, challenge_id: challengeId }
  const storedBundle = overrides.signed_bundle === undefined ? status === 'CONSUMED' ? bundle : null : overrides.signed_bundle
  return {
    challenge_id: challengeId, challenge_status: status, window_state: 'OPEN',
    issued_at: 1700000000, expires_at: 1700000300,
    consumed_at: status === 'CONSUMED' ? 1700000150 : null, revoked_at: status === 'REVOKED' ? 1700000160 : null,
    approval_payload_hash: challenge.approval_payload_hash, task_capabilities: challenge.task_capabilities,
    bundle_hash: status === 'CONSUMED' ? result.bundle_hash : null,
    root_credential_id: status === 'CONSUMED' ? result.root_credential_id : null,
    root_credential_hash: status === 'CONSUMED' ? result.root_credential_hash : null,
    ...overrides,
    payload: storedPayload,
    signed_bundle: storedBundle ? { ...storedBundle, payload: storedPayload } : null,
  }
}

function deferred<T>() {
  let resolve!: (value: T) => void
  let reject!: (error: unknown) => void
  const promise = new Promise<T>((done, fail) => { resolve = done; reject = fail })
  return { promise, resolve, reject }
}

function jsonFile(bytes: Uint8Array, returned: Promise<ArrayBuffer> | null = null) {
  const buffer = new ArrayBuffer(bytes.byteLength)
  new Uint8Array(buffer).set(bytes)
  const file = new File([buffer], 'external-approvals.json', { type: 'application/json' })
  const read = vi.fn().mockReturnValue(returned ?? Promise.resolve(buffer))
  Object.defineProperty(file, 'arrayBuffer', { value: read })
  return { file, read, buffer }
}

async function openDialog() {
  fireEvent.click(screen.getByRole('button', { name: '共同审批' }))
  const dialog = await screen.findByRole('dialog')
  await waitFor(() => {
    const refresh = within(dialog).getByRole('button', { name: '刷新配置与历史' })
    expect(refresh).toBeEnabled()
    expect(refresh).not.toHaveClass('ant-btn-loading')
  })
  return dialog
}

function enterBundle(dialog: HTMLElement, rawJson = JSON.stringify(bundle)) {
  fireEvent.change(within(dialog).getByRole('textbox', { name: '原始双签 JSON 文本' }), { target: { value: rawJson } })
}

function confirmSubmission(dialog: HTMLElement) {
  fireEvent.click(within(dialog).getByRole('checkbox', { name: '提交后将签发根授权，不执行工具' }))
}

beforeEach(() => {
  vi.spyOn(api, 'coauthorizationStatus').mockResolvedValue(enabled)
  vi.spyOn(api, 'coauthorizationTask').mockResolvedValue(review())
  vi.spyOn(api, 'createCoauthorizationChallenge').mockImplementation((taskId, holder) => Promise.resolve({
    ...challenge, payload: { ...payload, task_id: taskId,
      holder: { agent_id: holder.holder_agent_id, key_id: holder.holder_key_id }, delegation_depth: holder.delegation_depth },
  }))
  vi.spyOn(api, 'authorizeCoauthorizationTask').mockResolvedValue(result)
})

afterEach(() => {
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
})

describe('CoauthorizationTaskDialog', () => {
  it('only reads Authority and the selected task history after opening, without mutating', async () => {
    render(<CoauthorizationTaskDialog taskId="TASK-A" taskStatus="PENDING_AUTHORIZATION" />)
    expect(api.coauthorizationStatus).not.toHaveBeenCalled()
    expect(api.coauthorizationTask).not.toHaveBeenCalled()
    const dialog = await openDialog()
    expect(api.coauthorizationStatus).toHaveBeenCalledTimes(1)
    expect(api.coauthorizationTask).toHaveBeenCalledWith('TASK-A', 0)
    expect(api.createCoauthorizationChallenge).not.toHaveBeenCalled()
    expect(api.authorizeCoauthorizationTask).not.toHaveBeenCalled()
    expect(within(dialog).getByText('要求两方审批')).toBeInTheDocument()
    expect(within(dialog).getByText(/本机受信管理操作/)).toHaveTextContent('不远程登录审批人')
    expect(within(dialog).getByText(/存储证据未重新验签/)).toHaveTextContent('不代表根授权当前未撤销')
  })

  it('requires a selected task and performs no reads for a disabled trigger', () => {
    render(<CoauthorizationTaskDialog taskId={null} taskStatus={null} />)
    const trigger = screen.getByRole('button', { name: '共同审批' })
    expect(trigger).toBeDisabled()
    fireEvent.click(trigger)
    expect(api.coauthorizationStatus).not.toHaveBeenCalled()
    expect(api.coauthorizationTask).not.toHaveBeenCalled()
  })

  it('never treats missing or disabled Authority configuration as permission to mutate', async () => {
    vi.mocked(api.coauthorizationStatus).mockRejectedValueOnce(new ApiError(503, 'UNAVAILABLE', 'Unavailable'))
      .mockResolvedValueOnce({ ...enabled, enabled: false })
    render(<CoauthorizationTaskDialog taskId="TASK-A" taskStatus="PENDING_AUTHORIZATION" />)
    const dialog = await openDialog()
    expect(within(dialog).getByRole('alert')).toHaveTextContent('配置读取失败')
    expect(within(dialog).queryByText('未启用')).not.toBeInTheDocument()
    expect(within(dialog).getByRole('button', { name: '生成挑战' })).toBeDisabled()
    enterBundle(dialog)
    expect(within(dialog).getByRole('checkbox')).toBeDisabled()
    fireEvent.click(within(dialog).getByRole('button', { name: '刷新配置与历史' }))
    await within(dialog).findByText('未启用')
    expect(within(dialog).getByRole('button', { name: '生成挑战' })).toBeDisabled()
    expect(within(dialog).getByRole('button', { name: '提交外部双签包' })).toBeDisabled()
    expect(api.authorizeCoauthorizationTask).not.toHaveBeenCalled()
  })

  it('still reads history when Authority is disabled and retains readable configuration on a history 503', async () => {
    vi.mocked(api.coauthorizationStatus).mockResolvedValue({ ...enabled, enabled: false })
    vi.mocked(api.coauthorizationTask).mockResolvedValueOnce(review('TASK-A', [historyEntry()]))
      .mockRejectedValueOnce(new ApiError(503, 'COAUTH_HISTORY_UNAVAILABLE', 'Migration unavailable'))
    render(<CoauthorizationTaskDialog taskId="TASK-A" taskStatus="PENDING_AUTHORIZATION" />)
    const dialog = await openDialog()
    expect(api.coauthorizationTask).toHaveBeenCalledWith('TASK-A', 0)
    expect(within(dialog).getByText('未启用')).toBeInTheDocument()
    expect(within(dialog).getByText(payload.challenge_id)).toBeInTheDocument()
    fireEvent.click(within(dialog).getByRole('button', { name: '刷新配置与历史' }))
    expect(await within(dialog).findByRole('alert')).toHaveTextContent('HTTP 503')
    await within(dialog).findByText('未启用')
    expect(within(dialog).queryByText(payload.challenge_id)).not.toBeInTheDocument()
    expect(within(dialog).getByRole('button', { name: '生成挑战' })).toBeDisabled()
    expect(within(dialog).getByRole('button', { name: '提交外部双签包' })).toBeDisabled()
    expect(api.createCoauthorizationChallenge).not.toHaveBeenCalled()
    expect(api.authorizeCoauthorizationTask).not.toHaveBeenCalled()
  })

  it('generates a challenge only on command using default or explicitly edited Holder fields', async () => {
    render(<CoauthorizationTaskDialog taskId="TASK-A" taskStatus="PENDING_AUTHORIZATION" />)
    const dialog = await openDialog()
    expect(within(dialog).getByRole('textbox', { name: '持有者智能体' })).toHaveValue('agent-coordinator')
    expect(within(dialog).getByRole('textbox', { name: '持有者密钥标识' })).toHaveValue('agent-coordinator-key-01')
    expect(within(dialog).getByRole('spinbutton', { name: '委托深度' })).toHaveDisplayValue('2')
    fireEvent.click(within(dialog).getByRole('button', { name: '生成挑战' }))
    await within(dialog).findByRole('button', { name: '下载待签任务 JSON' })
    expect(api.createCoauthorizationChallenge).toHaveBeenCalledWith('TASK-A', {
      holder_agent_id: 'agent-coordinator', holder_key_id: 'agent-coordinator-key-01', delegation_depth: 2,
    })
    await waitFor(() => expect(within(dialog).getByRole('button', { name: '生成挑战' })).toBeEnabled())
    fireEvent.change(within(dialog).getByRole('textbox', { name: '持有者智能体' }), { target: { value: 'chosen-agent' } })
    fireEvent.change(within(dialog).getByRole('textbox', { name: '持有者密钥标识' }), { target: { value: 'chosen-key' } })
    fireEvent.change(within(dialog).getByRole('spinbutton', { name: '委托深度' }), { target: { value: '1' } })
    fireEvent.click(within(dialog).getByRole('button', { name: '生成挑战' }))
    await waitFor(() => expect(api.createCoauthorizationChallenge).toHaveBeenLastCalledWith('TASK-A', {
      holder_agent_id: 'chosen-agent', holder_key_id: 'chosen-key', delegation_depth: 1,
    }))
    expect(api.authorizeCoauthorizationTask).not.toHaveBeenCalled()
  })

  it.each([
    ['持有者智能体', ' agent-coordinator '],
    ['持有者智能体', ':agent'],
    ['持有者智能体', '中文'],
    ['持有者智能体', 'a'.repeat(129)],
    ['持有者密钥标识', 'key/01'],
    ['持有者密钥标识', 'k'.repeat(129)],
  ])('rejects a frozen-Identifier violation in %s without trimming it into a different identifier', async (fieldName, value) => {
    render(<CoauthorizationTaskDialog taskId="TASK-A" taskStatus="PENDING_AUTHORIZATION" />)
    const dialog = await openDialog()
    fireEvent.change(within(dialog).getByRole('textbox', { name: fieldName }), { target: { value } })
    expect(within(dialog).getByRole('textbox', { name: fieldName })).toHaveValue(value)
    expect(within(dialog).getByRole('button', { name: '生成挑战' })).toBeDisabled()
    expect(api.createCoauthorizationChallenge).not.toHaveBeenCalled()
  })

  it('accepts the 128-character Identifier boundary and limits the numeric Holder depth to 16', async () => {
    render(<CoauthorizationTaskDialog taskId="TASK-A" taskStatus="PENDING_AUTHORIZATION" />)
    const dialog = await openDialog()
    fireEvent.change(within(dialog).getByRole('textbox', { name: '持有者智能体' }), { target: { value: 'a'.repeat(128) } })
    fireEvent.change(within(dialog).getByRole('textbox', { name: '持有者密钥标识' }), { target: { value: 'A-a_0.key:01' } })
    const depth = within(dialog).getByRole('spinbutton', { name: '委托深度' })
    expect(depth).toHaveAttribute('aria-valuemax', '16')
    expect(depth).toHaveAttribute('aria-valuemin', '0')
    fireEvent.change(depth, { target: { value: '16' } })
    fireEvent.click(within(dialog).getByRole('button', { name: '生成挑战' }))
    await waitFor(() => expect(api.createCoauthorizationChallenge).toHaveBeenCalledWith('TASK-A', {
      holder_agent_id: 'a'.repeat(128), holder_key_id: 'A-a_0.key:01', delegation_depth: 16,
    }))
  })

  it('downloads the entire challenge response including capabilities, without fabricated approvals', async () => {
    const createUrl = vi.fn().mockReturnValue('blob:fixture')
    vi.stubGlobal('URL', { createObjectURL: createUrl, revokeObjectURL: vi.fn() })
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => undefined)
    render(<CoauthorizationTaskDialog taskId="TASK-A" taskStatus="PENDING_AUTHORIZATION" />)
    const dialog = await openDialog()
    fireEvent.click(within(dialog).getByRole('button', { name: '生成挑战' }))
    const download = await within(dialog).findByRole('button', { name: '下载待签任务 JSON' })
    await waitFor(() => expect(download).toBeEnabled())
    fireEvent.click(download)
    expect(createUrl).toHaveBeenCalledTimes(1)
    const downloaded = createUrl.mock.calls[0][0] as Blob
    const raw = await new Promise<string>((resolve, reject) => {
      const reader = new FileReader()
      reader.onload = () => resolve(String(reader.result))
      reader.onerror = reject
      reader.readAsText(downloaded)
    })
    expect(raw).toBe(JSON.stringify(challenge, null, 2))
    expect(raw).toContain('ticket.read')
    expect(raw).toContain('knowledge.read_associated')
    expect(raw).toContain('refund.create')
    expect(raw).toContain('notification.send_template')
    expect(raw).toContain('REFUND_SUCCESS')
    expect(raw).not.toContain('"approvals"')
    expect(raw).not.toContain('"signature"')
  })

  it('requires explicit confirmation and keeps duplicate JSON members intact for server rejection', async () => {
    vi.mocked(api.authorizeCoauthorizationTask).mockRejectedValue(new ApiError(400, 'DUPLICATE_JSON_MEMBER', 'Duplicate'))
    const changed = vi.fn().mockResolvedValue(undefined)
    render(<CoauthorizationTaskDialog taskId="TASK-A" taskStatus="PENDING_AUTHORIZATION" onChanged={changed} />)
    const dialog = await openDialog()
    const rawJson = ' \n{"payload":{"task_id":"TASK-A","task_id":"TASK-A"},"approvals":[]}\n '
    enterBundle(dialog, rawJson)
    const submit = within(dialog).getByRole('button', { name: '提交外部双签包' })
    expect(submit).toBeDisabled()
    expect(api.authorizeCoauthorizationTask).not.toHaveBeenCalled()
    confirmSubmission(dialog)
    fireEvent.click(submit)
    expect(await within(dialog).findByRole('alert')).toHaveTextContent('DUPLICATE_JSON_MEMBER')
    expect(api.authorizeCoauthorizationTask).toHaveBeenCalledWith('TASK-A', rawJson)
    expect(within(dialog).queryByText('Authority 授权返回')).not.toBeInTheDocument()
    expect(changed).not.toHaveBeenCalled()
  })

  it('preserves the complete pasted clipboard text including BOM and CRLF', async () => {
    vi.mocked(api.authorizeCoauthorizationTask).mockRejectedValue(new ApiError(400, 'INVALID_JSON', 'Rejected'))
    render(<CoauthorizationTaskDialog taskId="TASK-A" taskStatus="PENDING_AUTHORIZATION" />)
    const dialog = await openDialog()
    const rawJson = '\uFEFF {\r\n"payload":{"task_id":"TASK-A","task_id":"TASK-A"},"approvals":[]\r\n} '
    fireEvent.paste(within(dialog).getByRole('textbox', { name: '原始双签 JSON 文本' }), {
      clipboardData: { types: ['text/plain'], getData: vi.fn().mockReturnValue(rawJson) },
    })
    confirmSubmission(dialog)
    fireEvent.click(within(dialog).getByRole('button', { name: '提交外部双签包' }))
    await within(dialog).findByRole('alert')
    expect(api.authorizeCoauthorizationTask).toHaveBeenCalledWith('TASK-A', rawJson)
  })

  it.each([
    new TypeError('Network response unavailable'),
    new ApiError(503, 'UNAVAILABLE', 'Unavailable'),
    new ApiError(401, 'UNAUTHORIZED', 'Unauthorized'),
    new ApiError(422, 'UNEXPECTED_STATUS', 'Unexpected'),
    new ApiError(400, 'COAUTH_RESULT_UNCONFIRMED', 'Unconfirmed'),
  ])('locks raw text, file imports and submission until same-task history succeeds after an unknown result: %s', async (error) => {
    vi.mocked(api.authorizeCoauthorizationTask).mockRejectedValue(error)
    vi.mocked(api.coauthorizationTask).mockResolvedValueOnce(review('TASK-A', [historyEntry()]))
      .mockRejectedValueOnce(new ApiError(503, 'UNAVAILABLE', 'Unavailable'))
      .mockResolvedValueOnce(review())
    const changed = vi.fn().mockResolvedValue(undefined)
    render(<CoauthorizationTaskDialog taskId="TASK-A" taskStatus="PENDING_AUTHORIZATION" onChanged={changed} />)
    const dialog = await openDialog()
    const rawJson = JSON.stringify(bundle)
    enterBundle(dialog, rawJson)
    confirmSubmission(dialog)
    fireEvent.click(within(dialog).getByRole('button', { name: '提交外部双签包' }))
    expect(await within(dialog).findByRole('alert')).toHaveTextContent('COAUTH_RESULT_UNCONFIRMED')
    expect(within(dialog).getByRole('alert')).toHaveTextContent('请先刷新共同审批历史核对')
    expect(within(dialog).queryByText(payload.challenge_id)).not.toBeInTheDocument()
    const text = within(dialog).getByRole('textbox', { name: '原始双签 JSON 文本' })
    const fileInput = within(dialog).getByLabelText('选择外部双签 JSON 文件')
    expect(text).toBeDisabled()
    expect(fileInput).toBeDisabled()
    expect(within(dialog).getByRole('button', { name: '选择 JSON 文件' })).toBeDisabled()
    expect(within(dialog).getByRole('checkbox')).not.toBeChecked()
    expect(within(dialog).getByRole('checkbox')).toBeDisabled()
    expect(within(dialog).getByRole('button', { name: '提交外部双签包' })).toBeDisabled()
    enterBundle(dialog, '{"replacement":true}')
    const { file, read } = jsonFile(new TextEncoder().encode('{"replacement":true}'))
    fireEvent.change(fileInput, { target: { files: [file] } })
    expect(text).toHaveValue(rawJson)
    expect(read).not.toHaveBeenCalled()
    expect(api.authorizeCoauthorizationTask).toHaveBeenCalledTimes(1)
    expect(changed).not.toHaveBeenCalled()
    fireEvent.click(within(dialog).getByRole('button', { name: '刷新配置与历史' }))
    await waitFor(() => expect(within(dialog).getAllByRole('alert').some((node) => node.textContent?.includes('旧记录已清空'))).toBe(true))
    expect(text).toBeDisabled()
    expect(fileInput).toBeDisabled()
    await waitFor(() => expect(within(dialog).getByRole('button', { name: '刷新配置与历史' })).toBeEnabled())
    fireEvent.click(within(dialog).getByRole('button', { name: '刷新配置与历史' }))
    await within(dialog).findByText('暂无挑战记录')
    await waitFor(() => expect(text).toBeEnabled())
    expect(fileInput).toBeEnabled()
    expect(api.coauthorizationTask).toHaveBeenLastCalledWith('TASK-A', 0)
    expect(within(dialog).getByRole('checkbox')).not.toBeChecked()
    expect(within(dialog).getByRole('button', { name: '提交外部双签包' })).toBeDisabled()
    expect(api.authorizeCoauthorizationTask).toHaveBeenCalledTimes(1)
    confirmSubmission(dialog)
    expect(within(dialog).getByRole('button', { name: '提交外部双签包' })).toBeEnabled()
    expect(api.authorizeCoauthorizationTask).toHaveBeenCalledTimes(1)
  })

  it.each([400, 403, 404, 409])('keeps text editable but resets confirmation after an explicit rejection with HTTP %s', async (status) => {
    vi.mocked(api.authorizeCoauthorizationTask).mockRejectedValue(new ApiError(status, 'EXPLICIT_REJECTION', 'Rejected'))
    render(<CoauthorizationTaskDialog taskId="TASK-A" taskStatus="PENDING_AUTHORIZATION" />)
    const dialog = await openDialog()
    enterBundle(dialog)
    confirmSubmission(dialog)
    fireEvent.click(within(dialog).getByRole('button', { name: '提交外部双签包' }))
    expect(await within(dialog).findByRole('alert')).toHaveTextContent('EXPLICIT_REJECTION')
    expect(within(dialog).getByRole('textbox', { name: '原始双签 JSON 文本' })).toBeEnabled()
    expect(within(dialog).getByLabelText('选择外部双签 JSON 文件')).toBeEnabled()
    expect(within(dialog).getByRole('checkbox')).not.toBeChecked()
    expect(within(dialog).getByRole('button', { name: '提交外部双签包' })).toBeDisabled()
    expect(within(dialog).queryByText('COAUTH_RESULT_UNCONFIRMED')).not.toBeInTheDocument()
    expect(api.authorizeCoauthorizationTask).toHaveBeenCalledTimes(1)
  })

  it('resets confirmation whenever the external text changes', async () => {
    render(<CoauthorizationTaskDialog taskId="TASK-A" taskStatus="PENDING_AUTHORIZATION" />)
    const dialog = await openDialog()
    enterBundle(dialog)
    confirmSubmission(dialog)
    expect(within(dialog).getByRole('button', { name: '提交外部双签包' })).toBeEnabled()
    enterBundle(dialog, ' {"changed":true} ')
    expect(within(dialog).getByRole('checkbox')).not.toBeChecked()
    expect(within(dialog).getByRole('button', { name: '提交外部双签包' })).toBeDisabled()
  })

  it('enforces the 32768-byte limit by UTF-8 bytes rather than character count', async () => {
    render(<CoauthorizationTaskDialog taskId="TASK-A" taskStatus="PENDING_AUTHORIZATION" />)
    const dialog = await openDialog()
    enterBundle(dialog, `${' '.repeat(32766)}{}`)
    confirmSubmission(dialog)
    expect(within(dialog).getByRole('button', { name: '提交外部双签包' })).toBeEnabled()
    enterBundle(dialog, '中'.repeat(10923))
    expect(within(dialog).getByRole('alert')).toHaveTextContent('超过 32768 字节')
    expect(within(dialog).getByRole('button', { name: '提交外部双签包' })).toBeDisabled()
    expect(api.authorizeCoauthorizationTask).not.toHaveBeenCalled()
  })

  it('preserves file BOM, whitespace, CRLF and duplicate members in the raw submission', async () => {
    render(<CoauthorizationTaskDialog taskId="TASK-A" taskStatus="PENDING_AUTHORIZATION" />)
    const dialog = await openDialog()
    const rawJson = '\uFEFF {\r\n"payload":{"task_id":"TASK-A","task_id":"TASK-A"},"approvals":[]\r\n} '
    const { file, read } = jsonFile(new TextEncoder().encode(rawJson))
    vi.mocked(api.authorizeCoauthorizationTask).mockRejectedValue(new ApiError(400, 'INVALID_JSON', 'Rejected'))
    fireEvent.change(within(dialog).getByLabelText('选择外部双签 JSON 文件'), { target: { files: [file] } })
    await waitFor(() => expect(within(dialog).getByRole('button', { name: '选择 JSON 文件' })).toBeEnabled())
    expect(read).toHaveBeenCalledTimes(1)
    confirmSubmission(dialog)
    fireEvent.click(within(dialog).getByRole('button', { name: '提交外部双签包' }))
    await within(dialog).findByRole('alert')
    expect(api.authorizeCoauthorizationTask).toHaveBeenCalledWith('TASK-A', rawJson)
  })

  it('rejects malformed UTF-8 and clears the previously loaded external text', async () => {
    render(<CoauthorizationTaskDialog taskId="TASK-A" taskStatus="PENDING_AUTHORIZATION" />)
    const dialog = await openDialog()
    enterBundle(dialog)
    confirmSubmission(dialog)
    const { file } = jsonFile(new Uint8Array([0xc3, 0x28]))
    fireEvent.change(within(dialog).getByLabelText('选择外部双签 JSON 文件'), { target: { files: [file] } })
    expect(await within(dialog).findByRole('alert')).toHaveTextContent('严格 UTF-8 解码失败')
    expect(within(dialog).getByRole('textbox', { name: '原始双签 JSON 文本' })).toHaveValue('')
    expect(within(dialog).getByRole('checkbox')).not.toBeChecked()
    expect(within(dialog).getByRole('button', { name: '提交外部双签包' })).toBeDisabled()
  })

  it('rejects oversized files before reading their contents', async () => {
    render(<CoauthorizationTaskDialog taskId="TASK-A" taskStatus="PENDING_AUTHORIZATION" />)
    const dialog = await openDialog()
    const { file, read } = jsonFile(new Uint8Array(32769))
    fireEvent.change(within(dialog).getByLabelText('选择外部双签 JSON 文件'), { target: { files: [file] } })
    expect(await within(dialog).findByRole('alert')).toHaveTextContent('超过 32768 字节，未载入')
    expect(read).not.toHaveBeenCalled()
    expect(api.authorizeCoauthorizationTask).not.toHaveBeenCalled()
  })

  it('distinguishes consumed, pending, revoked and observed window states without inferring a partial approval', async () => {
    vi.mocked(api.coauthorizationTask).mockResolvedValue(review('TASK-A', [
      historyEntry({ challenge_id: 'CHALLENGE-consumed', challenge_status: 'CONSUMED', consumed_at: 1700000150,
        signed_bundle: bundle, bundle_hash: result.bundle_hash, root_credential_id: result.root_credential_id }),
      // Deliberately malformed pending projection; never promote its partial bundle to an approval.
      historyEntry({ challenge_id: 'CHALLENGE-pending', signed_bundle: { ...bundle, approvals: [bundle.approvals[0]] } }),
      historyEntry({ challenge_id: 'CHALLENGE-revoked', challenge_status: 'REVOKED', window_state: 'EXPIRED', revoked_at: 1700000160 }),
    ]))
    render(<CoauthorizationTaskDialog taskId="TASK-A" taskStatus="PENDING_AUTHORIZATION" />)
    const dialog = await openDialog()
    expect(within(dialog).getByText('已消费')).toBeInTheDocument()
    expect(within(dialog).getByText('待提交')).toBeInTheDocument()
    expect(within(dialog).getByText('已撤销')).toBeInTheDocument()
    expect(within(dialog).getAllByText('读取时开放（OPEN）')).toHaveLength(2)
    expect(within(dialog).getByText('读取时已过期（EXPIRED）')).toBeInTheDocument()
    const pending = within(dialog).getByText('CHALLENGE-pending').closest('article')!
    fireEvent.click(within(pending).getByText('查看挑战记录'))
    expect(within(pending).queryByText('企业审批记录')).not.toBeInTheDocument()
    expect(within(pending).queryByRole('button', { name: '下载历史双签包' })).not.toBeInTheDocument()
    const consumed = within(dialog).getByText('CHALLENGE-consumed').closest('article')!
    fireEvent.click(within(consumed).getByText('查看挑战记录'))
    expect(within(consumed).getByText('企业审批记录')).toBeInTheDocument()
    expect(within(consumed).getByText('财务审批记录')).toBeInTheDocument()
    expect(within(consumed).getAllByText('ENTERPRISE-fixture')).toHaveLength(2)
    expect(within(consumed).getAllByText(/声明时间/)).toHaveLength(2)
    expect(within(consumed).getAllByText(/签名时间/)).toHaveLength(2)
    expect(within(consumed).getByRole('button', { name: '下载历史双签包' })).toBeEnabled()
    expect(within(dialog).queryByText('审批通过')).not.toBeInTheDocument()
    expect(within(dialog).queryByText('验签成功')).not.toBeInTheDocument()
  })

  it('exposes the complete stored history JSON on pending, consumed and revoked entries', async () => {
    const entries = [
      historyEntry(),
      historyEntry({ challenge_id: 'CHALLENGE-consumed', challenge_status: 'CONSUMED', signed_bundle: bundle, consumed_at: 1700000150 }),
      historyEntry({ challenge_id: 'CHALLENGE-revoked', challenge_status: 'REVOKED', revoked_at: 1700000160, window_state: 'NOT_YET_VALID' }),
    ]
    vi.mocked(api.coauthorizationTask).mockResolvedValue(review('TASK-A', entries))
    render(<CoauthorizationTaskDialog taskId="TASK-A" taskStatus="PENDING_AUTHORIZATION" />)
    const dialog = await openDialog()
    for (const entry of entries) {
      const row = within(dialog).getByText(entry.challenge_id).closest('article')!
      fireEvent.click(within(row).getByText('查看挑战记录'))
      const summary = within(row).getByText('查看完整历史 JSON')
      fireEvent.click(summary)
      const details = summary.closest('details')!
      expect(details.querySelector('pre')?.textContent).toBe(JSON.stringify(entry, null, 2))
      expect(details.querySelector('pre')).toHaveTextContent('COAUTHORIZATION_TASK_APPROVAL')
      expect(details.querySelector('pre')).toHaveTextContent('TASK_COAUTHORIZATION_APPROVAL_V1')
      expect(details.querySelector('pre')).toHaveTextContent('agentguard-root-authorization')
    }
    expect(within(dialog).getByText('读取时尚未生效（NOT_YET_VALID）')).toBeInTheDocument()
    expect(api.authorizeCoauthorizationTask).not.toHaveBeenCalled()
  })

  it('uses fixed 20-entry pagination and clears old history after a failed page read', async () => {
    vi.mocked(api.coauthorizationTask).mockResolvedValueOnce(review('TASK-A', [historyEntry()], 0, true))
      .mockResolvedValueOnce(review('TASK-A', [historyEntry({ challenge_id: 'CHALLENGE-page-2' })], 20, false))
      .mockRejectedValueOnce(new ApiError(503, 'UNAVAILABLE', 'Unavailable'))
    render(<CoauthorizationTaskDialog taskId="TASK-A" taskStatus="PENDING_AUTHORIZATION" />)
    const dialog = await openDialog()
    fireEvent.click(within(dialog).getByRole('button', { name: '下一页共同审批历史' }))
    await within(dialog).findByText('CHALLENGE-page-2')
    expect(api.coauthorizationTask).toHaveBeenLastCalledWith('TASK-A', 20)
    expect(within(dialog).getByText('第 2 页 · 每页 20 条')).toBeInTheDocument()
    expect(within(dialog).getByRole('button', { name: '下一页共同审批历史' })).toBeDisabled()
    fireEvent.click(within(dialog).getByRole('button', { name: '上一页共同审批历史' }))
    expect(await within(dialog).findByRole('alert')).toHaveTextContent('旧记录已清空')
    expect(api.coauthorizationTask).toHaveBeenLastCalledWith('TASK-A', 0)
    expect(within(dialog).queryByText('CHALLENGE-page-2')).not.toBeInTheDocument()
    expect(within(dialog).queryByText(payload.challenge_id)).not.toBeInTheDocument()
  })

  it('ignores configuration and history responses from a closed session', async () => {
    const firstAuthority = deferred<CoauthorizationStatus>()
    const firstHistory = deferred<CoauthorizationTaskReview>()
    vi.mocked(api.coauthorizationStatus).mockReturnValueOnce(firstAuthority.promise)
      .mockResolvedValueOnce({ ...enabled, enabled: false })
    vi.mocked(api.coauthorizationTask).mockReturnValueOnce(firstHistory.promise).mockResolvedValueOnce(review())
    render(<CoauthorizationTaskDialog taskId="TASK-A" taskStatus="PENDING_AUTHORIZATION" />)
    fireEvent.click(screen.getByRole('button', { name: '共同审批' }))
    const first = await screen.findByRole('dialog')
    fireEvent.click(within(first).getByRole('button', { name: '关闭' }))
    const second = await openDialog()
    await within(second).findByText('未启用')
    await act(async () => {
      firstAuthority.resolve(enabled)
      firstHistory.resolve(review('TASK-A', [historyEntry()]))
      await Promise.all([firstAuthority.promise, firstHistory.promise])
    })
    expect(within(second).queryByText('要求两方审批')).not.toBeInTheDocument()
    expect(within(second).queryByText(payload.challenge_id)).not.toBeInTheDocument()
    expect(within(second).getByText('暂无挑战记录')).toBeInTheDocument()
  })

  it('disables closing and editing throughout a pending challenge mutation', async () => {
    const pending = deferred<CoauthorizationChallenge>()
    vi.mocked(api.createCoauthorizationChallenge).mockReturnValue(pending.promise)
    render(<CoauthorizationTaskDialog taskId="TASK-A" taskStatus="PENDING_AUTHORIZATION" />)
    const dialog = await openDialog()
    fireEvent.click(within(dialog).getByRole('button', { name: '生成挑战' }))
    expect(within(dialog).getByRole('button', { name: '关闭' })).toBeDisabled()
    expect(within(dialog).getByRole('textbox', { name: '持有者智能体' })).toBeDisabled()
    expect(within(dialog).getByRole('textbox', { name: '原始双签 JSON 文本' })).toBeDisabled()
    expect(within(dialog).getByRole('button', { name: '刷新配置与历史' })).toBeDisabled()
    fireEvent.keyDown(dialog, { key: 'Escape', code: 'Escape', keyCode: 27 })
    expect(screen.getByRole('dialog')).toBeInTheDocument()
    await act(async () => { pending.resolve(challenge); await pending.promise })
    await waitFor(() => expect(within(dialog).getByRole('button', { name: '关闭' })).toBeEnabled())
  })

  it('ignores an old task authorization result and never calls onChanged for it after task switching', async () => {
    const pending = deferred<CoauthorizationResult>()
    const changed = vi.fn().mockResolvedValue(undefined)
    vi.mocked(api.authorizeCoauthorizationTask).mockReturnValue(pending.promise)
    vi.mocked(api.coauthorizationTask).mockImplementation((taskId) => Promise.resolve(review(taskId)))
    const { rerender } = render(<CoauthorizationTaskDialog taskId="TASK-A" taskStatus="PENDING_AUTHORIZATION" onChanged={changed} />)
    const first = await openDialog()
    enterBundle(first)
    confirmSubmission(first)
    fireEvent.click(within(first).getByRole('button', { name: '提交外部双签包' }))
    expect(within(first).getByRole('button', { name: '关闭' })).toBeDisabled()
    rerender(<CoauthorizationTaskDialog taskId="TASK-B" taskStatus="PENDING_AUTHORIZATION" onChanged={changed} />)
    const second = await openDialog()
    await act(async () => { pending.resolve(result); await pending.promise })
    expect(within(second).getByText('TASK-B')).toBeInTheDocument()
    expect(within(second).queryByText('ROOT-fixture')).not.toBeInTheDocument()
    expect(within(second).getByRole('textbox', { name: '原始双签 JSON 文本' })).toHaveValue('')
    expect(changed).not.toHaveBeenCalled()
    expect(api.coauthorizationTask).toHaveBeenCalledTimes(2)
  })

  it('ignores a challenge result and a file read after their task is unmounted', async () => {
    const pendingChallenge = deferred<CoauthorizationChallenge>()
    vi.mocked(api.createCoauthorizationChallenge).mockReturnValue(pendingChallenge.promise)
    const changed = vi.fn().mockResolvedValue(undefined)
    const firstRender = render(<CoauthorizationTaskDialog taskId="TASK-A" taskStatus="PENDING_AUTHORIZATION" onChanged={changed} />)
    const first = await openDialog()
    fireEvent.click(within(first).getByRole('button', { name: '生成挑战' }))
    firstRender.unmount()
    await act(async () => { pendingChallenge.resolve(challenge); await pendingChallenge.promise })
    expect(api.coauthorizationTask).toHaveBeenCalledTimes(1)
    const pendingFile = deferred<ArrayBuffer>()
    const { file, buffer } = jsonFile(new TextEncoder().encode('{"old":true}'), pendingFile.promise)
    const secondRender = render(<CoauthorizationTaskDialog taskId="TASK-B" taskStatus="PENDING_AUTHORIZATION" onChanged={changed} />)
    vi.mocked(api.coauthorizationTask).mockResolvedValue(review('TASK-B'))
    const second = await openDialog()
    fireEvent.change(within(second).getByLabelText('选择外部双签 JSON 文件'), { target: { files: [file] } })
    secondRender.unmount()
    await act(async () => { pendingFile.resolve(buffer); await pendingFile.promise })
    expect(changed).not.toHaveBeenCalled()
    expect(api.authorizeCoauthorizationTask).not.toHaveBeenCalled()
  })

  it('keeps the Authority response visible when history or the parent page refresh fails', async () => {
    const changed = vi.fn().mockRejectedValue(new Error('Page unavailable'))
    vi.mocked(api.coauthorizationTask).mockResolvedValueOnce(review('TASK-A', [historyEntry()]))
      .mockRejectedValueOnce(new ApiError(503, 'UNAVAILABLE', 'Unavailable'))
    render(<CoauthorizationTaskDialog taskId="TASK-A" taskStatus="PENDING_AUTHORIZATION" onChanged={changed} />)
    const dialog = await openDialog()
    enterBundle(dialog)
    confirmSubmission(dialog)
    fireEvent.click(within(dialog).getByRole('button', { name: '提交外部双签包' }))
    await within(dialog).findByText('ROOT-fixture')
    await waitFor(() => expect(within(dialog).getAllByRole('alert').some((node) => node.textContent?.includes('授权已返回，但页面记录刷新失败'))).toBe(true))
    expect(changed).toHaveBeenCalledWith('TASK-A')
    expect(api.authorizeCoauthorizationTask).toHaveBeenCalledTimes(1)
    expect(within(dialog).queryByText('提交未获得授权返回，请读取历史核对结果。')).not.toBeInTheDocument()
    expect(within(dialog).queryByRole('button', { name: '下载历史双签包' })).not.toBeInTheDocument()
    expect(within(dialog).getByRole('checkbox')).not.toBeChecked()
    expect(within(dialog).getByRole('button', { name: '提交外部双签包' })).toBeDisabled()
  })

  it('reports idempotent reuse as an Authority return and refreshes the same task once', async () => {
    const changed = vi.fn().mockResolvedValue(undefined)
    vi.mocked(api.authorizeCoauthorizationTask).mockResolvedValue({ ...result, reused: true })
    render(<CoauthorizationTaskDialog taskId="TASK-A" taskStatus="AUTHORIZED" onChanged={changed} />)
    const dialog = await openDialog()
    expect(within(dialog).getByRole('button', { name: '生成挑战' })).toBeDisabled()
    enterBundle(dialog)
    confirmSubmission(dialog)
    fireEvent.click(within(dialog).getByRole('button', { name: '提交外部双签包' }))
    await within(dialog).findByText('返回已有根授权')
    await waitFor(() => expect(changed).toHaveBeenCalledTimes(1))
    expect(changed).toHaveBeenCalledWith('TASK-A')
    expect(api.coauthorizationTask).toHaveBeenLastCalledWith('TASK-A', 0)
  })

  it('rejects history or challenge responses belonging to another task', async () => {
    vi.mocked(api.coauthorizationTask).mockResolvedValueOnce(review('TASK-B')).mockResolvedValueOnce(review())
    vi.mocked(api.createCoauthorizationChallenge).mockResolvedValue({ ...challenge, payload: { ...payload, task_id: 'TASK-B' } })
    render(<CoauthorizationTaskDialog taskId="TASK-A" taskStatus="PENDING_AUTHORIZATION" />)
    const dialog = await openDialog()
    expect(within(dialog).getByRole('alert')).toHaveTextContent('历史读取失败')
    expect(within(dialog).getByRole('button', { name: '生成挑战' })).toBeDisabled()
    fireEvent.click(within(dialog).getByRole('button', { name: '刷新配置与历史' }))
    await waitFor(() => expect(within(dialog).getByRole('button', { name: '生成挑战' })).toBeEnabled())
    fireEvent.click(within(dialog).getByRole('button', { name: '生成挑战' }))
    expect(await within(dialog).findByRole('alert')).toHaveTextContent('挑战生成未获得有效返回')
    expect(within(dialog).queryByRole('button', { name: '下载待签任务 JSON' })).not.toBeInTheDocument()
    expect(within(dialog).queryByText('TASK-B')).not.toBeInTheDocument()
  })

  it('does not mutate a closed task even if a previously read page says pending', async () => {
    render(<CoauthorizationTaskDialog taskId="TASK-A" taskStatus="CLOSED" />)
    const dialog = await openDialog()
    enterBundle(dialog)
    expect(within(dialog).getByRole('button', { name: '生成挑战' })).toBeDisabled()
    expect(within(dialog).getByRole('checkbox')).toBeDisabled()
    expect(within(dialog).getByRole('button', { name: '提交外部双签包' })).toBeDisabled()
  })
})
