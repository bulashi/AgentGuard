import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { App } from 'antd'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { BusinessWorkspace } from './BusinessWorkspace'
import { api, ApiError } from '../api'
import { runtimeProfiles, savedSnapshot, workflowSnapshot } from '../test/fixtures'
import type { TaskSnapshot } from '../types'

const started = { run_id: 'RUN-new', task_id: 'TASK-new', state: 'QUEUED', runtime_mode: 'deterministic' as const }

function workspace(snapshot: TaskSnapshot | null = workflowSnapshot) {
  const inspect = vi.fn()
  const onStarted = vi.fn().mockResolvedValue(undefined)
  const onAuthorization = vi.fn()
  const onHistory = vi.fn()
  const props = { onInspect: inspect, onStarted, onHistory, onAuthorization }
  const view = render(<App><BusinessWorkspace snapshot={snapshot} {...props} /></App>)
  return { inspect, onStarted, onAuthorization, onHistory,
    changeTask: (next: TaskSnapshot | null) => view.rerender(<App><BusinessWorkspace snapshot={next} {...props} /></App>) }
}

function authorizedSnapshot(): TaskSnapshot {
  const now = Math.floor(Date.now() / 1000)
  return { ...savedSnapshot, task: { ...savedSnapshot.task, expires_at: now + 600 },
    credentials: [{ ...savedSnapshot.credentials[0], not_before: now - 1, expires_at: now + 600 }],
    executions: [], receipts: [], audit_events: [], workflow_runs: [], business_effects: { refunds: [], notifications: [] } }
}

function enableCoauthorization() {
  vi.mocked(api.coauthorizationStatus).mockResolvedValue({ schema_version: '1.0', enabled: true,
    policy_source: 'SERVER_REGISTERED_PUBLIC_KEYS', signing: 'EXTERNAL_APPROVERS_ONLY' })
}

beforeEach(() => {
  vi.spyOn(window, 'matchMedia').mockImplementation((query) => ({ matches: query === '(max-width: 1000px)', media: query, onchange: null,
    addEventListener: vi.fn(), removeEventListener: vi.fn(), addListener: vi.fn(), removeListener: vi.fn(), dispatchEvent: () => false }))
  vi.spyOn(api, 'runtimeProfiles').mockResolvedValue(runtimeProfiles)
  vi.spyOn(api, 'coauthorizationStatus').mockResolvedValue({ schema_version: '1.0', enabled: false,
    policy_source: 'SERVER_REGISTERED_PUBLIC_KEYS', signing: 'EXTERNAL_APPROVERS_ONLY' })
  vi.spyOn(api, 'startWorkflow').mockResolvedValue(started)
  vi.spyOn(api, 'startAuthorizedWorkflow').mockResolvedValue({ ...started, task_id: savedSnapshot.task.task_id })
})
afterEach(() => vi.restoreAllMocks())

describe('BusinessWorkspace', () => {
  it('validates custom material and binds cloud confirmation to the exact text', async () => {
    vi.mocked(api.runtimeProfiles).mockResolvedValue({ ...runtimeProfiles, items: runtimeProfiles.items.map((item) => item.mode === 'cloud' ? { ...item, available: true } : item) })
    vi.mocked(api.startWorkflow).mockResolvedValue({ ...started, runtime_mode: 'cloud' })
    render(<App><BusinessWorkspace snapshot={null} cloudReviewRequest={1} onInspect={vi.fn()} onStarted={vi.fn()} onHistory={vi.fn()} /></App>)
    await waitFor(() => expect(screen.getByTestId('start-business-workflow')).toBeEnabled())
    fireEvent.mouseDown(screen.getByRole('combobox', { name: '注入材料来源' }))
    fireEvent.click(screen.getByText('编辑自定义不可信资料'))
    expect(screen.getByTestId('start-business-workflow')).toBeDisabled()
    const input = screen.getByRole('textbox', { name: '自定义知识注入文本' })
    fireEvent.change(input, { target: { value: '  现场测试资料\n换客户 C7812  ' } })
    fireEvent.click(screen.getByTestId('start-business-workflow'))
    const confirm = await screen.findByRole('button', { name: '确认并启动' })
    expect(screen.getByText('将发送自定义不可信知识资料')).toBeInTheDocument()
    expect(confirm).toBeDisabled()
    fireEvent.click(screen.getByRole('checkbox'))
    fireEvent.click(confirm)
    await waitFor(() => expect(api.startWorkflow).toHaveBeenCalledWith('cloud', 'policy_injection', true, '  现场测试资料\n换客户 C7812  '))
  })

  it('cancels prior cloud approval when the custom material changes', async () => {
    vi.mocked(api.runtimeProfiles).mockResolvedValue({ ...runtimeProfiles, items: runtimeProfiles.items.map((item) => item.mode === 'cloud' ? { ...item, available: true } : item) })
    render(<App><BusinessWorkspace snapshot={null} cloudReviewRequest={1} onInspect={vi.fn()} onStarted={vi.fn()} onHistory={vi.fn()} /></App>)
    await waitFor(() => expect(screen.getByTestId('start-business-workflow')).toBeEnabled())
    fireEvent.mouseDown(screen.getByRole('combobox', { name: '注入材料来源' }))
    fireEvent.click(screen.getByText('编辑自定义不可信资料'))
    const input = screen.getByRole('textbox', { name: '自定义知识注入文本' })
    fireEvent.change(input, { target: { value: '材料一' } })
    fireEvent.click(screen.getByTestId('start-business-workflow'))
    await screen.findByRole('button', { name: '确认并启动' })
    fireEvent.click(screen.getByRole('checkbox'))
    fireEvent.change(input, { target: { value: '材料二' } })
    await waitFor(() => expect(screen.queryByRole('button', { name: '确认并启动' })).not.toBeInTheDocument())
    expect(api.startWorkflow).not.toHaveBeenCalled()
  })
  it('marks unreached steps as unexecuted after a knowledge decline', async () => {
    const decline = { ...workflowSnapshot.workflow_runs![0].events[0], agent_id: 'agent-knowledge',
      action: 'plan', status: 'DENIED', details: { stage: 'knowledge_summary', decision: 'decline', intents: [] } }
    const snapshot = { ...workflowSnapshot, executions: [], business_effects: { refunds: [], notifications: [] },
      workflow_runs: workflowSnapshot.workflow_runs!.map((run) => ({ ...run, state: 'DENIED', events: [decline] })) }
    const { inspect } = workspace(snapshot)
    const order = screen.getByTestId('workflow-execution-order')
    expect(within(order).queryByText('等待前序')).not.toBeInTheDocument()
    expect(within(screen.getByRole('button', { name: '查看创建退款' })).getByText('未执行')).toBeInTheDocument()
    fireEvent.click(within(order).getByRole('button', { name: /知识检索/ }))
    expect(inspect).toHaveBeenCalledWith({ kind: 'workflow', runId: snapshot.workflow_runs[0].run_id, sequence: decline.sequence })
  })

  it('shows a rejected business verification as a final refund result in the flow header', () => {
    const snapshot: TaskSnapshot = { ...savedSnapshot, task: { ...savedSnapshot.task, ticket_id: 'T10095', customer_id: 'C9595' },
      business_context: { ticket: { ticket_id: 'T10095', customer_id: 'C9595', title: '重复扣款申请', description: '', status: 'OPEN',
        verification_status: 'REJECTED', payment_verification_status: 'REJECTED', can_refund: false }, documents: [] } }
    workspace(snapshot)
    expect(screen.getByTestId('business-workspace-outcome')).toHaveTextContent('退款业务结果：退款未执行')
    expect(screen.getByTestId('business-workspace-outcome')).toHaveTextContent('业务核验未通过，未提交退款；客户通知未发送')
    expect(screen.getByRole('button', { name: /任务记录/ })).toHaveTextContent('退款未执行')
  })
  it('keeps an explicit injection review when an older normal-run snapshot arrives late', async () => {
    vi.mocked(api.runtimeProfiles).mockResolvedValue({ ...runtimeProfiles, items: runtimeProfiles.items.map((item) => item.mode === 'cloud' ? { ...item, available: true } : item) })
    vi.mocked(api.startWorkflow).mockResolvedValue({ ...started, runtime_mode: 'cloud' })
    const props = { onInspect: vi.fn(), onStarted: vi.fn().mockResolvedValue(undefined), onHistory: vi.fn(), cloudReviewRequest: 1 }
    const view = render(<App><BusinessWorkspace snapshot={null} {...props} /></App>)
    await waitFor(() => expect(screen.getByTestId('start-business-workflow')).toBeEnabled())
    view.rerender(<App><BusinessWorkspace snapshot={workflowSnapshot} {...props} /></App>)
    expect(screen.getByRole('radio', { name: '智能体审查' })).toBeChecked()
    expect(view.container.querySelector('.scenario-control')).toHaveTextContent('关联文档指令注入')
    expect(api.startWorkflow).not.toHaveBeenCalled()
    fireEvent.click(screen.getByTestId('start-business-workflow'))
    const confirm = await screen.findByRole('button', { name: '确认并启动' })
    expect(confirm).toBeDisabled()
    fireEvent.click(screen.getByRole('checkbox'))
    fireEvent.click(confirm)
    await waitFor(() => expect(api.startWorkflow).toHaveBeenCalledWith('cloud', 'policy_injection', true))
  })

  it('shows an expired root as an observation, not a completed authorization', async () => {
    const snapshot = authorizedSnapshot()
    snapshot.credentials[0].expires_at = snapshot.credentials[0].not_before + 1
    const observedAt = snapshot.credentials[0].expires_at
    render(<App><BusinessWorkspace snapshot={snapshot} observedAt={observedAt}
      onInspect={vi.fn()} onStarted={vi.fn()} onHistory={vi.fn()} /></App>)
    const rootNode = screen.getByRole('button', { name: '查看企业授权' })
    expect(within(rootNode).getByText('凭证已过期')).toBeInTheDocument()
    expect(within(rootNode).queryByText('已完成')).not.toBeInTheDocument()
    expect(screen.getByTestId('evidence-rail-authorization')).toHaveTextContent('凭证已过期')
    expect(screen.getByTestId('evidence-rail-authorization')).not.toHaveTextContent('签名有效')
  })

  it('distinguishes a queued run from active execution without hiding stored records', async () => {
    const snapshot = { ...workflowSnapshot, workflow_runs: workflowSnapshot.workflow_runs?.map((item) => ({ ...item, state: 'QUEUED' })) }
    workspace(snapshot)
    expect(screen.getByTestId('start-business-workflow')).toHaveTextContent('协作等待运行')
    expect(screen.getByText('等待调度 · 已入队')).toBeInTheDocument()
    expect(screen.getByTestId('evidence-rail-business')).toHaveTextContent('70.00')
  })

  it('opens every role and the protected gateway/tools from the compact graph', async () => {
    const { inspect } = workspace()
    await screen.findByText('已保存运行记录')
    for (const [label, agentId] of [['协调智能体', 'agent-coordinator'], ['知识智能体', 'agent-knowledge'], ['工单智能体', 'agent-case'], ['退款智能体', 'agent-refund']]) {
      fireEvent.click(screen.getByRole('button', { name: `查看${label}` }))
      expect(inspect).toHaveBeenLastCalledWith({ kind: 'agent', agentId })
    }
    fireEvent.click(screen.getByRole('button', { name: '查看安全网关' }))
    expect(inspect).toHaveBeenLastCalledWith({ kind: 'stage', stage: 'gateway' })
    fireEvent.click(screen.getByRole('button', { name: '查看创建退款' }))
    expect(inspect).toHaveBeenLastCalledWith({ kind: 'execution', execution: workflowSnapshot.executions[0] })
    expect(within(screen.getByTestId('business-graph')).getAllByRole('button')).toHaveLength(10)
  })

  it('maps an archived local run to cloud review without silently starting or changing the old task', async () => {
    vi.mocked(api.runtimeProfiles).mockResolvedValue({ ...runtimeProfiles, items: runtimeProfiles.items.map((item) => item.mode === 'cloud' ? { ...item, available: true } : item) })
    vi.mocked(api.startWorkflow).mockResolvedValue({ ...started, runtime_mode: 'cloud' })
    const { onStarted } = workspace()
    const start = screen.getByTestId('start-business-workflow')
    await waitFor(() => expect(start).toBeEnabled())
    expect(screen.getByRole('radio', { name: '智能体审查' })).toBeChecked()
    expect(screen.queryByRole('radio', { name: '本地模型' })).not.toBeInTheDocument()
    fireEvent.click(start)
    const confirm = await screen.findByRole('button', { name: '确认并启动' })
    expect(confirm).toBeDisabled()
    expect(api.startWorkflow).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('checkbox'))
    fireEvent.click(confirm)
    await waitFor(() => expect(api.startWorkflow).toHaveBeenCalledWith('cloud', 'normal', true))
    expect(onStarted).toHaveBeenCalledWith({ ...started, runtime_mode: 'cloud' })
  })

  it('keeps an unconfigured cloud mode disabled', async () => {
    workspace(null)
    await waitFor(() => expect(screen.getByTestId('start-business-workflow')).toBeEnabled())
    expect(screen.getByRole('radio', { name: '智能体审查' })).toBeDisabled()
  })

  it('requires explicit confirmation before a configured cloud request', async () => {
    vi.mocked(api.startWorkflow).mockResolvedValue({ ...started, runtime_mode: 'cloud' })
    vi.mocked(api.runtimeProfiles).mockResolvedValue({ ...runtimeProfiles, items: runtimeProfiles.items.map((item) => item.mode === 'cloud' ? { ...item, available: true } : item) })
    workspace(null)
    await waitFor(() => expect(screen.getByRole('radio', { name: '智能体审查' })).toBeEnabled())
    fireEvent.click(screen.getByRole('radio', { name: '智能体审查' }))
    fireEvent.click(screen.getByTestId('start-business-workflow'))
    const confirm = await screen.findByRole('button', { name: '确认并启动' })
    expect(confirm).toBeDisabled()
    expect(api.startWorkflow).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('checkbox'))
    fireEvent.click(confirm)
    await waitFor(() => expect(api.startWorkflow).toHaveBeenCalledWith('cloud', 'normal', true))
  })

  it('blocks the single-sign workflow when independent coauthorization is enabled', async () => {
    enableCoauthorization()
    const { onAuthorization } = workspace(null)
    expect(await screen.findByText('共同授权已启用')).toBeInTheDocument()
    expect(screen.getByTestId('start-business-workflow')).toBeDisabled()
    expect(api.startWorkflow).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button', { name: '打开当前任务授权' }))
    expect(onAuthorization).toHaveBeenCalledOnce()
  })

  it('waits for an explicit approval configuration instead of assuming single-sign mode', async () => {
    vi.mocked(api.coauthorizationStatus).mockReturnValue(new Promise(() => undefined))
    workspace(null)
    await waitFor(() => expect(api.runtimeProfiles).toHaveBeenCalled())
    expect(screen.getByTestId('start-business-workflow')).toBeDisabled()
    expect(screen.getByTestId('start-business-workflow')).toHaveTextContent('授权配置未确认')
    expect(api.startWorkflow).not.toHaveBeenCalled()
  })

  it('keeps configuration failures closed and offers explicit refresh without starting', async () => {
    vi.mocked(api.coauthorizationStatus).mockRejectedValueOnce(new Error('unavailable')).mockResolvedValue({
      schema_version: '1.0', enabled: false, policy_source: 'SERVER_REGISTERED_PUBLIC_KEYS', signing: 'EXTERNAL_APPROVERS_ONLY',
    })
    workspace(null)
    expect(await screen.findByText('共同授权配置读取失败')).toBeInTheDocument()
    expect(screen.getByTestId('start-business-workflow')).toBeDisabled()
    fireEvent.click(screen.getByRole('button', { name: '刷新运行与授权配置' }))
    await waitFor(() => expect(screen.getByTestId('start-business-workflow')).toBeEnabled())
    expect(api.startWorkflow).not.toHaveBeenCalled()
  })

  it('explicitly starts the same authorized task without creating a new single-sign demo', async () => {
    enableCoauthorization()
    const snapshot = authorizedSnapshot()
    const { onStarted } = workspace(snapshot)
    expect(screen.getByLabelText('根授权已签发（AUTHORIZED）')).toBeInTheDocument()
    const start = screen.getByTestId('start-business-workflow')
    await waitFor(() => expect(start).toBeEnabled())
    expect(start).toHaveTextContent('运行当前任务')
    expect(api.startAuthorizedWorkflow).not.toHaveBeenCalled()
    fireEvent.click(start)
    await waitFor(() => expect(api.startAuthorizedWorkflow).toHaveBeenCalledWith(snapshot.task.task_id, 'deterministic', 'normal', false))
    expect(api.startWorkflow).not.toHaveBeenCalled()
    expect(onStarted).toHaveBeenCalledWith({ ...started, task_id: snapshot.task.task_id })
  })

  it('routes a pending task to its own authorization and runs only that task after it is authorized', async () => {
    const pending = authorizedSnapshot()
    pending.task.status = 'PENDING_AUTHORIZATION'
    const { changeTask, onAuthorization } = workspace(pending)

    await waitFor(() => expect(screen.getByTestId('start-business-workflow')).toHaveTextContent('打开当前任务授权'))
    expect(screen.getByTestId('start-business-workflow')).toBeEnabled()
    fireEvent.click(screen.getByTestId('start-business-workflow'))
    expect(onAuthorization).toHaveBeenCalledOnce()
    expect(api.startWorkflow).not.toHaveBeenCalled()
    expect(api.startAuthorizedWorkflow).not.toHaveBeenCalled()

    changeTask({ ...pending, task: { ...pending.task, status: 'AUTHORIZED' } })
    await waitFor(() => expect(screen.getByTestId('start-business-workflow')).toHaveTextContent('运行当前任务'))
    expect(screen.getByTestId('start-business-workflow')).toBeEnabled()
    fireEvent.click(screen.getByTestId('start-business-workflow'))
    await waitFor(() => expect(api.startAuthorizedWorkflow).toHaveBeenCalledWith(pending.task.task_id, 'deterministic', 'normal', false))
    expect(api.startWorkflow).not.toHaveBeenCalled()
  })
  it('starts the selected authorized task even when joint approval is disabled', async () => {
    const snapshot = authorizedSnapshot()
    snapshot.task.ticket_id = 'T10089'
    snapshot.task.customer_id = 'C9528'
    const { onStarted } = workspace(snapshot)
    const start = screen.getByTestId('start-business-workflow')
    await waitFor(() => expect(start).toBeEnabled())
    expect(start).toHaveTextContent('运行当前任务')
    fireEvent.click(start)
    await waitFor(() => expect(api.startAuthorizedWorkflow).toHaveBeenCalledWith(snapshot.task.task_id, 'deterministic', 'normal', false))
    expect(api.startWorkflow).not.toHaveBeenCalled()
    expect(onStarted).toHaveBeenCalledWith({ ...started, task_id: snapshot.task.task_id })
  })
  it('binds single-approval cloud confirmation to the current task without creating a default task', async () => {
    vi.mocked(api.runtimeProfiles).mockResolvedValue({ ...runtimeProfiles, items: runtimeProfiles.items.map((item) => item.mode === 'cloud' ? { ...item, available: true } : item) })
    const snapshot = authorizedSnapshot()
    vi.mocked(api.startAuthorizedWorkflow).mockResolvedValue({ ...started, task_id: snapshot.task.task_id, runtime_mode: 'cloud' })
    workspace(snapshot)
    await waitFor(() => expect(screen.getByTestId('start-business-workflow')).toBeEnabled())
    fireEvent.click(screen.getByTestId('start-business-workflow'))
    expect(await screen.findByText(/本次目标：已授权任务/)).toHaveTextContent(snapshot.task.task_id)
    const confirm = screen.getByRole('button', { name: '确认并启动' })
    expect(confirm).toBeDisabled()
    fireEvent.click(screen.getByRole('checkbox'))
    fireEvent.click(confirm)
    await waitFor(() => expect(api.startAuthorizedWorkflow).toHaveBeenCalledWith(snapshot.task.task_id, 'cloud', 'normal', true))
    expect(api.startWorkflow).not.toHaveBeenCalled()
  })
  it('does not fall back to a default task if single-approval authorization expires during cloud confirmation', async () => {
    vi.mocked(api.runtimeProfiles).mockResolvedValue({ ...runtimeProfiles, items: runtimeProfiles.items.map((item) => item.mode === 'cloud' ? { ...item, available: true } : item) })
    const snapshot = authorizedSnapshot()
    const { changeTask } = workspace(snapshot)
    await waitFor(() => expect(screen.getByTestId('start-business-workflow')).toBeEnabled())
    fireEvent.click(screen.getByTestId('start-business-workflow'))
    const confirm = await screen.findByRole('button', { name: '确认并启动' })
    changeTask({ ...snapshot, credentials: snapshot.credentials.map((item) => ({ ...item, expires_at: Math.floor(Date.now() / 1000) })) })
    fireEvent.click(screen.getByRole('checkbox'))
    fireEvent.click(confirm)
    expect(await screen.findByText('任务或授权配置已变化，请刷新状态后重新确认')).toBeInTheDocument()
    expect(api.startAuthorizedWorkflow).not.toHaveBeenCalled()
    expect(api.startWorkflow).not.toHaveBeenCalled()
  })

  it.each(['pending', 'revoked', 'expired', 'wrong-holder', 'depth', 'invalid-signature', 'existing-run', 'existing-effect'])(
    'does not start an ineligible current task: %s', async (boundary) => {
      enableCoauthorization()
      const snapshot = authorizedSnapshot()
      if (boundary === 'pending') snapshot.task.status = 'PENDING_AUTHORIZATION'
      if (boundary === 'revoked') snapshot.credentials[0].revoked_at = 0
      if (boundary === 'expired') snapshot.credentials[0].expires_at = Math.floor(Date.now() / 1000)
      if (boundary === 'wrong-holder') snapshot.credentials[0].holder_agent_id = 'agent-refund'
      if (boundary === 'depth') snapshot.credentials[0].delegation_depth = 1
      if (boundary === 'invalid-signature') snapshot.credentials[0] = { ...snapshot.credentials[0], signature: { ...snapshot.credentials[0].signature, valid: false } }
      if (boundary === 'existing-run') snapshot.workflow_runs = workflowSnapshot.workflow_runs
      if (boundary === 'existing-effect') snapshot.business_effects = workflowSnapshot.business_effects
      const { onAuthorization } = workspace(snapshot)
      await screen.findByText('共同授权已启用')
      if (boundary === 'pending') {
        const start = screen.getByTestId('start-business-workflow')
        expect(start).toHaveTextContent('打开当前任务授权')
        expect(start).toBeEnabled()
        fireEvent.click(start)
        expect(onAuthorization).toHaveBeenCalledOnce()
        expect(api.startWorkflow).not.toHaveBeenCalled()
        expect(api.startAuthorizedWorkflow).not.toHaveBeenCalled()
        return
      }
      expect(screen.getByTestId('start-business-workflow')).toBeDisabled()
      expect(api.startAuthorizedWorkflow).not.toHaveBeenCalled()
    },
  )

  it('binds cloud confirmation to the selected task and cancels it on task change', async () => {
    enableCoauthorization()
    vi.mocked(api.runtimeProfiles).mockResolvedValue({ ...runtimeProfiles, items: runtimeProfiles.items.map((item) => item.mode === 'cloud' ? { ...item, available: true } : item) })
    const snapshot = authorizedSnapshot()
    const { changeTask } = workspace(snapshot)
    await waitFor(() => expect(screen.getByTestId('start-business-workflow')).toBeEnabled())
    fireEvent.click(screen.getByRole('radio', { name: '智能体审查' }))
    fireEvent.click(screen.getByTestId('start-business-workflow'))
    expect(await screen.findByRole('button', { name: '确认并启动' })).toBeDisabled()
    expect(api.startAuthorizedWorkflow).not.toHaveBeenCalled()
    changeTask({ ...snapshot, task: { ...snapshot.task, task_id: 'TASK-other' } })
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    expect(api.startAuthorizedWorkflow).not.toHaveBeenCalled()
  })

  it('requires explicit cloud confirmation for the same already-authorized task', async () => {
    enableCoauthorization()
    vi.mocked(api.runtimeProfiles).mockResolvedValue({ ...runtimeProfiles, items: runtimeProfiles.items.map((item) => item.mode === 'cloud' ? { ...item, available: true } : item) })
    const snapshot = authorizedSnapshot()
    vi.mocked(api.startAuthorizedWorkflow).mockResolvedValue({ ...started, task_id: snapshot.task.task_id, runtime_mode: 'cloud' })
    workspace(snapshot)
    await waitFor(() => expect(screen.getByTestId('start-business-workflow')).toBeEnabled())
    fireEvent.click(screen.getByRole('radio', { name: '智能体审查' }))
    fireEvent.click(screen.getByTestId('start-business-workflow'))
    const confirm = await screen.findByRole('button', { name: '确认并启动' })
    fireEvent.click(screen.getByRole('checkbox'))
    fireEvent.click(confirm)
    await waitFor(() => expect(api.startAuthorizedWorkflow).toHaveBeenCalledWith(snapshot.task.task_id, 'cloud', 'normal', true))
    expect(api.startWorkflow).not.toHaveBeenCalled()
  })

  it('locks uncertain submissions rather than automatically retrying them', async () => {
    enableCoauthorization()
    vi.mocked(api.startAuthorizedWorkflow).mockRejectedValue(new ApiError(503, 'WORKFLOW_RESULT_UNCONFIRMED', 'test-only timeout'))
    const { onHistory } = workspace(authorizedSnapshot())
    const start = screen.getByTestId('start-business-workflow')
    await waitFor(() => expect(start).toBeEnabled())
    fireEvent.click(start)
    await waitFor(() => expect(within(screen.getByTestId('business-workspace')).getByRole('alert')).toHaveTextContent('启动结果未确认；请查看任务及运行档案，不要重复启动'))
    expect(start).toBeDisabled()
    fireEvent.click(screen.getByRole('button', { name: '查看运行档案' }))
    expect(onHistory).toHaveBeenCalledOnce()
    expect(api.startAuthorizedWorkflow).toHaveBeenCalledOnce()
  })

  it('keeps an accepted run distinct from a failed status refresh', async () => {
    enableCoauthorization()
    const { onStarted } = workspace(authorizedSnapshot())
    onStarted.mockRejectedValue(new Error('read unavailable'))
    const start = screen.getByTestId('start-business-workflow')
    await waitFor(() => expect(start).toBeEnabled())
    fireEvent.click(start)
    await waitFor(() => expect(within(screen.getByTestId('business-workspace')).getByRole('alert')).toHaveTextContent(`协作 ${started.run_id} 已接收，但状态刷新失败；请查看运行档案，不要重复启动`))
    expect(start).toBeDisabled()
    expect(api.startAuthorizedWorkflow).toHaveBeenCalledOnce()
  })

  it('does not select another task from a mismatched queue response', async () => {
    enableCoauthorization()
    vi.mocked(api.startAuthorizedWorkflow).mockResolvedValue({ ...started, task_id: 'TASK-other' })
    const { onStarted } = workspace(authorizedSnapshot())
    const start = screen.getByTestId('start-business-workflow')
    await waitFor(() => expect(start).toBeEnabled())
    fireEvent.click(start)
    await waitFor(() => expect(within(screen.getByTestId('business-workspace')).getByRole('alert')).toHaveTextContent('启动结果未确认'))
    expect(onStarted).not.toHaveBeenCalled()
    expect(start).toBeDisabled()
    expect(api.startAuthorizedWorkflow).toHaveBeenCalledOnce()
  })

  it('does not select an old task when its queued response arrives after the user changes tasks', async () => {
    enableCoauthorization()
    let resolveStart!: (value: typeof started) => void
    vi.mocked(api.startAuthorizedWorkflow).mockReturnValue(new Promise((resolve) => { resolveStart = resolve }))
    const snapshot = authorizedSnapshot()
    const { onStarted, changeTask } = workspace(snapshot)
    await waitFor(() => expect(screen.getByTestId('start-business-workflow')).toBeEnabled())
    fireEvent.click(screen.getByTestId('start-business-workflow'))
    await waitFor(() => expect(api.startAuthorizedWorkflow).toHaveBeenCalledOnce())
    changeTask({ ...snapshot, task: { ...snapshot.task, task_id: 'TASK-other' } })
    resolveStart({ ...started, task_id: snapshot.task.task_id })
    await screen.findByText(`任务 ${snapshot.task.task_id} 已接收协作 ${started.run_id}；当前选择保持不变，可在运行档案查看`)
    expect(onStarted).not.toHaveBeenCalled()
  })

  it('does not fabricate role history for an old task', () => {
    workspace(savedSnapshot)
    expect(screen.getByText('该任务没有新增协作过程记录，图中仅显示已有授权与执行状态。')).toBeInTheDocument()
    expect(within(screen.getByRole('button', { name: '查看退款智能体' })).getByText('等待')).toBeInTheDocument()
    expect(screen.queryByText('逐步回放')).not.toBeInTheDocument()
  })

  it('starts replay before future refunds and delegations exist', async () => {
    workspace()
    fireEvent.click(screen.getByText('逐步回放'))
    fireEvent.click(screen.getByRole('button', { name: '播放或暂停过程回放' }))
    expect(within(screen.getByRole('button', { name: '查看退款智能体' })).getByText('等待')).toBeInTheDocument()
    expect(within(screen.getByRole('button', { name: '查看创建退款' })).getByText('等待')).toBeInTheDocument()
    expect(screen.getByTestId('evidence-rail-business')).toHaveTextContent('0 笔退款')
    expect(screen.getByTestId('evidence-rail-gateway')).toHaveTextContent('0 允许 / 0 拒绝')
    expect(screen.getByTestId('evidence-rail-evidence')).toHaveTextContent('0 / 0 回执核对一致')
    expect(screen.getByRole('button', { name: /0 份子委托/ })).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '查看创建退款' }))
  })
})
