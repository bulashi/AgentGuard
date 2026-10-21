import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { StrictMode } from 'react'
import { App as AntApp } from 'antd'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import App from './App'
import { api, ApiError } from './api'
import { runtimeProfiles, workflowSnapshot } from './test/fixtures'

vi.mock('./useAuditPrefix', () => ({ useAuditPrefix: () => ({ report: null, error: null, observedAt: undefined }) }))
vi.mock('./useAuditRefresh', () => ({ useAuditRefresh: () => undefined }))
vi.mock('./sections/BusinessWorkspace', () => ({ BusinessWorkspace: ({ presentation }: { presentation: string }) => <section data-testid="test-business" data-presentation={presentation}>协作运行控制</section> }))
vi.mock('./sections/AuthorizationExplorer', () => ({ AuthorizationExplorer: ({ snapshot, onChanged }: {
  snapshot: { task: { task_id: string } } | null; onChanged: (taskId?: string) => Promise<void>
}) => <section data-testid="test-authorization">授权与预算 <span data-testid="authorization-task-id">{snapshot?.task.task_id}</span>
  <button type="button" onClick={() => void onChanged(snapshot?.task.task_id).catch(() => undefined)}>模拟授权刷新</button></section> }))
vi.mock('./sections/AuditEvidence', () => ({ AuditEvidence: ({ section }: { section: string }) => <section data-testid="test-audit">{section}</section> }))
vi.mock('./sections/HistoryView', () => ({ HistoryView: ({ onSelect }: { onSelect: (id: string) => void }) => <button type="button" onClick={() => onSelect(workflowSnapshot.task.task_id)}>打开已保存任务</button> }))
vi.mock('./sections/SecurityLab', () => ({ SecurityLab: () => <section data-testid="test-security">安全测试</section> }))
vi.mock('./sections/Benchmark', () => ({ Benchmark: () => <section data-testid="test-benchmark">系统评测</section> }))

beforeEach(() => {
  window.history.replaceState(null, '', '/')
  vi.spyOn(api, 'bootstrapOperatorSession').mockResolvedValue()
  vi.spyOn(api, 'runtimeProfiles').mockResolvedValue(runtimeProfiles)
  vi.spyOn(api, 'modelConfigurations').mockResolvedValue({ items: [], default_id: null, supported_api_modes: ['chat_completions'] })
  vi.spyOn(api, 'tasks').mockResolvedValue({ items: [{ ...workflowSnapshot.task, credential_count: 4, execution_count: 1 }] })
  vi.spyOn(api, 'task').mockResolvedValue(workflowSnapshot)
  vi.spyOn(api, 'overview').mockRejectedValue(new Error('not part of navigation fixture'))
  vi.spyOn(api, 'matrix').mockRejectedValue(new Error('not part of navigation fixture'))
  vi.spyOn(api, 'benchmarks').mockRejectedValue(new Error('not part of navigation fixture'))
})
afterEach(() => vi.restoreAllMocks())

describe('layered console navigation with synthetic API fixtures', () => {
  it('gates every data read and model settings entry until startup exchange finishes', async () => {
    const token = 'a'.repeat(64)
    window.history.replaceState(null, '', `/?settings=models&task=${workflowSnapshot.task.task_id}#launch_token=${token}`)
    let finish!: () => void
    vi.mocked(api.bootstrapOperatorSession).mockImplementation(() => {
      window.history.replaceState(null, '', `/?settings=models&task=${workflowSnapshot.task.task_id}`)
      return new Promise<void>((resolve) => { finish = resolve })
    })
    render(<AntApp><App /></AntApp>)
    expect(screen.getByText('正在建立本机操作者会话')).toBeInTheDocument()
    for (const read of [api.tasks, api.task, api.overview, api.matrix, api.benchmarks, api.runtimeProfiles, api.modelConfigurations]) {
      expect(read).not.toHaveBeenCalled()
    }
    expect(document.body.textContent).not.toContain(token)
    await act(async () => finish())
    expect(await screen.findByText('智能体运行配置')).toBeInTheDocument()
    await waitFor(() => expect(api.modelConfigurations).toHaveBeenCalledOnce())
    expect(window.location.search).toContain('settings=models')
    expect(window.location.hash).toBe('#overview')
    expect(window.location.search).toContain(workflowSnapshot.task.task_id)
  })

  it('fails closed after an invalid startup exchange, including the model settings shortcut', async () => {
    window.history.replaceState(null, '', '/?settings=models')
    vi.mocked(api.bootstrapOperatorSession).mockRejectedValue(new Error('TEST_ONLY_PRIVATE_TOKEN'))
    render(<AntApp><App /></AntApp>)
    expect(await screen.findByText('需要本机启动授权')).toBeInTheDocument()
    expect(screen.getByText(/请从“启动AgentGuard”进入/)).toBeInTheDocument()
    expect(document.body.textContent).not.toContain('TEST_ONLY_PRIVATE_TOKEN')
    expect(api.tasks).not.toHaveBeenCalled()
    expect(api.modelConfigurations).not.toHaveBeenCalled()
    expect(api.runtimeProfiles).not.toHaveBeenCalled()
    expect(screen.queryByTestId('nav-overview')).not.toBeInTheDocument()
  })

  it('requires launcher entry when a manual URL has no valid operator cookie', async () => {
    window.history.replaceState(null, '', '/?settings=models')
    vi.mocked(api.tasks).mockRejectedValue(new ApiError(401, 'OPERATOR_SESSION_REQUIRED', 'TEST_ONLY_PRIVATE_TOKEN'))
    render(<AntApp><App /></AntApp>)
    expect(await screen.findByText('需要本机启动授权')).toBeInTheDocument()
    expect(api.task).not.toHaveBeenCalled()
    expect(api.overview).not.toHaveBeenCalled()
    expect(api.modelConfigurations).not.toHaveBeenCalled()
    expect(document.body.textContent).not.toContain('TEST_ONLY_PRIVATE_TOKEN')
  })

  it('remains usable when mounted twice under StrictMode with a valid session', async () => {
    render(<StrictMode><AntApp><App /></AntApp></StrictMode>)
    expect(await screen.findByTestId('task-overview')).toBeInTheDocument()
    expect(screen.queryByText('需要本机启动授权')).not.toBeInTheDocument()
  })

  it('keeps a task-scope API failure readable without claiming the selected task does not exist', async () => {
    const failure = new ApiError(403, 'CROSS_TASK', '请求引用了其他任务，未返回本任务快照')
    vi.mocked(api.task).mockRejectedValue(failure)
    render(<AntApp><App /></AntApp>)
    const warning = await screen.findByText(/任务详情暂不可用（请求与当前任务不一致：请求引用了其他任务/)
    expect(warning).toHaveTextContent('尚未获得新的快照')
    expect(warning).not.toHaveTextContent('该任务不存在')
    expect(screen.getByTestId('nav-overview')).toBeInTheDocument()
    expect(screen.queryByTestId('task-overview')).not.toBeInTheDocument()
    expect(failure.reasonCode).toBe('CROSS_TASK')
  })
  it('returns to the same task after its authorization refresh is confirmed', async () => {
    const pending = { ...workflowSnapshot, task: { ...workflowSnapshot.task, status: 'PENDING_AUTHORIZATION' } }
    const authorized = { ...pending, task: { ...pending.task, status: 'AUTHORIZED' } }
    let approvalComplete = false
    vi.mocked(api.tasks).mockImplementation(async () => ({
      items: [{ ...(approvalComplete ? authorized : pending).task, credential_count: 4, execution_count: approvalComplete ? 0 : 1 }],
    }))
    vi.mocked(api.task).mockImplementation(async () => approvalComplete ? authorized : pending)
    render(<AntApp><App /></AntApp>)
    await screen.findByTestId('task-overview')

    fireEvent.click(screen.getByRole('button', { name: '打开当前任务授权' }))
    expect(await screen.findByTestId('test-authorization')).toBeInTheDocument()
    expect(screen.getByTestId('authorization-task-id')).toHaveTextContent(pending.task.task_id)
    expect(screen.getByText(/这里处理的是当前工单的任务授权，不会执行退款/)).toBeInTheDocument()

    approvalComplete = true
    fireEvent.click(screen.getByRole('button', { name: '模拟授权刷新' }))
    await waitFor(() => expect(screen.getByTestId('task-overview')).toBeInTheDocument())
    expect(window.location.hash).toBe('#overview')
    expect(window.location.search).toContain(pending.task.task_id)
    expect(screen.getByTestId('test-business').parentElement).not.toHaveAttribute('hidden')
  })
  it('stays in authorization when the post-approval task refresh is not confirmed', async () => {
    const pending = { ...workflowSnapshot, task: { ...workflowSnapshot.task, status: 'PENDING_AUTHORIZATION' } }
    vi.mocked(api.tasks).mockResolvedValue({ items: [{ ...pending.task, credential_count: 4, execution_count: 0 }] })
    vi.mocked(api.task).mockResolvedValueOnce(pending).mockRejectedValueOnce(new Error('temporary read failure'))
    render(<AntApp><App /></AntApp>)
    await screen.findByTestId('task-overview')

    fireEvent.click(screen.getByRole('button', { name: '打开当前任务授权' }))
    await screen.findByTestId('test-authorization')
    fireEvent.click(screen.getByRole('button', { name: '模拟授权刷新' }))

    await waitFor(() => expect(api.task).toHaveBeenCalledTimes(2))
    expect(window.location.hash).toBe('#evidence')
    expect(screen.getByTestId('test-authorization')).toBeInTheDocument()
    expect(screen.getByText('返回当前工单')).toBeInTheDocument()
  })
  it('defaults to the overview, defers run controls and keeps every feature reachable', async () => {
    render(<AntApp><App /></AntApp>)
    await screen.findByTestId('task-overview')
    expect(screen.queryByText('浏览器边界')).not.toBeInTheDocument()
    expect(screen.queryByText('不持有密钥 · 不直连工具')).not.toBeInTheDocument()
    expect(screen.getByTestId('test-business').parentElement).toHaveAttribute('hidden')
    expect(screen.queryByTestId('execution-records')).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '运行与配置' }))
    expect(screen.getByTestId('test-business').parentElement).not.toHaveAttribute('hidden')
    fireEvent.click(screen.getByTestId('nav-flow'))
    expect(screen.getByTestId('test-business')).toHaveAttribute('data-presentation', 'layered')
    fireEvent.click(screen.getByTestId('nav-records'))
    expect(screen.getByTestId('execution-records')).toBeInTheDocument()
    fireEvent.click(screen.getByTestId('nav-evidence'))
    expect(screen.getByTestId('test-authorization')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('tab', { name: '执行回执' }))
    expect(screen.getByTestId('test-audit')).toHaveTextContent('receipts')
    fireEvent.click(screen.getByRole('tab', { name: '审计记录' }))
    expect(screen.getByTestId('test-audit')).toHaveTextContent('audit')
    fireEvent.click(screen.getByTestId('nav-security'))
    expect(screen.getByTestId('test-security')).toBeInTheDocument()
    fireEvent.click(screen.getByTestId('nav-benchmark'))
    expect(screen.getByTestId('test-benchmark')).toBeInTheDocument()
    expect(window.location.search).toContain(workflowSnapshot.task.task_id)
  })
  it('restores a section URL and returns a historical task to the overview', async () => {
    window.history.replaceState(null, '', '/#records')
    render(<AntApp><App /></AntApp>)
    await screen.findByTestId('execution-records')
    await waitFor(() => expect(screen.getByRole('button', { name: '查看执行 execution-refund' })).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('nav-history'))
    fireEvent.click(screen.getByRole('button', { name: '打开已保存任务' }))
    await screen.findByTestId('task-overview')
    expect(window.location.hash).toBe('#overview')
  })
  it('opens and closes mobile navigation after a section selection', async () => {
    vi.spyOn(window, 'matchMedia').mockImplementation((query) => ({ matches: query === '(max-width: 1000px)', media: query,
      onchange: null, addEventListener: vi.fn(), removeEventListener: vi.fn(), addListener: vi.fn(), removeListener: vi.fn(), dispatchEvent: () => false }))
    render(<AntApp><App /></AntApp>)
    await screen.findByTestId('task-overview')
    expect(screen.getByRole('complementary', { name: '工作区导航', hidden: true })).toHaveAttribute('inert')
    fireEvent.click(screen.getByRole('button', { name: '打开导航' }))
    expect(screen.getByRole('complementary', { name: '工作区导航' })).not.toHaveAttribute('inert')
    fireEvent.click(screen.getByTestId('nav-records'))
    expect(screen.getByRole('button', { name: '打开导航' })).toHaveAttribute('aria-expanded', 'false')
  })
})
