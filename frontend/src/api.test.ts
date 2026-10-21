import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from './api'

beforeEach(() => {
  vi.useFakeTimers()
  vi.stubGlobal('fetch', vi.fn((_path: string, options: RequestInit) => new Promise((_resolve, reject) => {
    options.signal?.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')), { once: true })
  })))
})

describe('model configuration same-origin mutation contract', () => {
  it('sends custom knowledge text while preserving workflow authority fields', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({ state: 'QUEUED' }))))
    await api.startAuthorizedWorkflow('TASK-1', 'cloud', 'policy_injection', true, '现场编辑\n资料')
    const [path, options] = vi.mocked(fetch).mock.calls[0]
    expect(path).toBe('/api/tasks/TASK-1/workflow')
    expect(JSON.parse(String(options?.body))).toEqual({ runtime_mode: 'cloud', scenario: 'policy_injection', cloud_data_confirmed: true, custom_injection_text: '现场编辑\n资料' })
  })
  it.each(['save', 'default', 'delete', 'test'] as const)('adds the configuration guard header for %s without installing a mutation timeout', async (action) => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({ id: 'profile-1', status: 'PASS' }))))
    if (action === 'save') await api.saveModelConfiguration('profile-1', { name: '企业服务', provider_id: 'enterprise',
      base_url: 'https://api.example.com/v1', api_mode: 'chat_completions', model: 'model-1', timeout_seconds: 120, enabled: true })
    if (action === 'default') await api.setDefaultModelConfiguration('profile-1')
    if (action === 'delete') await api.deleteModelConfiguration('profile-1')
    if (action === 'test') await api.testModelConfiguration('profile-1')
    const [path, options] = vi.mocked(fetch).mock.calls[0]
    expect(path).toMatch(/^\/api\/model-configurations\//)
    expect(options?.headers).toMatchObject({ 'Content-Type': 'application/json', 'X-AgentGuard-Configuration': '1' })
    expect(options?.signal).toBeUndefined()
    if (action === 'test') expect(JSON.parse(String(options?.body))).toEqual({ confirm_cloud_call: true })
    expect(vi.getTimerCount()).toBe(0)
  })
  it('uses a bounded public read and does not send a credential or mutation header', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({ items: [], default_id: null, supported_api_modes: ['chat_completions'] }))))
    await api.modelConfigurations()
    expect(fetch).toHaveBeenCalledWith('/api/model-configurations', expect.objectContaining({ headers: { 'Content-Type': 'application/json' } }))
    expect(vi.mocked(fetch).mock.calls[0][1]?.body).toBeUndefined()
  })
})
afterEach(() => { vi.useRealTimers(); vi.unstubAllGlobals() })

describe('read deadlines without abandoning mutations', () => {
  it('preserves localized task field errors instead of HTTP 422', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({
      reason_code: 'REQUEST_SCHEMA_INVALID', message: '请检查任务字段的格式和取值', field_errors: { customer_id: '客户不可含空白' },
    }), { status: 422 })))
    await expect(api.createTask({})).rejects.toMatchObject({
      reasonCode: 'REQUEST_SCHEMA_INVALID', message: '请检查任务字段的格式和取值', fieldErrors: { customer_id: '客户不可含空白' },
    })
  })
  it('handles legacy FastAPI validation arrays without exposing raw input', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({
      detail: [{ loc: ['body', 'customer_id'], type: 'string_pattern_mismatch', input: 'PRIVATE_INPUT' }],
    }), { status: 422 })))
    await expect(api.createTask({})).rejects.toMatchObject({
      reasonCode: 'REQUEST_SCHEMA_INVALID', fieldErrors: { customer_id: '客户格式或取值不正确' },
    })
  })
  it('shares only concurrent audit overview reads and starts a fresh read afterward', async () => {
    const resolvers: Array<(value: Response) => void> = []
    vi.stubGlobal('fetch', vi.fn(() => new Promise<Response>((resolve) => { resolvers.push(resolve) })))
    const first = api.overview()
    const duplicate = api.overview()
    expect(duplicate).toBe(first)
    expect(fetch).toHaveBeenCalledTimes(1)
    resolvers[0](new Response(JSON.stringify({ audit: { verification: { valid: false } } })))
    await expect(first).resolves.toMatchObject({ audit: { verification: { valid: false } } })
    const fresh = api.overview()
    expect(fresh).not.toBe(first)
    expect(fetch).toHaveBeenCalledTimes(2)
    resolvers[1](new Response(JSON.stringify({ audit: { verification: { valid: true } } })))
    await expect(fresh).resolves.toMatchObject({ audit: { verification: { valid: true } } })
  })

  it('keeps ordinary reads bounded at 15 seconds', async () => {
    const result = api.tasks()
    const rejection = expect(result).rejects.toMatchObject({ reasonCode: 'UI_READ_TIMEOUT', message: '只读请求超过 15 秒，未获得新的数据' })
    await vi.advanceTimersByTimeAsync(15000)
    await rejection
  })
  it.each(['overview', 'auditPrefix'] as const)('gives %s a separate full-verification window', async (method) => {
    const result = method === 'overview' ? api.overview() : api.auditPrefix('task-test', [])
    const signal = vi.mocked(fetch).mock.calls[0][1]?.signal
    const rejection = expect(result).rejects.toMatchObject({ reasonCode: 'UI_READ_TIMEOUT', message: '只读请求超过 90 秒，未获得新的数据' })
    await vi.advanceTimersByTimeAsync(15000)
    expect(signal?.aborted).toBe(false)
    await vi.advanceTimersByTimeAsync(75000)
    await rejection
  })
  it('does not install an abandon timer on a potentially committed write', async () => {
    const result = api.createTask({})
    void result
    expect(vi.mocked(fetch).mock.calls[0][1]?.signal).toBeUndefined()
    expect(vi.getTimerCount()).toBe(0)
  })

  it('aborts an obsolete task audit read without treating cancellation as a timeout', async () => {
    const controller = new AbortController()
    const result = api.auditPrefix('task-test', [], controller.signal)
    const rejection = expect(result).rejects.toMatchObject({ name: 'AbortError' })
    controller.abort()
    await rejection
    expect(vi.getTimerCount()).toBe(0)
  })
})
