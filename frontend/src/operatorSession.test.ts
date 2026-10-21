import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const TEST_TOKEN = 'a'.repeat(64)

beforeEach(() => {
  vi.resetModules()
  window.history.replaceState(null, '', '/')
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({ authenticated: true }))))
})

afterEach(() => {
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
  window.history.replaceState(null, '', '/')
})

describe('local operator bootstrap with fixture tokens only', () => {
  it('removes the fragment synchronously, preserves settings and task, and exchanges only once', async () => {
    const storage = vi.spyOn(Storage.prototype, 'setItem')
    window.history.replaceState(null, '', `/?settings=models&task=task-1#launch_token=${TEST_TOKEN}`)
    const { api } = await import('./api')
    const first = api.bootstrapOperatorSession()
    const duplicate = api.bootstrapOperatorSession()
    expect(duplicate).toBe(first)
    expect(window.location.hash).toBe('')
    expect(window.location.search).toBe('?settings=models&task=task-1')
    expect(fetch).toHaveBeenCalledExactlyOnceWith('/api/operator-session', expect.objectContaining({
      method: 'POST', credentials: 'same-origin', cache: 'no-store', redirect: 'error',
      headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ launch_token: TEST_TOKEN }),
    }))
    await expect(first).resolves.toBeUndefined()
    await api.bootstrapOperatorSession()
    expect(fetch).toHaveBeenCalledOnce()
    expect(storage).not.toHaveBeenCalled()
    expect(document.body.textContent).not.toContain(TEST_TOKEN)
  })

  it('does not exchange without a fragment and lets the server validate the existing cookie', async () => {
    window.history.replaceState(null, '', '/?settings=models#records')
    const { api } = await import('./api')
    await api.bootstrapOperatorSession()
    expect(fetch).not.toHaveBeenCalled()
    expect(window.location.hash).toBe('#records')
    vi.mocked(fetch).mockResolvedValue(new Response(JSON.stringify({ reason_code: 'OPERATOR_SESSION_REQUIRED' }), { status: 401 }))
    await expect(api.tasks()).rejects.toMatchObject({ status: 401, reasonCode: 'OPERATOR_SESSION_REQUIRED' })
    expect(vi.mocked(fetch).mock.calls[0][1]?.credentials).toBe('same-origin')
  })

  it.each(['', 'bad-token', 'a'.repeat(63), 'A'.repeat(64), `${TEST_TOKEN}&launch_token=${TEST_TOKEN}`])(
    'rejects malformed or duplicate fragment tokens without making a request: %s', async (value) => {
      window.history.replaceState(null, '', `/?settings=models#launch_token=${value}`)
      const { api } = await import('./api')
      await expect(api.bootstrapOperatorSession()).rejects.toMatchObject({ reasonCode: 'OPERATOR_SESSION_REQUIRED' })
      expect(window.location.hash).toBe('')
      expect(window.location.search).toBe('?settings=models')
      expect(fetch).not.toHaveBeenCalled()
    },
  )

  it.each([false, 'true', 1, null, undefined])('requires an explicit authenticated true result: %j', async (authenticated) => {
    vi.mocked(fetch).mockResolvedValue(new Response(JSON.stringify({ authenticated })))
    window.history.replaceState(null, '', `/#launch_token=${TEST_TOKEN}`)
    const { api } = await import('./api')
    await expect(api.bootstrapOperatorSession()).rejects.toMatchObject({ reasonCode: 'OPERATOR_SESSION_REQUIRED' })
    expect(window.location.hash).toBe('')
  })

  it('sanitizes failed exchanges and does not retry an already consumed fragment', async () => {
    vi.mocked(fetch).mockResolvedValue(new Response(JSON.stringify({ message: TEST_TOKEN }), { status: 401 }))
    window.history.replaceState(null, '', `/#launch_token=${TEST_TOKEN}`)
    const { api, OPERATOR_START_MESSAGE } = await import('./api')
    await expect(api.bootstrapOperatorSession()).rejects.toThrow(OPERATOR_START_MESSAGE)
    await expect(api.bootstrapOperatorSession()).rejects.not.toThrow(TEST_TOKEN)
    expect(fetch).toHaveBeenCalledOnce()
  })

  it('fails closed on transport failure without exposing request contents', async () => {
    vi.mocked(fetch).mockRejectedValue(new Error(TEST_TOKEN))
    window.history.replaceState(null, '', `/#launch_token=${TEST_TOKEN}`)
    const { api, OPERATOR_START_MESSAGE } = await import('./api')
    await expect(api.bootstrapOperatorSession()).rejects.toThrow(OPERATOR_START_MESSAGE)
    expect(window.location.hash).toBe('')
  })
})
