import { act, renderHook } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { Overview } from './types'
import { useAuditRefresh } from './useAuditRefresh'

const report = { audit: { verification: { latest_event_sequence: 10 } } } as Overview

afterEach(() => { vi.useRealTimers() })

describe('audit report refresh scheduling', () => {
  it('is not starved by faster snapshot rerenders while refresh is still required', async () => {
    vi.useFakeTimers()
    const read = vi.fn().mockResolvedValue(report)
    const apply = vi.fn()
    const { rerender, unmount } = renderHook(({ required }: { required: boolean; snapshotVersion: number }) => useAuditRefresh(required, read, apply), {
      initialProps: { required: true, snapshotVersion: 0 },
    })
    for (let version = 1; version <= 3; version += 1) {
      await act(async () => { await vi.advanceTimersByTimeAsync(500) })
      rerender({ required: true, snapshotVersion: version })
    }
    expect(read).toHaveBeenCalledTimes(1)
    expect(apply).toHaveBeenCalledWith(report)
    rerender({ required: false, snapshotVersion: 4 })
    await act(async () => { await vi.advanceTimersByTimeAsync(3000) })
    expect(read).toHaveBeenCalledTimes(1)
    unmount()
  })

  it('retries failed reads and does not apply an in-flight response after cleanup', async () => {
    vi.useFakeTimers()
    let finish: (value: Overview) => void = () => { throw new Error('request not started') }
    const read = vi.fn().mockRejectedValueOnce(new Error('read unavailable'))
      .mockImplementationOnce(() => new Promise<Overview>((resolve) => { finish = resolve }))
    const apply = vi.fn()
    const { unmount } = renderHook(() => useAuditRefresh(true, read, apply))
    await act(async () => { await vi.advanceTimersByTimeAsync(3000) })
    expect(read).toHaveBeenCalledTimes(2)
    unmount()
    await act(async () => { finish(report); await Promise.resolve() })
    expect(apply).not.toHaveBeenCalled()
  })
})
