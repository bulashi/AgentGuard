import { act, renderHook } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { auditPrefixObservation } from './auditPrefixBinding'
import { useAuditPrefix } from './useAuditPrefix'
import { savedSnapshot } from './test/fixtures'
import { mockAuditPrefixReport } from './test/auditPrefixFixtures'
import type { TaskSnapshot } from './types'

const event = savedSnapshot.audit_events[0]
const mockReport = mockAuditPrefixReport(event)

afterEach(() => { vi.useRealTimers() })

describe('exact audit-prefix report refresh with mocked transport', () => {
  it('does not restart the scheduled read when only unrelated snapshot state changes', async () => {
    vi.useFakeTimers()
    const read = vi.fn().mockResolvedValue(mockReport)
    const { result, rerender, unmount } = renderHook(({ snapshot }) => useAuditPrefix(snapshot, null, read), {
      initialProps: { snapshot: savedSnapshot },
    })
    await act(async () => { await Promise.resolve() })
    expect(auditPrefixObservation(savedSnapshot.task.task_id, event, result.current.report).status).toBe('ANCHORED')
    for (let version = 1; version <= 4; version += 1) {
      rerender({ snapshot: { ...savedSnapshot, task: { ...savedSnapshot.task, updated_at: version } } })
      await act(async () => { await vi.advanceTimersByTimeAsync(2500) })
    }
    expect(read).toHaveBeenCalledTimes(2)
    unmount()
  })

  it('clears a prior positive report on a failed reread and keeps retrying', async () => {
    vi.useFakeTimers()
    const read = vi.fn().mockResolvedValueOnce(mockReport).mockRejectedValueOnce(new Error('unavailable')).mockResolvedValue(mockReport)
    const { result, unmount } = renderHook(() => useAuditPrefix(savedSnapshot, null, read))
    await act(async () => { await Promise.resolve() })
    expect(result.current.report).not.toBeNull()
    await act(async () => { await vi.advanceTimersByTimeAsync(10000) })
    expect(result.current.report).toBeNull()
    expect(result.current.error).not.toBeNull()
    await act(async () => { await vi.advanceTimersByTimeAsync(3000) })
    expect(read).toHaveBeenCalledTimes(3)
    expect(result.current.report).not.toBeNull()
    unmount()
  })

  it('does not apply an old-task in-flight result after switching the task', async () => {
    let finish: (value: unknown) => void = () => { throw new Error('read not started') }
    const next = { ...savedSnapshot, task: { ...savedSnapshot.task, task_id: 'TASK-other' } }
    const read = vi.fn().mockImplementationOnce(() => new Promise((resolve) => { finish = resolve }))
      .mockResolvedValue(mockAuditPrefixReport(event, next.task.task_id))
    const { result, rerender, unmount } = renderHook(({ snapshot }) => useAuditPrefix(snapshot, null, read), {
      initialProps: { snapshot: savedSnapshot },
    })
    const previousSignal = read.mock.calls[0][2] as AbortSignal
    rerender({ snapshot: next })
    expect(previousSignal.aborted).toBe(true)
    await act(async () => { await Promise.resolve() })
    await act(async () => { finish(mockReport); await Promise.resolve() })
    expect(result.current.report?.task_id).toBe(next.task.task_id)
    const currentSignal = read.mock.calls[1][2] as AbortSignal
    unmount()
    expect(currentSignal.aborted).toBe(true)
  })

  it('rejects a stale positive report whose same-ID event timestamp changed', async () => {
    const changed = { ...event, timestamp: event.timestamp + 2 }
    const snapshot = { ...savedSnapshot, audit_events: [changed] }
    const read = vi.fn().mockResolvedValue(mockReport)
    const { result, unmount } = renderHook(() => useAuditPrefix(snapshot, null, read))
    await act(async () => { await Promise.resolve() })
    expect(result.current.report).toBeNull()
    expect(result.current.error).not.toBeNull()
    unmount()
  })

  it('caps the batch and prioritizes an explicitly opened older event', async () => {
    const events = Array.from({ length: 130 }, (_, index) => ({
      ...event, event_sequence: index + 1, event_id: `EVENT-${index + 1}`,
    }))
    const snapshot: TaskSnapshot = { ...savedSnapshot, audit_events: events }
    const read = vi.fn().mockRejectedValue(new Error('mock transport'))
    const { unmount } = renderHook(() => useAuditPrefix(snapshot, events[0], read))
    await act(async () => { await Promise.resolve() })
    const batch = read.mock.calls[0][1]
    expect(batch).toHaveLength(100)
    expect(batch[99].event_id).toBe('EVENT-1')
    expect(new Set(batch.map((selected: { event_id: string }) => selected.event_id)).size).toBe(100)
    expect(batch[0]).not.toHaveProperty('coauthorization_evidence')
    unmount()
  })

  it('does not request or retain coverage for an empty task projection', async () => {
    const read = vi.fn()
    const { result, unmount } = renderHook(() => useAuditPrefix({ ...savedSnapshot, audit_events: [] }, null, read))
    await act(async () => { await Promise.resolve() })
    expect(read).not.toHaveBeenCalled()
    expect(result.current.report).toBeNull()
    expect(result.current.loading).toBe(false)
    unmount()
  })
})
