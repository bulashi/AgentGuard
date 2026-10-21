import { useEffect } from 'react'
import type { Overview } from './types'

/** Stable while refresh remains required, independent of ordinary task polling. */
export function useAuditRefresh(required: boolean, read: () => Promise<Overview>, apply?: (next: Overview) => void) {
  useEffect(() => {
    if (!required) return
    let active = true
    let timer = 0
    const poll = async () => {
      try {
        const next = await read()
        if (active) apply?.(next)
      } catch {
        // The caller keeps the prior report and its pending-verification state.
      } finally {
        if (active) timer = window.setTimeout(() => void poll(), 1500)
      }
    }
    timer = window.setTimeout(() => void poll(), 1500)
    return () => { active = false; window.clearTimeout(timer) }
  }, [apply, read, required])
}
