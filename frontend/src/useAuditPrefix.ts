import { useEffect, useState } from 'react'
import { api } from './api'
import { auditEventCore, auditPrefixObservation, parseAuditPrefixReport } from './auditPrefixBinding'
import type { AuditEventCore, AuditPrefixReport } from './auditPrefixBinding'
import type { AuditEventView, TaskSnapshot } from './types'

type PrefixReader = (taskId: string, events: AuditEventCore[], signal?: AbortSignal) => Promise<unknown>
type Observation = { report: AuditPrefixReport | null; error: string | null; loading: boolean; observedAt?: number }
const EMPTY: Observation = { report: null, error: null, loading: false }

export function useAuditPrefix(snapshot: TaskSnapshot | null, focus: AuditEventView | null = null, read: PrefixReader = api.auditPrefix): Observation {
  const taskId = snapshot?.task.task_id
  const events = snapshot?.audit_events ?? []
  const focused = focus && events.filter((event) => event.event_id === focus.event_id && event.event_sequence === focus.event_sequence)
  const priority = focused?.length === 1 ? focused[0] : null
  const recent = events.filter((event) => event !== priority).slice(priority ? -99 : -100)
  const selected = priority ? [...recent, priority] : recent
  const key = taskId && selected.length ? JSON.stringify({ taskId, events: selected.map(auditEventCore) }) : ''
  const [observation, setObservation] = useState<(Observation & { key: string }) | null>(null)

  useEffect(() => {
    if (!key) return
    const batch = JSON.parse(key) as { taskId: string; events: AuditEventCore[] }
    let active = true
    let timer = 0
    const controller = new AbortController()
    setObservation({ key, report: null, error: null, loading: true })
    const poll = async () => {
      let interval = 3000
      try {
        const report = parseAuditPrefixReport(await read(batch.taskId, batch.events, controller.signal))
        if (!report || report.task_id !== batch.taskId || report.event_bindings.length !== batch.events.length
          || report.event_bindings.some((binding, index) => {
            const event = batch.events[index]
            const verified = binding.verified_event
            const matched = verified !== null && (Object.keys(event) as Array<keyof AuditEventCore>)
              .every((field) => verified[field] === event[field])
            return binding.event_sequence !== event.event_sequence || binding.event_id !== event.event_id
              || binding.event_hash !== event.event_hash || binding.matched !== matched
          })) throw new Error('audit prefix response batch mismatch')
        if (!active) return
        setObservation({ key, report, error: null, loading: false, observedAt: Date.now() / 1000 })
        const complete = batch.events.every((core) => auditPrefixObservation(batch.taskId, {
          ...core, coauthorization_evidence: null, evidence_binding_valid: null,
        }, report).status === 'ANCHORED')
        if (complete) interval = 10000
      } catch {
        if (active) setObservation({ key, report: null, error: '逐事件核验暂不可用，未使用旧报告替代', loading: false })
      } finally {
        if (active) timer = window.setTimeout(() => void poll(), interval)
      }
    }
    void poll()
    return () => { active = false; window.clearTimeout(timer); controller.abort() }
  }, [key, read])

  return observation?.key === key ? observation : key ? { ...EMPTY, loading: true } : EMPTY
}
