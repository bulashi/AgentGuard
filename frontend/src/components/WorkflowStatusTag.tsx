import type { WorkflowEvent } from '../types'
import { workflowEventState, workflowStatus } from '../workflowModel'
import { StatusTag } from './Evidence'

export function WorkflowStatusTag({ state, reasonCode }: { state: string | null | undefined; reasonCode?: string | null }) {
  return <StatusTag {...workflowStatus(state, reasonCode)} />
}

export function WorkflowEventStatusTag({ event }: { event: WorkflowEvent }) {
  const state = workflowEventState(event)
  if (state === 'stopped') return <StatusTag value="BUSINESS_STOPPED" label="停止后续办理" />
  if (state === 'unknown') return <StatusTag value="UNKNOWN" label="结果未确认" />
  return <StatusTag value={event.status} />
}
