import type { ExecutionView, TaskSnapshot, WorkflowEvent, WorkflowRun } from './types'

export interface RequestEvidence {
  key: string
  runId: string | null
  request: WorkflowEvent | null
  decisionEvent: WorkflowEvent | null
  execution: ExecutionView | null
  association: 'request_hash' | 'legacy_sequence' | 'execution_only' | 'unlinked'
  tool: string
  agentId: string | null
}

export function publicObject(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : {}
}

function executionMatches(request: WorkflowEvent, execution: ExecutionView): boolean {
  const details = request.details
  return execution.tool_name === details.tool && execution.parameter_hash === details.parameter_hash
    && (typeof details.tool_service !== 'string' || execution.tool_service === details.tool_service)
    && (typeof details.tool_version !== 'string' || execution.tool_version === details.tool_version)
    && (typeof details.credential_chain_hash !== 'string' || execution.credential_chain_hash === details.credential_chain_hash)
}

export function requestEvidenceForRun(
  snapshot: TaskSnapshot | null, run: WorkflowRun | null, events: WorkflowEvent[], includeUnobserved = true,
): RequestEvidence[] {
  const ordered = [...events].sort((a, b) => a.sequence - b.sequence)
  const executions = snapshot?.executions ?? []
  const observableIds = new Set(ordered.filter((event) => ['gateway_decision', 'call_tool'].includes(event.action))
    .map((event) => event.details.execution_id).filter((value): value is string => typeof value === 'string'))
  const observableExecutions = executions.filter((execution) => includeUnobserved || observableIds.has(execution.execution_id))
  const values: RequestEvidence[] = []
  const linked = new Set<string>()
  for (let index = 0; index < ordered.length; index += 1) {
    const request = ordered[index]
    if (request.action !== 'gateway_request') continue
    const following = ordered.slice(index + 1)
    const nextRequest = following.find((event) => event.agent_id === request.agent_id && event.action === 'gateway_request')
    const decisionEvent = following.find((event) => event.agent_id === request.agent_id && event.action === 'gateway_decision'
      && event.details.tool === request.details.tool && (!nextRequest || event.sequence < nextRequest.sequence)
      && (typeof request.details.request_id !== 'string' || event.details.request_id === request.details.request_id)) ?? null
    const requestHash = request.details.request_hash
    const candidates = typeof requestHash === 'string'
      ? observableExecutions.filter((execution) => execution.request_hash === requestHash && executionMatches(request, execution))
      : observableExecutions.filter((execution) => execution.execution_id === decisionEvent?.details.execution_id && executionMatches(request, execution))
    // A tool name alone cannot link repeated calls. Old observations use a marked sequence association.
    const execution = candidates.length === 1 ? candidates[0] : null
    if (execution) linked.add(execution.execution_id)
    values.push({
      key: `${run?.run_id ?? 'unrecorded'}:${request.sequence}`, runId: run?.run_id ?? null,
      request, decisionEvent, execution,
      association: execution ? typeof requestHash === 'string' ? 'request_hash' : 'legacy_sequence' : 'unlinked',
      tool: typeof request.details.tool === 'string' ? request.details.tool : '未记录工具', agentId: request.agent_id,
    })
  }
  for (const execution of observableExecutions) {
    if (linked.has(execution.execution_id)) continue
    const decisionEvent = ordered.find((event) => event.action === 'gateway_decision' && event.details.execution_id === execution.execution_id) ?? null
    values.push({ key: execution.execution_id, runId: decisionEvent ? run?.run_id ?? null : null, request: null, decisionEvent,
      execution, association: 'execution_only', tool: execution.tool_name, agentId: decisionEvent?.agent_id ?? null })
  }
  return values
}

export function observationForExecution(snapshot: TaskSnapshot | null, executionId: string): RequestEvidence | null {
  const values = (snapshot?.workflow_runs ?? []).flatMap((run) => requestEvidenceForRun(snapshot, run, run.events, false))
    .filter((value) => value.execution?.execution_id === executionId && value.request)
  return values.length === 1 ? values[0] : null
}
