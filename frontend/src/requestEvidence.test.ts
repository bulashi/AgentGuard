import { describe, expect, it } from 'vitest'
import { observationForExecution, requestEvidenceForRun } from './requestEvidence'
import { workflowSnapshot } from './test/fixtures'
import type { ExecutionView, TaskSnapshot, WorkflowEvent } from './types'

const run = workflowSnapshot.workflow_runs![0]
const execution = workflowSnapshot.executions[0]
const request: WorkflowEvent = {
  ...run.events[11], sequence: 1,
  details: { tool: execution.tool_name, tool_service: execution.tool_service, tool_version: execution.tool_version,
    request_hash: execution.request_hash, credential_chain_hash: execution.credential_chain_hash, parameter_hash: execution.parameter_hash,
    parameters: { ticket_id: 'T10086', customer_id: 'C9527', amount_fen: 7000 } },
}
const decision: WorkflowEvent = { ...run.events[12], sequence: 2 }
const snapshot = (events: WorkflowEvent[], executions: ExecutionView[] = [execution]): TaskSnapshot => ({
  ...workflowSnapshot, executions, workflow_runs: [{ ...run, events }],
})

describe('single-request evidence association', () => {
  it('requires the exact request, parameter and chain hashes for new observations', () => {
    const entries = requestEvidenceForRun(snapshot([request, decision]), run, [request, decision])
    expect(entries).toHaveLength(1)
    expect(entries[0]).toMatchObject({ execution, association: 'request_hash' })
    const changed = { ...request, details: { ...request.details, credential_chain_hash: '0'.repeat(64) } }
    expect(requestEvidenceForRun(snapshot([changed, decision]), run, [changed, decision])[0].execution).toBeNull()
  })

  it('does not associate calls merely because they use the same tool or amount', () => {
    const unrelated = { ...execution, execution_id: 'another-execution', request_hash: '1'.repeat(64) }
    const entries = requestEvidenceForRun(snapshot([request], [unrelated]), run, [request])
    expect(entries[0].association).toBe('unlinked')
    expect(entries[0].execution).toBeNull()
    expect(entries[1].association).toBe('execution_only')
  })

  it('marks old observations and requires both adjacent decision and parameter hash', () => {
    const legacy = { ...request, details: { tool: execution.tool_name, parameter_hash: execution.parameter_hash, parameters: { amount_fen: 7000 } } }
    expect(requestEvidenceForRun(snapshot([legacy, decision]), run, [legacy, decision])[0].association).toBe('legacy_sequence')
    expect(requestEvidenceForRun(snapshot([legacy]), run, [legacy])[0].execution).toBeNull()
    const missingHash = { ...legacy, details: { tool: execution.tool_name, parameters: { amount_fen: 7000 } } }
    expect(requestEvidenceForRun(snapshot([missingHash, decision]), run, [missingHash, decision])[0].execution).toBeNull()
  })

  it('does not expose future execution or side-effect state at the replay request event', () => {
    const entries = requestEvidenceForRun(snapshot([request, decision]), run, [request], false)
    expect(entries).toHaveLength(1)
    expect(entries[0].execution).toBeNull()
    expect(entries[0].decisionEvent).toBeNull()
    expect(requestEvidenceForRun(snapshot([request, decision]), run, [request, decision], false)[0].execution).toEqual(execution)
  })

  it('does not borrow a later decision across another request from the same role', () => {
    const nextRequest = { ...request, sequence: 2, details: { tool: execution.tool_name, parameter_hash: execution.parameter_hash } }
    const later = { ...decision, sequence: 3 }
    const first = { ...request, details: { tool: execution.tool_name, parameter_hash: execution.parameter_hash } }
    const entries = requestEvidenceForRun(snapshot([first, nextRequest, later]), run, [first, nextRequest, later])
    expect(entries[0].execution).toBeNull()
    expect(entries[1].association).toBe('legacy_sequence')
  })

  it('refuses an ambiguous observation shared across multiple runs', () => {
    const value = snapshot([request, decision])
    value.workflow_runs = [{ ...run, events: [request, decision] }, { ...run, run_id: 'RUN-other', events: [request, decision] }]
    expect(observationForExecution(value, execution.execution_id)).toBeNull()
  })
})
