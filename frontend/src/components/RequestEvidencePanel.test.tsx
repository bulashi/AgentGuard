import { fireEvent, render, screen, within } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { savedSnapshot, workflowSnapshot } from '../test/fixtures'
import type { TaskSnapshot } from '../types'
import { RequestEvidencePanel } from './RequestEvidencePanel'

function linkedSnapshot(): TaskSnapshot {
  const execution = workflowSnapshot.executions[0]
  const run = workflowSnapshot.workflow_runs![0]
  return {
    ...workflowSnapshot,
    workflow_runs: [{ ...run, events: run.events.map((event) => event.action === 'gateway_request' ? {
      ...event, details: { ...event.details, request_hash: execution.request_hash, parameter_hash: execution.parameter_hash,
        credential_chain_hash: execution.credential_chain_hash, tool_service: execution.tool_service, tool_version: execution.tool_version },
    } : event) }],
  }
}

describe('RequestEvidencePanel', () => {
  it('does not invent missing parameters for an old execution record', () => {
    render(<RequestEvidencePanel snapshot={savedSnapshot} run={null} events={[]} replay={false} onInspect={vi.fn()} />)
    const panel = screen.getByTestId('request-evidence-panel')
    expect(within(panel).getByText('此记录没有保存原始参数，不补造历史输入')).toBeInTheDocument()
    expect(within(panel).getByText('仅执行记录')).toBeInTheDocument()
    expect(within(panel).getByText('网关拒绝')).toBeInTheDocument()
    expect(within(panel).queryByRole('table')).not.toBeInTheDocument()
  })

  it('opens the execution and receipt actually linked by request hash', () => {
    const inspect = vi.fn()
    const snapshot = linkedSnapshot()
    const run = snapshot.workflow_runs![0]
    render(<RequestEvidencePanel snapshot={snapshot} run={run} events={run.events} replay={false} onInspect={inspect} />)
    const panel = screen.getByTestId('request-evidence-panel')
    expect(within(panel).getByText('请求摘要关联')).toBeInTheDocument()
    expect(within(panel).getByText('网关允许')).toBeInTheDocument()
    expect(within(panel).getByText('1 笔退款记录')).toBeInTheDocument()
    fireEvent.click(within(panel).getByRole('button', { name: '打开关联详情' }))
    expect(inspect).toHaveBeenLastCalledWith({ kind: 'execution', execution: snapshot.executions[0] })
    fireEvent.click(within(panel).getByRole('button', { name: /回执 · 签名与绑定一致/ }))
    expect(inspect).toHaveBeenLastCalledWith({ kind: 'receipt', receipt: snapshot.receipts[0] })
  })

  it('does not reveal a future execution or effect before its replay event', () => {
    const snapshot = linkedSnapshot()
    const run = snapshot.workflow_runs![0]
    render(<RequestEvidencePanel snapshot={snapshot} run={run} events={run.events.filter((event) => event.sequence <= 12)} replay onInspect={vi.fn()} />)
    const panel = screen.getByTestId('request-evidence-panel')
    expect(within(panel).getByText('尚无唯一执行关联')).toBeInTheDocument()
    expect(within(panel).getByText('无已关联裁决')).toBeInTheDocument()
    expect(within(panel).queryByText('网关允许')).not.toBeInTheDocument()
    expect(within(panel).queryByText('1 笔退款记录')).not.toBeInTheDocument()
    expect(within(panel).queryByRole('button', { name: /回执 · 签名与绑定一致/ })).not.toBeInTheDocument()
  })
})
