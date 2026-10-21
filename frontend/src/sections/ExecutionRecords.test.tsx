import { fireEvent, render, screen, within } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { ExecutionRecords } from './ExecutionRecords'
import { savedSnapshot, workflowSnapshot } from '../test/fixtures'

describe('ExecutionRecords', () => {
  it('searches persisted execution records and preserves an empty result', () => {
    render(<ExecutionRecords snapshot={workflowSnapshot} onInspect={vi.fn()} />)
    fireEvent.change(screen.getByRole('textbox', { name: '搜索执行记录' }), { target: { value: 'refund.create' } })
    expect(within(screen.getByRole('table')).getByText('refund.create')).toBeInTheDocument()
    fireEvent.change(screen.getByRole('textbox', { name: '搜索执行记录' }), { target: { value: 'missing-record' } })
    expect(screen.getByText('暂无匹配执行记录')).toBeInTheDocument()
  })
  it('opens the exact execution object and retains the request comparison entry', () => {
    const inspect = vi.fn()
    render(<ExecutionRecords snapshot={savedSnapshot} onInspect={inspect} />)
    fireEvent.click(screen.getByRole('button', { name: '查看执行 execution-denied' }))
    expect(inspect).toHaveBeenCalledWith({ kind: 'execution', execution: savedSnapshot.executions[0] })
    expect(screen.getByText('单笔请求与授权范围')).toBeInTheDocument()
    expect(within(screen.getByRole('table')).getByText('无副作用')).toBeInTheDocument()
  })
})
