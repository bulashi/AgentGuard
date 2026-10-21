import names from '../customerDisplayNames.json'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { App as AntApp } from 'antd'
import { useState } from 'react'
import { describe, expect, it, vi } from 'vitest'
import { api, ApiError } from '../api'
import { TaskCenter } from './TaskCenter'
import type { TaskSummary } from '../types'

const task: TaskSummary = {
  task_id: 'TASK-test-table-binding',
  tenant_id: 'tenant-A',
  ticket_id: 'T10086',
  customer_id: 'C9527',
  refund_total_fen: 7000,
  max_tool_calls: 4,
  expires_at: 1_790_709_439,
  status: 'AUTHORIZED',
  created_at: 1_790_707_639,
  updated_at: 1_790_707_639,
  credential_count: 4,
  execution_count: 4,
}

describe('TaskCenter', () => {
  it('creates original business facts first, selects the new ticket, and leaves authorization as a separate action', async () => {
    const facts = { schema_version: '1.0' as const, order: { order_id: 'O-created', amount_fen: 7000, currency: 'CNY' as const }, claim_text: '请核对订单支付',
      payments: [{ transaction_id: 'P-created', amount_fen: 7000, status: 'SUCCESS' as const, refunded_amount_fen: 0 }] }
    const tickets = vi.spyOn(api, 'businessTickets').mockResolvedValue({ items: [] })
    const createCase = vi.spyOn(api, 'createBusinessCase').mockResolvedValue({ tenant_id: 'tenant-A', customer_id: 'customer-A', ticket_id: 'T-created', facts_hash: 'hash-created', business_facts: facts })
    const createTask = vi.spyOn(api, 'createTask')
    try {
      render(<AntApp><TaskCenter businessMode tasks={[task]} selectedTaskId={task.task_id}
        onSelect={vi.fn()} onChanged={vi.fn()} onDemo={vi.fn()} /></AntApp>)
      fireEvent.click(screen.getByRole('button', { name: '新建任务' }))
      await waitFor(() => expect(screen.getByRole('button', { name: '新建业务工单' })).toBeEnabled())
      fireEvent.click(screen.getByRole('button', { name: '新建业务工单' }))
      await waitFor(() => expect(screen.getByLabelText('业务租户')).toHaveValue('tenant-A'))
      fireEvent.change(screen.getByLabelText('客户申诉'), { target: { value: facts.claim_text } })
      fireEvent.click(screen.getByRole('button', { name: '保存业务工单' }))
      await waitFor(() => expect(screen.getByLabelText('工单编号')).toHaveValue('T-created'))
      expect(screen.getByLabelText('客户')).toHaveValue('customer-A')
      expect(screen.getByRole('region', { name: '当前工单业务资格' })).toHaveTextContent('待运行核验')
      expect(screen.getByRole('region', { name: '当前工单业务资格' })).toHaveTextContent('P-created')
      expect(screen.getByRole('button', { name: '复制为新案例' })).toBeInTheDocument()
      expect(createTask).not.toHaveBeenCalled()
      expect(createCase).toHaveBeenCalledOnce()
    } finally { tickets.mockRestore(); createCase.mockRestore(); createTask.mockRestore() }
  })
  it('prefers an unprocessed verified ticket and displays trusted remaining funds', async () => {
    const available = { tenant_id: '企业乙', ticket_id: 'T20001', customer_id: '客户乙', title: '重复扣款',
      verification_status: 'VERIFIED' as const, payment_verification_status: 'VERIFIED' as const,
      original_transaction_id: 'transaction-new', refundable_amount_fen: 7000, transaction_remaining_fen: 9000,
      evidence_reference: 'verification-new', can_refund: true, already_processed: false, in_progress: false }
    const tickets = vi.spyOn(api, 'businessTickets').mockResolvedValue({ items: [
      { ...available, ticket_id: 'T10086', already_processed: true, can_refund: false }, available,
    ] })
    try {
      render(<AntApp><TaskCenter businessMode tasks={[task]} selectedTaskId={task.task_id}
        onSelect={vi.fn()} onChanged={vi.fn()} onDemo={vi.fn()} /></AntApp>)
      fireEvent.click(screen.getByRole('button', { name: '新建任务' }))
      await waitFor(() => expect(screen.getByLabelText('工单编号')).toHaveValue('T20001'))
      expect(screen.getByLabelText('租户')).toHaveValue('企业乙')
      expect(screen.getByLabelText('客户')).toHaveValue('客户乙')
      expect(screen.getByRole('region', { name: '当前工单业务资格' })).toHaveTextContent('可办理')
      expect(screen.getByRole('region', { name: '当前工单业务资格' })).toHaveTextContent('90.00')
      expect(screen.getByRole('region', { name: '当前工单业务资格' })).toHaveTextContent('verification-new')
    } finally { tickets.mockRestore() }
  })
  it('clears the selected business ticket and its dependent fields together', async () => {
    const available = { tenant_id: '企业乙', ticket_id: 'T20001', customer_id: '客户乙', title: '重复扣款',
      verification_status: 'VERIFIED' as const, payment_verification_status: 'VERIFIED' as const,
      original_transaction_id: 'transaction-new', refundable_amount_fen: 7000, transaction_remaining_fen: 9000,
      evidence_reference: 'verification-new', can_refund: true, already_processed: false, in_progress: false }
    const tickets = vi.spyOn(api, 'businessTickets').mockResolvedValue({ items: [available] })
    try {
      render(<AntApp><TaskCenter businessMode tasks={[task]} selectedTaskId={task.task_id}
        onSelect={vi.fn()} onChanged={vi.fn()} onDemo={vi.fn()} /></AntApp>)
      fireEvent.click(screen.getByRole('button', { name: '新建任务' }))
      await waitFor(() => expect(screen.getByLabelText('工单编号')).toHaveValue('T20001'))
      const clear = document.querySelector('.ant-modal .ant-select-clear')
      expect(clear).toBeTruthy()
      fireEvent.mouseDown(clear!)
      fireEvent.click(clear!)
      await waitFor(() => {
        expect(screen.getByLabelText('租户')).toHaveValue('')
        expect(screen.getByLabelText('工单编号')).toHaveValue('')
        expect(screen.getByLabelText('客户')).toHaveValue('')
      })
      expect(screen.queryByRole('region', { name: '当前工单业务资格' })).not.toBeInTheDocument()
    } finally { tickets.mockRestore() }
  })
  it('submits Chinese tenant and customer unchanged', async () => {
    const tickets = vi.spyOn(api, 'businessTickets').mockResolvedValue({ items: [] })
    const create = vi.spyOn(api, 'createTask').mockResolvedValue({ task_id: 'TASK-new', status: 'PENDING_AUTHORIZATION' })
    try {
      render(<AntApp><TaskCenter businessMode tasks={[task]} selectedTaskId={task.task_id}
        onSelect={vi.fn()} onChanged={vi.fn()} onDemo={vi.fn()} /></AntApp>)
      fireEvent.click(screen.getByRole('button', { name: '新建任务' }))
      fireEvent.change(screen.getByLabelText('租户'), { target: { value: '演示企业' } })
      fireEvent.change(screen.getByLabelText('客户'), { target: { value: '张三' } })
      fireEvent.change(screen.getByLabelText('工单编号'), { target: { value: 'T10088' } })
      fireEvent.click(screen.getByRole('button', { name: /创建待授权任务/ }))
      await waitFor(() => expect(create).toHaveBeenCalledWith({
        tenant_id: '演示企业', customer_id: '张三', ticket_id: 'T10088',
        refund_total_fen: 7000, max_tool_calls: 4, expires_in_seconds: 1800,
      }))
    } finally { tickets.mockRestore(); create.mockRestore() }
  })
  it('shows server validation against the actual form field', async () => {
    const tickets = vi.spyOn(api, 'businessTickets').mockResolvedValue({ items: [] })
    const create = vi.spyOn(api, 'createTask').mockRejectedValue(new ApiError(422, 'REQUEST_SCHEMA_INVALID', '请检查任务字段', { customer_id: '客户与业务记录不符' }))
    try {
      render(<AntApp><TaskCenter businessMode tasks={[task]} selectedTaskId={task.task_id}
        onSelect={vi.fn()} onChanged={vi.fn()} onDemo={vi.fn()} /></AntApp>)
      fireEvent.click(screen.getByRole('button', { name: '新建任务' }))
      fireEvent.change(screen.getByLabelText('租户'), { target: { value: 'tenant-A' } })
      fireEvent.change(screen.getByLabelText('客户'), { target: { value: 'C9527' } })
      fireEvent.change(screen.getByLabelText('工单编号'), { target: { value: 'T10086' } })
      fireEvent.click(screen.getByRole('button', { name: /创建待授权任务/ }))
      expect(await screen.findByText('客户与业务记录不符')).toBeInTheDocument()
      expect(screen.queryByText('HTTP_ERROR: HTTP 422')).not.toBeInTheDocument()
    } finally { tickets.mockRestore(); create.mockRestore() }
  })
  it('keeps a created task selected when the follow-up list refresh fails', async () => {
    const tickets = vi.spyOn(api, 'businessTickets').mockResolvedValue({ items: [] })
    const create = vi.spyOn(api, 'createTask').mockResolvedValue({ task_id: 'TASK-new', status: 'PENDING_AUTHORIZATION' })
    const onSelect = vi.fn()
    const onChanged = vi.fn().mockRejectedValue(new ApiError(408, 'UI_READ_TIMEOUT', '任务列表读取超时'))
    try {
      render(<AntApp><TaskCenter businessMode tasks={[task]} selectedTaskId={task.task_id}
        onSelect={onSelect} onChanged={onChanged} onDemo={vi.fn()} /></AntApp>)
      fireEvent.click(screen.getByRole('button', { name: '新建任务' }))
      fireEvent.change(screen.getByLabelText('租户'), { target: { value: '演示企业' } })
      fireEvent.change(screen.getByLabelText('客户'), { target: { value: '张三' } })
      fireEvent.change(screen.getByLabelText('工单编号'), { target: { value: 'T10088' } })
      fireEvent.click(screen.getByRole('button', { name: /创建待授权任务/ }))
      expect(await screen.findByText('任务 TASK-new 已创建，但任务列表刷新失败；请刷新任务列表查看，暂不要重复创建')).toBeInTheDocument()
      expect(create).toHaveBeenCalledOnce()
      expect(onSelect).toHaveBeenCalledWith('TASK-new')
      expect(onChanged).toHaveBeenCalledWith('TASK-new')
      expect(screen.queryByRole('button', { name: /创建待授权任务/ })).not.toBeInTheDocument()
    } finally { tickets.mockRestore(); create.mockRestore() }
  })
  it('exposes task commands without duplicating the evidence flow in the business workspace', () => {
    const inspect = vi.fn()
    render(<AntApp><TaskCenter businessMode tasks={[task]} selectedTaskId={task.task_id}
      onSelect={vi.fn()} onChanged={vi.fn()} onDemo={vi.fn()} onInspect={inspect} /></AntApp>)
    fireEvent.click(screen.getByRole('button', { name: '查看当前任务约束' }))
    expect(inspect).toHaveBeenCalledWith({ kind: 'task' })
    expect(screen.getByRole('combobox', { name: '切换当前任务' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '新建任务' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '运行当前任务' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '另建标准任务并运行' })).not.toBeInTheDocument()
  })

  it('opens approval for a pending task without invoking single-sign authorization', () => {
    const onAuthorization = vi.fn()
    const authorize = vi.spyOn(api, 'authorizeTask')
    try {
      render(<AntApp><TaskCenter businessMode tasks={[{ ...task, status: 'PENDING_AUTHORIZATION', execution_count: 0 }]}
        selectedTaskId={task.task_id} onSelect={vi.fn()} onChanged={vi.fn()} onDemo={vi.fn()}
        onAuthorization={onAuthorization} /></AntApp>)
      fireEvent.click(screen.getByRole('button', { name: '打开当前任务授权' }))
      expect(onAuthorization).toHaveBeenCalledOnce()
      expect(authorize).not.toHaveBeenCalled()
      expect(screen.queryByRole('button', { name: '确认当前任务授权' })).not.toBeInTheDocument()
    } finally { authorize.mockRestore() }
  })

  it('does not report a denied demo response as completed', async () => {
    const normalDemo = vi.spyOn(api, 'normalDemo').mockResolvedValue({
      demo_kind: 'NORMAL', task_id: task.task_id, planner: 'deterministic',
      status: 'DENIED', reason_code: 'PARAMETER_CONSTRAINT_VIOLATION', trace: [],
    })
    try {
      render(<AntApp><TaskCenter tasks={[task]} selectedTaskId={task.task_id}
        onSelect={vi.fn()} onChanged={vi.fn()} onDemo={vi.fn()} /></AntApp>)
      fireEvent.click(screen.getByRole('button', { name: '另建标准任务并运行' }))
      expect(await screen.findByText('任务协作：权限拒绝；请查看执行记录')).toBeInTheDocument()
      expect(screen.queryByText('四智能体协作已完成')).not.toBeInTheDocument()
    } finally { normalDemo.mockRestore() }
  })
  it('reports a persisted queued demo as started, without calling it completed or denied', async () => {
    const demo = vi.spyOn(api, 'normalDemo').mockResolvedValue({ demo_kind: 'NORMAL', task_id: task.task_id,
      planner: 'deterministic', status: 'QUEUED', reason_code: null, trace: [] })
    try {
      render(<AntApp><TaskCenter tasks={[task]} selectedTaskId={task.task_id}
        onSelect={vi.fn()} onChanged={vi.fn()} onDemo={vi.fn()} /></AntApp>)
      fireEvent.click(screen.getByRole('button', { name: '另建标准任务并运行' }))
      expect(await screen.findByText('任务已启动，请查看协作流程')).toBeInTheDocument()
      expect(screen.queryByText('四智能体协作已完成')).not.toBeInTheDocument()
      expect(screen.queryByText(/任务协作：QUEUED/)).not.toBeInTheDocument()
    } finally { demo.mockRestore() }
  })
  it('renders task records from the BFF projection', () => {
    render(
      <AntApp>
        <TaskCenter
          tasks={[task]}
          selectedTaskId={task.task_id}
          onSelect={vi.fn()}
          onChanged={vi.fn()}
          onDemo={vi.fn()}
        />
      </AntApp>,
    )

    expect(screen.getByText('T10086 / C9527 · 根授权已签发 · binding')).toBeInTheDocument()
    expect(screen.getByRole('combobox', { name: '切换当前任务' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '另建标准任务并运行' })).toBeInTheDocument()
  })

  it('keeps completion messages mounted when the demo switches views', async () => {
    const normalDemo = vi.spyOn(api, 'normalDemo').mockResolvedValue({
      demo_kind: 'NORMAL', task_id: task.task_id, planner: 'deterministic',
      status: 'COMPLETED', reason_code: null, trace: [],
    })
    function DemoHarness() {
      const [visible, setVisible] = useState(true)
      return (
        <AntApp>
          {visible ? <TaskCenter tasks={[task]} selectedTaskId={task.task_id}
            onSelect={vi.fn()} onChanged={vi.fn()}
            onDemo={async () => { setVisible(false) }} /> : <span>Execution</span>}
        </AntApp>
      )
    }
    try {
      render(<DemoHarness />)
      fireEvent.click(screen.getByRole('button', { name: '另建标准任务并运行' }))
      expect(await screen.findByText('Execution')).toBeInTheDocument()
      expect(await screen.findByText('四智能体协作已完成')).toBeInTheDocument()
    } finally {
      normalDemo.mockRestore()
    }
  })
  it('submits decimal yuan as exact fen while retaining the customer identifier behind its display alias', async () => {
    const [customerId, alias] = Object.entries(names)[0]
    const available = { tenant_id: 'tenant-A', ticket_id: 'T-new-yuan', customer_id: customerId, title: '重复扣款',
      verification_status: 'VERIFIED' as const, payment_verification_status: 'VERIFIED' as const,
      original_transaction_id: 'PAY-yuan', refundable_amount_fen: 7000, transaction_remaining_fen: 9000,
      can_refund: true, already_processed: false, in_progress: false }
    const tickets = vi.spyOn(api, 'businessTickets').mockResolvedValue({ items: [available] })
    const create = vi.spyOn(api, 'createTask').mockResolvedValue({ task_id: 'TASK-yuan', status: 'PENDING_AUTHORIZATION' })
    try {
      render(<AntApp><TaskCenter businessMode tasks={[task]} selectedTaskId={task.task_id}
        onSelect={vi.fn()} onChanged={vi.fn()} onDemo={vi.fn()} /></AntApp>)
      fireEvent.click(screen.getByRole('button', { name: '新建任务' }))
      await waitFor(() => expect(screen.getByLabelText('客户')).toHaveValue(alias))
      expect(screen.getByLabelText('客户')).toHaveAttribute('title', customerId)
      fireEvent.change(screen.getByLabelText('退款预算（元）'), { target: { value: '1.23' } })
      fireEvent.click(screen.getByRole('button', { name: /创建待授权任务/ }))
      await waitFor(() => expect(create).toHaveBeenCalledWith({ tenant_id: 'tenant-A', ticket_id: 'T-new-yuan',
        customer_id: customerId, refund_total_fen: 123, max_tool_calls: 4, expires_in_seconds: 1800 }))
    } finally { tickets.mockRestore(); create.mockRestore() }
  })

})
