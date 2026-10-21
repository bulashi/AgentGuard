import { act, fireEvent, render, screen, within } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { TaskOverview } from './TaskOverview'
import { savedSnapshot, workflowSnapshot } from '../test/fixtures'
import { eventTitle } from '../workflowModel'

afterEach(() => vi.useRealTimers())

function overview(snapshot = workflowSnapshot) {
  const actions = { onInspect: vi.fn(), onFlow: vi.fn(), onRecords: vi.fn(), onAuthorization: vi.fn(), onConfigure: vi.fn() }
  render(<TaskOverview snapshot={snapshot} observedAt={1790000005} controlsOpen={false} {...actions} />)
  return actions
}

describe('TaskOverview', () => {
  it('shows persisted business totals without displaying an audit or collaboration table', () => {
    overview()
    expect(screen.getByText('业务结果已提交')).toBeInTheDocument()
    expect(screen.queryByTestId('business-graph')).not.toBeInTheDocument()
    expect(screen.queryByRole('table')).not.toBeInTheDocument()
    expect(screen.getByTestId('task-overview')).toHaveTextContent('¥ 70.00')
    expect(screen.getByTestId('task-overview')).toHaveTextContent('任务授权上限')
    expect(screen.getByTestId('task-overview')).not.toHaveTextContent('不代表实际退款金额')
    expect(screen.getByTestId('task-overview')).not.toHaveTextContent('累计额度')
    expect(screen.getByText('业务结果 · 任务累计')).toBeInTheDocument()
  })
  it('labels an authorization state without implying that a refund was approved or submitted', () => {
    const snapshot = { ...savedSnapshot, workflow_runs: [], executions: [], business_effects: { refunds: [], notifications: [] } }
    overview(snapshot)
    expect(screen.getByLabelText('根授权已签发（AUTHORIZED）')).toBeInTheDocument()
    expect(screen.getByTestId('business-outcome-detail')).toHaveTextContent('尚未执行退款或通知')
  })
  it('makes the business result notice and the notification record action available before execution', () => {
    const template = { template_id: 'REFUND_SUCCESS', version: 'v1', title: '退款成功通知', content_template: '客户 {customer_id} 的退款 {refund_id} 已提交。' }
    const actions = overview({ ...savedSnapshot, business_context: { ticket: null, documents: [], notification_templates: [template] } })
    const notification = screen.getByRole('region', { name: '客户通知' })
    expect(within(notification).getByRole('heading', { name: '客户通知' })).toBeInTheDocument()
    expect(within(notification).getByRole('region', { name: '办理结果通知' })).toBeInTheDocument()
    expect(within(notification).getByLabelText('办理结果通知正文')).toHaveTextContent('本次未办理退款')
    expect(notification).toHaveTextContent('工单 T10086 · 客户 C9527')
    expect(notification).not.toHaveTextContent('固定模板 REFUND_SUCCESS · 版本 v1')
    expect(within(notification).getByText('暂无已保存通知')).toBeInTheDocument()
    expect(within(notification).queryByText('通知已发送')).not.toBeInTheDocument()
    fireEvent.click(within(notification).getByRole('button', { name: '查看通知记录' }))
    expect(actions.onInspect).toHaveBeenCalledWith({ kind: 'business', resource: 'notifications' })
  })
  it('shows the persisted notification body and refund binding after execution', () => {
    const content = '尊敬的 C9527 客户：\n退款 refund-1 已提交，金额 70.00 元。'
    overview({ ...workflowSnapshot, business_context: { ...workflowSnapshot.business_context!, notification_templates: [
      { template_id: 'REFUND_SUCCESS', version: 'v1', title: '退款成功通知', content_template: '客户 {customer_id} 的退款已提交。' }] },
      executions: [...workflowSnapshot.executions, { ...workflowSnapshot.executions[0], execution_id: 'exec-notice',
        tool_name: 'notification.send_template', business_effect_id: 'notice-1' }],
      business_effects: { ...workflowSnapshot.business_effects, notifications: [{ notification_id: 'notice-1', execution_id: 'exec-notice',
        template_id: 'REFUND_SUCCESS', template_version: 'v1', customer_id: 'C9527', content,
        related_business_effect_id: 'refund-1', status: 'SENT', created_at: 1790000002 }] } })
    const notification = screen.getByRole('region', { name: '客户通知' })
    expect(within(notification).getByLabelText('已保存通知正文').textContent).toBe(content)
    expect(notification).toHaveTextContent('客户 C9527 · 关联退款 refund-1')
    expect(within(notification).getByText('办理结果通知')).toBeInTheDocument()
    expect(within(notification).getByText('通知已发送')).toBeInTheDocument()
    expect(within(notification).queryByRole('region', { name: '办理结果通知' })).not.toBeInTheDocument()
  })
  it('does not report a rejected execution as a committed refund', () => {
    overview(savedSnapshot)
    expect(screen.getByText('请求已被拒绝')).toBeInTheDocument()
    expect(screen.getByTestId('task-overview')).toHaveTextContent('¥ 0.00')
    expect(screen.getByTestId('task-overview')).toHaveTextContent('0 允许 / 1 拒绝')
  })
  it('shows the trusted business rejection as the final business result', () => {
    overview({ ...savedSnapshot, task: { ...savedSnapshot.task, ticket_id: 'T10095', customer_id: 'C9595' },
      business_context: { ticket: { ticket_id: 'T10095', customer_id: 'C9595', title: '重复扣款申请', description: '', status: 'OPEN',
        verification_status: 'REJECTED', payment_verification_status: 'REJECTED', can_refund: false }, documents: [] } })
    expect(screen.getByText('退款未执行')).toBeInTheDocument()
    expect(screen.getByTestId('business-outcome-detail')).toHaveTextContent('业务核验未通过')
    expect(screen.getByRole('region', { name: '客户通知' })).toHaveTextContent('未发送：业务核验未通过')
    expect(screen.getByLabelText('办理结果通知正文')).toHaveTextContent('您的工单 T10095 未通过退款业务核验，本次未办理退款')
  })
  it('distinguishes persisted effects from other rejected requests in the same task', () => {
    overview({ ...workflowSnapshot, executions: [...savedSnapshot.executions, ...workflowSnapshot.executions] })
    expect(screen.getByText('业务已提交，另有拒绝记录')).toBeInTheDocument()
    expect(screen.queryByText('请求已被拒绝')).not.toBeInTheDocument()
    expect(screen.getByTestId('task-overview')).toHaveTextContent('1 允许 / 1 拒绝')
    expect(screen.getByTestId('task-overview')).toHaveTextContent('¥ 70.00')
  })
  it('does not label an incomplete latest run as a completed task when prior effects remain', () => {
    overview({ ...workflowSnapshot, workflow_runs: [{ ...workflowSnapshot.workflow_runs![0], state: 'FAILED' }],
      executions: [...savedSnapshot.executions, ...workflowSnapshot.executions] })
    expect(screen.getByText('本次运行未完成，已有业务提交')).toBeInTheDocument()
    expect(screen.queryByText('业务结果已提交')).not.toBeInTheDocument()
    expect(screen.queryByText('请求已被拒绝')).not.toBeInTheDocument()
    expect(screen.getByTestId('task-overview')).toHaveTextContent('¥ 70.00')
  })
  it('shows a stopped business decision without inventing a gateway denial or a refund', () => {
    overview({ ...workflowSnapshot, workflow_runs: [{ ...workflowSnapshot.workflow_runs![0], state: 'DENIED', reason_code: 'PLANNER_DECLINED' }],
      executions: [], business_effects: { refunds: [], notifications: [] } })
    expect(screen.getByText('本次办理已停止，未提交退款')).toBeInTheDocument()
    expect(screen.getByText('任务已停止，未发送通知')).toBeInTheDocument()
    expect(screen.queryByText('等待受控执行')).not.toBeInTheDocument()
    expect(screen.queryByText('请求已被拒绝')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: /安全网关/ })).toHaveTextContent('0 允许 / 0 拒绝')
    expect(screen.getByRole('button', { name: /业务工具/ })).toHaveTextContent('0 笔退款 / 0 条通知')
    expect(screen.getByText('业务已停止')).toBeInTheDocument()
    expect(screen.queryByLabelText('已拒绝（DENIED）')).not.toBeInTheDocument()
  })
  it('keeps unknown business results conspicuous instead of presenting a zero refund as final', () => {
    overview({ ...workflowSnapshot, executions: [{ ...workflowSnapshot.executions[0], state: 'UNKNOWN', business_effect_id: null }],
      business_effects: { refunds: [], notifications: [] } })
    expect(screen.getByText('业务结果未确认，请勿重复办理')).toBeInTheDocument()
    expect(screen.getByTestId('task-overview').querySelector('.studio-result-amount')).toHaveTextContent('结果待确认')
    expect(screen.getByRole('button', { name: /业务工具/ })).toHaveAttribute('data-state', 'unknown')
    expect(screen.queryByText('业务结果已提交')).not.toBeInTheDocument()
  })
  it('uses four main stages with evidence in its own detail entry', () => {
    overview()
    expect(screen.getByTestId('task-overview').querySelectorAll('.studio-process-stage')).toHaveLength(4)
    expect(screen.getByRole('button', { name: '回执留证' })).toBeInTheDocument()
  })
  it('keeps prior committed effects visible when the latest run stops', () => {
    overview({ ...workflowSnapshot, workflow_runs: [{ ...workflowSnapshot.workflow_runs![0], state: 'DENIED', reason_code: 'PLANNER_DECLINED' }] })
    expect(screen.getByText('本次运行已停止，已有业务提交')).toBeInTheDocument()
    expect(screen.queryByText('任务已停止，未执行退款')).not.toBeInTheDocument()
    expect(screen.getByTestId('task-overview')).toHaveTextContent('¥ 70.00')
  })
  it('keeps authorizations, flow, execution details and records independently accessible', () => {
    const actions = overview()
    fireEvent.click(screen.getByRole('button', { name: /企业授权/ }))
    expect(actions.onAuthorization).toHaveBeenCalledTimes(1)
    expect(actions.onInspect).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button', { name: /智能体协作/ }))
    expect(actions.onFlow).toHaveBeenCalledTimes(1)
    fireEvent.click(screen.getByRole('button', { name: /安全网关/ }))
    expect(actions.onInspect).toHaveBeenCalledWith({ kind: 'stage', stage: 'gateway' })
    fireEvent.click(screen.getByRole('button', { name: '执行记录' }))
    expect(actions.onRecords).toHaveBeenCalledTimes(1)
  })
  it('only sums committed business records and never claims a browser crypto check', () => {
    overview({ ...workflowSnapshot, business_effects: { ...workflowSnapshot.business_effects,
      refunds: [...workflowSnapshot.business_effects.refunds, { refund_id: 'pending', execution_id: 'pending', amount_fen: 9900, status: 'PENDING', created_at: 1790000002 }] } })
    expect(within(screen.getByTestId('task-overview')).queryByText('浏览器验签通过')).not.toBeInTheDocument()
    expect(screen.getByTestId('task-overview')).not.toHaveTextContent('169.00')
  })
  it('counts SENT notifications using the actual business status contract', () => {
    overview({ ...workflowSnapshot, executions: [...workflowSnapshot.executions,
      { ...workflowSnapshot.executions[0], execution_id: 'exec-notice', tool_name: 'notification.send_template', business_effect_id: 'notice-1' }], business_effects: { ...workflowSnapshot.business_effects,
      notifications: [{ notification_id: 'notice-1', execution_id: 'exec-notice', template_id: 'REFUND_SUCCESS', related_business_effect_id: 'refund-1', status: 'SENT', created_at: 1790000002 }] } })
    expect(screen.getByTestId('task-overview')).toHaveTextContent('通知 1 条')
    expect(screen.getByRole('button', { name: /业务工具/ })).toHaveTextContent('1 笔退款 / 1 条通知')
  })
  it('distinguishes a completed historical execution from the current expired credential', () => {
    const root = workflowSnapshot.credentials.find((item) => item.credential_type === 'ROOT')!
    render(<TaskOverview snapshot={workflowSnapshot} observedAt={root.expires_at + 1} controlsOpen={false}
      onInspect={vi.fn()} onFlow={vi.fn()} onRecords={vi.fn()} onConfigure={vi.fn()} />)
    expect(screen.getByText('业务结果已提交')).toBeInTheDocument()
    expect(screen.getAllByText(/历史授权 · 当前已到期/)).toHaveLength(2)
    expect(screen.queryByText('凭证已过期')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: /回执留证/ })).toBeInTheDocument()
  })
  it('keeps long source material in details instead of expanding the overview', () => {
    overview({ ...workflowSnapshot, business_context: { ...workflowSnapshot.business_context!,
      ticket: { ...workflowSnapshot.business_context!.ticket!, description: '仅在工单详情展示的完整合成资料' } } })
    expect(screen.queryByText('仅在工单详情展示的完整合成资料')).not.toBeInTheDocument()
    expect(document.querySelector('.studio-task-subject p')).toHaveTextContent('工单 T10086 · 客户 C9527')
  })
  it('opens the exact persisted execution from the homepage tool list', () => {
    const actions = overview()
    fireEvent.click(screen.getByRole('button', { name: /创建退款.*refund-service/ }))
    expect(actions.onInspect).toHaveBeenCalledWith({ kind: 'execution', execution: workflowSnapshot.executions[0] })
  })
  it('replays saved observations without changing or hiding task business totals', () => {
    vi.useFakeTimers()
    const actions = overview()
    const events = workflowSnapshot.workflow_runs![0].events
    const slider = screen.getByRole('slider', { name: '首页回放进度' })
    expect(slider).toHaveValue(String(events.length))
    fireEvent.click(screen.getByRole('button', { name: '回放过程' }))
    expect(slider).toHaveValue('0')
    expect(screen.getByText('业务结果已提交')).toBeInTheDocument()
    act(() => vi.advanceTimersByTime(650))
    expect(slider).toHaveValue('1')
    expect(screen.getByTestId('overview-replay')).toHaveTextContent(eventTitle(events[0]))
    fireEvent.click(screen.getByRole('button', { name: '查看事件' }))
    expect(actions.onInspect).toHaveBeenCalledWith({ kind: 'workflow', runId: workflowSnapshot.workflow_runs![0].run_id, sequence: events[0].sequence })
    fireEvent.click(screen.getByRole('button', { name: '暂停回放' }))
    act(() => vi.advanceTimersByTime(1300))
    expect(slider).toHaveValue('1')
    fireEvent.change(slider, { target: { value: String(events.length) } })
    expect(screen.getByTestId('task-overview')).toHaveTextContent('¥ 70.00')
    fireEvent.click(screen.getByRole('button', { name: '回放过程' }))
    expect(slider).toHaveValue('0')
  })
  it('preserves a paused cursor during polling and resets it for a different task', () => {
    const actions = { onInspect: vi.fn(), onFlow: vi.fn(), onRecords: vi.fn(), onConfigure: vi.fn() }
    const { rerender } = render(<TaskOverview snapshot={workflowSnapshot} observedAt={1790000005} controlsOpen={false} {...actions} />)
    fireEvent.change(screen.getByRole('slider', { name: '首页回放进度' }), { target: { value: '3' } })
    rerender(<TaskOverview snapshot={{ ...workflowSnapshot }} observedAt={1790000006} controlsOpen={false} {...actions} />)
    expect(screen.getByRole('slider', { name: '首页回放进度' })).toHaveValue('3')
    rerender(<TaskOverview snapshot={savedSnapshot} observedAt={1790000006} controlsOpen={false} {...actions} />)
    expect(screen.queryByTestId('overview-replay')).not.toBeInTheDocument()
    expect(screen.getByText('请求已被拒绝')).toBeInTheDocument()
  })
  it('does not count an undecided request as accepted or rejected', () => {
    overview({ ...savedSnapshot, executions: [{ ...savedSnapshot.executions[0], decision: null, state: 'ADMITTED' }] })
    expect(screen.getByTestId('task-overview')).toHaveTextContent('0 允许 / 0 拒绝')
    expect(screen.getByTestId('task-overview')).toHaveTextContent('1 笔待裁决')
    expect(screen.queryByText('请求已被拒绝')).not.toBeInTheDocument()
  })
  it.each([
    { name: 'wrong execution', refunds: [{ ...workflowSnapshot.business_effects.refunds[0], execution_id: 'missing' }] },
    { name: 'duplicate refund', refunds: [...workflowSnapshot.business_effects.refunds, ...workflowSnapshot.business_effects.refunds] },
    { name: 'negative amount', refunds: [{ ...workflowSnapshot.business_effects.refunds[0], amount_fen: -7000 }] },
    { name: 'unsafe amount', refunds: [{ ...workflowSnapshot.business_effects.refunds[0], amount_fen: Number.MAX_SAFE_INTEGER + 1 }] },
    { name: 'over budget', refunds: [{ ...workflowSnapshot.business_effects.refunds[0], amount_fen: 7100 }] },
  ])('does not present $name as a confirmed business result', ({ refunds }) => {
    overview({ ...workflowSnapshot, business_effects: { refunds, notifications: [] } })
    expect(screen.getByText('业务记录关联异常，待核对')).toBeInTheDocument()
    expect(screen.queryByText('业务结果已提交')).not.toBeInTheDocument()
    expect(screen.getByTestId('task-overview').querySelector('.studio-result-amount')).toHaveTextContent('待核对')
  })
  it('does not count a SENT notification without a bound committed execution', () => {
    overview({ ...workflowSnapshot, business_effects: { ...workflowSnapshot.business_effects,
      notifications: [{ notification_id: 'notice-1', execution_id: 'missing', template_id: 'REFUND_SUCCESS', related_business_effect_id: 'refund-1', status: 'SENT', created_at: 1790000002 }] } })
    expect(screen.getByText('业务记录关联异常，待核对')).toBeInTheDocument()
    expect(screen.queryByText('业务结果已提交')).not.toBeInTheDocument()
    const notification = screen.getByRole('region', { name: '客户通知' })
    expect(within(notification).getByText('通知记录不一致')).toBeInTheDocument()
    expect(within(notification).queryByText('通知已发送')).not.toBeInTheDocument()
  })
  it('does not include a notification for another customer in the task totals', () => {
    overview({ ...workflowSnapshot, executions: [...workflowSnapshot.executions,
      { ...workflowSnapshot.executions[0], execution_id: 'exec-notice', tool_name: 'notification.send_template', business_effect_id: 'notice-1' }],
      business_effects: { ...workflowSnapshot.business_effects, notifications: [{ notification_id: 'notice-1', execution_id: 'exec-notice',
        template_id: 'REFUND_SUCCESS', customer_id: 'C7812', related_business_effect_id: 'refund-1', status: 'SENT', created_at: 1790000002 }] } })
    expect(screen.getByText('业务记录关联异常，待核对')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /业务工具/ })).toHaveTextContent('业务记录待核对')
    expect(screen.getByText('通知记录不一致')).toBeInTheDocument()
    expect(screen.queryByText('业务结果已提交')).not.toBeInTheDocument()
    expect(screen.queryByText('通知已发送')).not.toBeInTheDocument()
  })
})
