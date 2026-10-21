import { render, screen, within } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import type { TaskSnapshot } from '../types'
import { savedSnapshot, workflowSnapshot } from '../test/fixtures'
import { NotificationPreview } from './NotificationPreview'

const template = {
  template_id: 'REFUND_SUCCESS', version: 'v1', title: '退款成功通知',
  content_template: '客户 {customer_id}，您的退款 {refund_id} 已提交，金额 {amount}。',
}
const storedBody = '尊敬的 C9527 客户：\n工单 T10086 的退款 refund-1 已提交，金额 70.00 元。'

function notifiedSnapshot(): TaskSnapshot {
  return { ...workflowSnapshot,
    business_context: { ...workflowSnapshot.business_context!, notification_templates: [template] },
    executions: [...workflowSnapshot.executions, { ...workflowSnapshot.executions[0], execution_id: 'exec-notice',
      tool_name: 'notification.send_template', business_effect_id: 'notice-1' }],
    business_effects: { ...workflowSnapshot.business_effects, notifications: [{ notification_id: 'notice-1', execution_id: 'exec-notice',
      template_id: 'REFUND_SUCCESS', template_version: 'v1', customer_id: 'C9527', content: storedBody,
      related_business_effect_id: 'refund-1', status: 'SENT', created_at: 1790000002 }] },
  }
}

describe('NotificationPreview', () => {
  it('shows the business outcome without displaying a success template or creating a sent notice', () => {
    const snapshot = { ...savedSnapshot, business_context: { ticket: null, documents: [], notification_templates: [template] } }
    const original = JSON.stringify(snapshot)
    render(<NotificationPreview snapshot={snapshot} />)
    const preview = screen.getByRole('region', { name: '办理结果通知' })
    expect(within(preview).getByLabelText('办理结果通知正文')).toHaveTextContent('您的工单 T10086 本次未办理退款')
    for (const text of ['模板预览', '仅供查看，不代表已发送', '仅模板预览', '固定模板 REFUND_SUCCESS · 版本 v1', '退款成功通知']) {
      expect(screen.queryByText(text)).not.toBeInTheDocument()
    }
    expect(screen.getByText('暂无已保存通知')).toBeInTheDocument()
    expect(screen.queryByLabelText('已保存通知正文')).not.toBeInTheDocument()
    expect(screen.queryByText('通知已发送')).not.toBeInTheDocument()
    expect(JSON.stringify(snapshot)).toBe(original)
  })

  it('shows the business outcome even when the catalog is absent', () => {
    render(<NotificationPreview snapshot={savedSnapshot} />)
    expect(screen.getByLabelText('办理结果通知正文')).toHaveTextContent('本次未办理退款')
    expect(screen.queryByText('通知已发送')).not.toBeInTheDocument()
  })
  it('distinguishes a stopped workflow from a pending notification that was never requested', () => {
    const snapshot = { ...workflowSnapshot,
      workflow_runs: [{ ...workflowSnapshot.workflow_runs![0], state: 'DENIED', reason_code: 'PLANNER_DECLINED' }],
      executions: [], business_effects: { refunds: [], notifications: [] } }
    render(<NotificationPreview snapshot={snapshot} />)
    expect(screen.getByText('任务已停止，未发送通知')).toBeInTheDocument()
    expect(screen.queryByText('等待退款确认')).not.toBeInTheDocument()
    expect(screen.queryByText('通知已拒绝')).not.toBeInTheDocument()
    expect(screen.queryByText('通知已发送')).not.toBeInTheDocument()
  })

  it('keeps the business result separate from the exact stored body and its associations', () => {
    render(<NotificationPreview snapshot={notifiedSnapshot()} />)
    const preview = screen.getByRole('region', { name: '办理结果通知' })
    const saved = screen.getByRole('region', { name: '已保存通知' })
    expect(within(preview).getByLabelText('办理结果通知正文')).toHaveTextContent('已提交退款申请，金额 70.00 元')
    expect(within(saved).getByLabelText('已保存通知正文').textContent).toBe(storedBody)
    expect(saved).toHaveTextContent('客户 C9527 · 关联退款 refund-1')
    expect(saved).toHaveTextContent('通知 notice-1 · 关联执行 exec-notice')
    expect(within(saved).getByText('办理结果通知')).toBeInTheDocument()
    expect(within(saved).getByText('通知已发送')).toBeInTheDocument()
    expect(within(saved).queryByLabelText('办理结果通知正文')).not.toBeInTheDocument()
  })

  it('reports missing historical content and version without filling them from the current template', () => {
    const snapshot = notifiedSnapshot()
    snapshot.business_effects.notifications = snapshot.business_effects.notifications.map((notice) => ({ ...notice,
      content: undefined, template_version: undefined, customer_id: undefined }))
    render(<NotificationPreview snapshot={snapshot} includeTemplatePreview={false} />)
    expect(screen.getByText('未保存通知正文')).toBeInTheDocument()
    expect(screen.queryByText(/固定模板/)).not.toBeInTheDocument()
    expect(screen.getByText('客户 未记录 · 关联退款 refund-1')).toBeInTheDocument()
    expect(screen.queryByLabelText('已保存通知正文')).not.toBeInTheDocument()
    expect(screen.queryByText('退款成功通知')).not.toBeInTheDocument()
  })

  it.each([
    { name: 'missing execution', change: { execution_id: 'missing' } },
    { name: 'unrelated refund', change: { related_business_effect_id: 'other-refund' } },
    { name: 'different template', change: { template_id: 'OTHER_TEMPLATE' } },
    { name: 'different customer', change: { customer_id: 'OTHER_CUSTOMER' } },
  ])('does not show sent success for a SENT row with $name', ({ change }) => {
    const snapshot = notifiedSnapshot()
    snapshot.business_effects.notifications = snapshot.business_effects.notifications.map((notice) => ({ ...notice, ...change }))
    render(<NotificationPreview snapshot={snapshot} includeTemplatePreview={false} />)
    expect(screen.getByText('通知记录不一致')).toBeInTheDocument()
    expect(screen.queryByText('通知已发送')).not.toBeInTheDocument()
    expect(screen.getByLabelText('已保存通知正文').textContent).toBe(storedBody)
    expect(screen.getByTestId('notification-record')).toHaveTextContent('记录状态 SENT')
  })

  it('rejects duplicate SENT rows instead of counting them as multiple delivered notices', () => {
    const snapshot = notifiedSnapshot()
    snapshot.business_effects.notifications = [...snapshot.business_effects.notifications, ...snapshot.business_effects.notifications]
    render(<NotificationPreview snapshot={snapshot} includeTemplatePreview={false} />)
    expect(screen.getAllByText('通知记录不一致')).toHaveLength(2)
    expect(screen.queryByText('通知已发送')).not.toBeInTheDocument()
  })

  it.each(['DENIED', 'FAILED_NO_EFFECT', 'ADMITTED'])('does not show sent success for an empty %s execution', (state) => {
    const snapshot = notifiedSnapshot()
    snapshot.business_effects.notifications = []
    snapshot.executions = snapshot.executions.map((execution) => execution.execution_id === 'exec-notice'
      ? { ...execution, state, decision: state === 'DENIED' ? 'DENY' : 'ALLOW', business_effect_id: null } : execution)
    render(<NotificationPreview snapshot={snapshot} />)
    expect(screen.getByText('暂无已保存通知')).toBeInTheDocument()
    expect(screen.queryByText('通知已发送')).not.toBeInTheDocument()
    expect(screen.queryByLabelText('已保存通知正文')).not.toBeInTheDocument()
    if (state === 'DENIED') expect(screen.getByText('通知权限被拒绝')).toBeInTheDocument()
  })

  it('renders historical text as text and preserves it across a catalog revision', () => {
    const snapshot = notifiedSnapshot()
    const content = '历史合成记录\n<script>alert("stored")</script>'
    snapshot.business_effects.notifications = snapshot.business_effects.notifications.map((notice) => ({ ...notice, content }))
    const { rerender } = render(<NotificationPreview snapshot={snapshot} includeTemplatePreview={false} />)
    expect(screen.getByLabelText('已保存通知正文').textContent).toBe(content)
    expect(screen.getByLabelText('已保存通知正文').querySelector('script')).toBeNull()
    rerender(<NotificationPreview snapshot={{ ...snapshot, business_context: { ...snapshot.business_context!,
      notification_templates: [{ ...template, version: 'v2', content_template: '新的模板正文' }] } }} includeTemplatePreview={false} />)
    expect(screen.getByLabelText('已保存通知正文').textContent).toBe(content)
    expect(screen.queryByText(/固定模板/)).not.toBeInTheDocument()
    expect(screen.queryByText('新的模板正文')).not.toBeInTheDocument()
  })
  it('shows T10095 verification failure without success wording, placeholders or a fabricated sent record', () => {
    const snapshot: TaskSnapshot = { ...savedSnapshot,
      task: { ...savedSnapshot.task, ticket_id: 'T10095', customer_id: 'C9595' },
      business_context: { ticket: { ticket_id: 'T10095', customer_id: 'C9595', title: '重复扣款申请', description: '', status: 'OPEN',
        verification_status: 'REJECTED', payment_verification_status: 'REJECTED', can_refund: false }, documents: [], notification_templates: [template] } }
    const original = JSON.stringify(snapshot)
    render(<NotificationPreview snapshot={snapshot} />)
    const body = screen.getByLabelText('办理结果通知正文')
    expect(body).toHaveTextContent('尊敬的客户 C9595：您的工单 T10095 未通过退款业务核验，本次未办理退款')
    expect(body).toHaveTextContent('如需核实核验情况，请通过原客服渠道联系')
    expect(body.textContent).not.toMatch(/已办理退款|已提交退款|\{customer_id\}|\{ticket_id\}|\{refund_id\}/)
    expect(screen.getByText('未发送：业务核验未通过')).toBeInTheDocument()
    expect(screen.queryByLabelText('已保存通知正文')).not.toBeInTheDocument()
    expect(screen.queryByText('通知已发送')).not.toBeInTheDocument()
    expect(JSON.stringify(snapshot)).toBe(original)
  })

  it.each([
    { status: 'REJECTED' as const, reason: '只有 P-one 支付成功，P-two 支付失败，没有第二笔成功扣款。', label: '未发送：业务核验未通过' },
    { status: 'PENDING' as const, reason: 'P-two 的支付仍在处理中，需要等待支付结果确认。', label: '未发送：资料待核验，未退款' },
  ])('explains the actual $status fact evaluation without creating a saved notice', ({ status, reason, label }) => {
    const snapshot: TaskSnapshot = { ...workflowSnapshot, executions: [], business_effects: { refunds: [], notifications: [] },
      workflow_runs: [{ ...workflowSnapshot.workflow_runs![0], state: 'DENIED', reason_code: `BUSINESS_VERIFICATION_${status}` }],
      business_context: { ...workflowSnapshot.business_context!, ticket: { ...workflowSnapshot.business_context!.ticket!, source: 'facts',
        business_verification: { schema_version: '1.0', task_id: workflowSnapshot.task.task_id, ticket_id: workflowSnapshot.task.ticket_id,
          facts_hash: 'a'.repeat(64), status, reason_code: status === 'REJECTED' ? 'NO_DUPLICATE_SUCCESSFUL_CHARGE' : 'PAYMENT_PROCESSING',
          reason, evidence_ids: ['P-one', 'P-two'], refundable_amount_fen: 0, original_transaction_id: null,
          policy_version: 'duplicate-full-charge-v1', evaluated_at: 1790000001 } } } }
    const original = JSON.stringify(snapshot)
    render(<NotificationPreview snapshot={snapshot} />)
    expect(screen.getByLabelText('办理结果通知正文')).toHaveTextContent(`本次未办理退款。原因：${reason}`)
    expect(screen.getByText(label)).toBeInTheDocument()
    expect(screen.queryByText('等待退款确认')).not.toBeInTheDocument()
    expect(screen.queryByText('通知已发送')).not.toBeInTheDocument()
    expect(screen.queryByLabelText('已保存通知正文')).not.toBeInTheDocument()
    expect(JSON.stringify(snapshot)).toBe(original)
  })
})
