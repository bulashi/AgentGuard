import { CustomerName } from './CustomerName'
import type { CSSProperties } from 'react'
import type { TaskSnapshot } from '../types'
import { activeWorkflow, businessOutcome, isBusinessStop, workflowBusinessResults } from '../workflowModel'
import { StatusTag, TimeValue } from './Evidence'

const bodyStyle: CSSProperties = {
  margin: '12px 0', padding: '12px 16px', borderLeft: '3px solid var(--blue)',
  background: 'var(--blue-soft)', color: 'var(--ink)', fontSize: 16, lineHeight: 1.8,
  whiteSpace: 'pre-wrap', overflowWrap: 'anywhere',
}
const metaStyle: CSSProperties = { margin: '6px 0', color: 'var(--secondary)', fontSize: 14, overflowWrap: 'anywhere' }
const headingStyle: CSSProperties = { display: 'flex', alignItems: 'center', flexWrap: 'wrap', gap: 12 }

export function NotificationPreview({ snapshot, includeTemplatePreview = true }: {
  snapshot: TaskSnapshot; includeTemplatePreview?: boolean
}) {
  const notices = snapshot.business_effects.notifications
  const result = workflowBusinessResults(snapshot).notification
  const outcome = businessOutcome(snapshot)
  const run = activeWorkflow(snapshot)
  const stoppedBeforeNotice = run?.state === 'DENIED'
    && !snapshot.executions.some((execution) => execution.tool_name === 'notification.send_template')
  const emptyStatus = outcome.status === 'BUSINESS_STOPPED' ? 'BUSINESS_STOPPED'
    : stoppedBeforeNotice && isBusinessStop(run?.reason_code) ? 'BUSINESS_STOPPED'
    : result.state === 'unknown' ? 'UNKNOWN' : stoppedBeforeNotice || result.state === 'denied' ? 'DENIED' : result.state === 'failed' ? 'FAILED' : 'PENDING'
  const verification = snapshot.business_context?.ticket?.business_verification
  const factBased = snapshot.business_context?.ticket?.source === 'facts' || Boolean(snapshot.business_context?.ticket?.business_facts)
  const emptyLabel = outcome.status === 'BUSINESS_STOPPED' ? verification?.status === 'PENDING' ? '未发送：资料待核验，未退款' : '未发送：业务核验未通过'
    : stoppedBeforeNotice && !factBased && isBusinessStop(run?.reason_code) ? '任务已停止，未发送通知'
      : outcome.status === 'NO_EFFECT' ? '未发送：退款未执行'
      : outcome.status === 'DENIED' ? '未发送：网关拒绝退款请求'
        : stoppedBeforeNotice ? '任务已停止，未发送通知' : result.label
  const outcomeText = outcome.status === 'BUSINESS_STOPPED'
    ? verification?.reason ? `本次未办理退款。原因：${verification.reason} 如需补充或核实支付资料，请通过原客服渠道联系。` : '未通过退款业务核验，本次未办理退款。如需核实核验情况，请通过原客服渠道联系。'
    : outcome.status === 'COMPLETED' ? `已提交退款申请，金额 ${(outcome.refundFen / 100).toFixed(2)} 元。`
      : outcome.status === 'UNKNOWN' || outcome.status === 'INCONSISTENT'
        ? '的退款结果尚待核实，请勿重复提交退款申请。如需进一步协助，请通过原客服渠道联系。'
        : outcome.status === 'RUNNING' ? '正在办理中，退款结果尚未确认。'
          : outcome.status === 'NOT_RUN' ? '尚未执行退款办理。'
            : '本次未办理退款。如需进一步协助，请通过原客服渠道联系。'

  return <div className="studio-notification-content" data-testid="customer-notification-content" style={{ minWidth: 0 }}>
    {includeTemplatePreview ? <section aria-label="办理结果通知" data-testid="notification-result-content">
      <h3 style={{ margin: '0 0 12px', fontSize: 16, color: 'var(--ink)' }}>办理结果通知</h3>
      <p className="studio-notification-body" style={bodyStyle} aria-label="办理结果通知正文">尊敬的客户 <CustomerName id={snapshot.task.customer_id} />：您的工单 {snapshot.task.ticket_id} {outcomeText}</p>
    </section> : null}
    <section aria-label="已保存通知" data-testid="notification-saved-records" style={{ marginTop: includeTemplatePreview ? 20 : 0 }}>
      <h3 style={{ margin: '0 0 12px', fontSize: 16, color: 'var(--ink)' }}>已保存通知</h3>
      {notices.length ? notices.map((notice, index) => {
        const valid = result.state === 'completed' && (notice.customer_id === undefined || notice.customer_id === snapshot.task.customer_id)
        const hasContent = typeof notice.content === 'string' && notice.content.trim().length > 0
        return <article className="studio-notification-record" key={`${notice.notification_id}-${index}`} data-testid="notification-record"
          style={{ padding: '12px 0', borderTop: '1px solid var(--line)', minWidth: 0 }}>
          <div className="studio-notification-heading" style={headingStyle}><strong>办理结果通知</strong>
            <StatusTag value={valid ? 'COMPLETED' : notice.status === 'SENT' ? 'INVALID' : notice.status}
              label={valid ? '通知已发送' : notice.status === 'SENT' ? '通知记录不一致' : '通知未发送'} />
          </div>
          <p className="studio-notification-meta" style={metaStyle}>客户 {notice.customer_id ? <CustomerName id={notice.customer_id} /> : '未记录'} · 关联退款 {notice.related_business_effect_id}</p>
          <p className="studio-notification-meta" style={metaStyle}>通知 {notice.notification_id} · 关联执行 {notice.execution_id} · 记录状态 {notice.status}</p>
          <p className="studio-notification-meta" style={metaStyle}>保存时间 <TimeValue value={notice.created_at} /></p>
          {hasContent ? <p className="studio-notification-body" style={bodyStyle} aria-label="已保存通知正文">{notice.content}</p>
            : <p className="detail-muted">未保存通知正文</p>}
        </article>
      }) : <div style={headingStyle}><p style={{ ...metaStyle, margin: 0 }}>暂无已保存通知</p><StatusTag value={emptyStatus} label={emptyLabel} /></div>}
    </section>
  </div>
}
