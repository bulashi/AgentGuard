import { Descriptions, Empty } from 'antd'
import { Fen, ShortHash, StatusTag, TimeValue } from './Evidence'
import type { BusinessTicket } from '../api'
import { ticketBusinessStatus } from '../businessTickets'
import { BusinessFacts } from './BusinessFacts'

function fields(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : {}
}

const LABELS: Record<string, string> = { VERIFIED: '已核验', PENDING: '待核验', REJECTED: '不符合办理条件' }

function verificationStatus(value: unknown) {
  const status = typeof value === 'string' ? value : ''
  return <StatusTag value={status === 'VERIFIED' ? 'VERIFIED' : status === 'REJECTED' ? 'BUSINESS_STOPPED' : 'PENDING'}
    label={LABELS[status] ?? '核验状态未提供'} />
}

function amount(value: unknown) {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 ? <Fen value={value} /> : '未提供'
}

export function RefundVerificationFacts({ value, ticket, compact = false }: { value: unknown; ticket?: unknown; compact?: boolean }) {
  const rows = Array.isArray(value) ? value.map(fields) : []
  const metadata = fields(ticket)
  if (metadata.source === 'facts' || metadata.business_facts) {
    const verification = fields(metadata.business_verification)
    const verified = typeof verification.status === 'string'
    const reason = typeof verification.reason === 'string' ? verification.reason : ''
    const evidenceIds = Array.isArray(verification.evidence_ids) ? verification.evidence_ids.filter((id): id is string => typeof id === 'string') : []
    return <section className={`refund-verification-facts${compact ? ' verification-compact' : ''}`} aria-label="业务核验记录" data-testid="refund-verification-facts">
      <h3>业务核验<span>基于订单与支付事实</span></h3>
      <div className="refund-verification-row">
        <span>办理状态 {verified ? verificationStatus(verification.status) : <StatusTag value="PENDING" label="待运行核验" />}</span>
        {verified ? <span>核验可退金额 {amount(verification.refundable_amount_fen)}</span> : null}
      </div>
      {reason ? <p data-testid="business-verification-reason">{reason}</p> : null}
      {verified && evidenceIds.length ? <p className="detail-muted">依据：{evidenceIds.join('、')}</p> : null}
      {!compact ? <><BusinessFacts facts={metadata.business_facts} />
        {verified ? <Descriptions column={1} size="small" items={[
          { key: 'transaction', label: '拟退款流水', children: typeof verification.original_transaction_id === 'string' ? <ShortHash value={verification.original_transaction_id} /> : '未提交退款' },
          { key: 'time', label: '核验时间', children: <TimeValue value={typeof verification.evaluated_at === 'number' ? verification.evaluated_at : null} /> },
          { key: 'hash', label: '原始事实摘要', children: <ShortHash value={typeof metadata.facts_hash === 'string' ? metadata.facts_hash : null} /> },
        ]} /> : null}</> : null}
    </section>
  }
  const hasMetadata = ['can_refund', 'already_processed', 'in_progress', 'transaction_remaining_fen'].some((key) => key in metadata)
  if (!rows.length && !hasMetadata) return compact ? null : <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="当前工单记录未提供业务核验字段" />
  return <section className={`refund-verification-facts${compact ? ' verification-compact' : ''}`} aria-label="业务核验记录" data-testid="refund-verification-facts">
    <h3>业务核验<span>工单服务记录</span></h3>
    {hasMetadata ? <div className="refund-verification-row">
      <span>办理状态 {ticketBusinessStatus(metadata as unknown as BusinessTicket)}</span>
      <span>原交易 <ShortHash value={typeof metadata.original_transaction_id === 'string' ? metadata.original_transaction_id : null} copyable={false} /></span>
      <span>交易剩余额 {amount(metadata.transaction_remaining_fen)}</span>
    </div> : null}
    {rows.map((row, index) => <div className="refund-verification-row" key={index}>
      {compact ? <><span>{verificationStatus(row.verification_status)}</span><span>原交易 <ShortHash value={typeof row.original_transaction_id === 'string' ? row.original_transaction_id : null} size={8} copyable={false} /></span>
        <span>可退金额 {amount(row.refundable_amount_fen)}</span></>
        : <Descriptions column={1} size="small" items={[
          { key: 'status', label: '业务核验状态', children: verificationStatus(row.verification_status) },
          { key: 'payment', label: '支付核验状态', children: verificationStatus(row.payment_verification_status) },
          { key: 'slot', label: '办理事项标识', children: typeof row.trusted_action_slot === 'string' ? row.trusted_action_slot : '未提供' },
          { key: 'transaction', label: '原交易标识', children: <ShortHash value={typeof row.original_transaction_id === 'string' ? row.original_transaction_id : null} /> },
          { key: 'reason', label: '退款事由代码', children: typeof row.refund_reason_code === 'string' ? row.refund_reason_code : '未提供' },
          { key: 'amount', label: '事项可退金额', children: amount(row.refundable_amount_fen) },
          { key: 'transaction-amount', label: '交易可退金额', children: amount(row.transaction_refundable_amount_fen) },
          { key: 'reference', label: '核验依据编号', children: typeof row.evidence_reference === 'string' ? row.evidence_reference : '未提供' },
          { key: 'time', label: '核验时间', children: <TimeValue value={typeof row.verified_at === 'number' ? row.verified_at : null} /> },
        ]} />}
    </div>)}
  </section>
}
