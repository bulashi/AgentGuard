import { Descriptions, Table } from 'antd'
import type { BusinessFactsRecord, BusinessPaymentFact } from '../api'
import { Fen, StatusTag } from './Evidence'

function fields(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : {}
}

export function readBusinessFacts(value: unknown): BusinessFactsRecord | null {
  const facts = fields(value)
  const order = fields(facts.order)
  if (facts.schema_version !== '1.0' || typeof order.order_id !== 'string' || order.currency !== 'CNY'
    || !Number.isSafeInteger(order.amount_fen) || Number(order.amount_fen) <= 0
    || typeof facts.claim_text !== 'string' || !Array.isArray(facts.payments) || !facts.payments.length || facts.payments.length > 8) return null
  const identifiers = new Set<string>()
  for (const item of facts.payments) {
    const payment = fields(item)
    if (typeof payment.transaction_id !== 'string' || identifiers.has(payment.transaction_id)
      || !['SUCCESS', 'FAILED', 'PROCESSING'].includes(String(payment.status))
      || !Number.isSafeInteger(payment.amount_fen) || Number(payment.amount_fen) <= 0
      || !Number.isSafeInteger(payment.refunded_amount_fen) || Number(payment.refunded_amount_fen) < 0
      || Number(payment.refunded_amount_fen) > Number(payment.amount_fen)
      || payment.status !== 'SUCCESS' && payment.refunded_amount_fen !== 0) return null
    identifiers.add(payment.transaction_id)
  }
  return value as BusinessFactsRecord
}

const paymentLabels = { SUCCESS: '支付成功', FAILED: '支付失败', PROCESSING: '支付处理中' }

export function BusinessFacts({ facts: raw, compact = false }: { facts: unknown; compact?: boolean }) {
  const facts = readBusinessFacts(raw)
  if (!facts) return <p className="detail-muted" role="status">订单或支付事实不完整，请查看原始记录。</p>
  return <section aria-label="订单与支付事实" data-testid="business-facts">
    <h3>订单与支付事实</h3>
    <Descriptions column={compact ? 2 : 1} size="small" items={[
      { key: 'order', label: '订单编号', children: <span className="mono" style={{ overflowWrap: 'anywhere' }}>{facts.order.order_id}</span> },
      { key: 'amount', label: '订单应付金额', children: <Fen value={facts.order.amount_fen} /> },
      ...(!compact ? [{ key: 'claim', label: '客户申诉', children: <span style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{facts.claim_text}</span> }] : []),
    ]} />
    <Table<BusinessPaymentFact> size="small" pagination={false} rowKey="transaction_id" dataSource={facts.payments}
      scroll={{ x: 520 }} columns={[
        { key: 'id', title: '支付流水', dataIndex: 'transaction_id', render: (value: string) => <span className="mono" style={{ overflowWrap: 'anywhere' }}>{value}</span> },
        { key: 'status', title: '支付状态', dataIndex: 'status', render: (value: BusinessPaymentFact['status']) => <StatusTag value={value === 'SUCCESS' ? 'COMMITTED' : value === 'FAILED' ? 'BUSINESS_STOPPED' : 'PENDING'} label={paymentLabels[value]} /> },
        { key: 'amount', title: '交易金额', dataIndex: 'amount_fen', render: (value: number) => <Fen value={value} /> },
        { key: 'refunded', title: '此前已退金额', dataIndex: 'refunded_amount_fen', render: (value: number) => <Fen value={value} /> },
      ]} />
  </section>
}
