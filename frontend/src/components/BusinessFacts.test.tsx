import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { BusinessFacts, readBusinessFacts } from './BusinessFacts'
import type { BusinessFactsRecord } from '../api'

const facts: BusinessFactsRecord = { schema_version: '1.0', order: { order_id: 'O-new', amount_fen: 7000, currency: 'CNY' }, claim_text: '客户怀疑重复扣款，请核对。', payments: [
  { transaction_id: 'P-success', amount_fen: 7000, status: 'SUCCESS', refunded_amount_fen: 123 },
  { transaction_id: 'P-failed', amount_fen: 7000, status: 'FAILED', refunded_amount_fen: 0 },
  { transaction_id: 'P-processing', amount_fen: 7000, status: 'PROCESSING', refunded_amount_fen: 0 },
] }

describe('raw business facts display', () => {
  it('shows the actual states and prior refund balances without promoting a claim to a verified conclusion', () => {
    render(<BusinessFacts facts={facts} />)
    const displayed = screen.getByTestId('business-facts')
    for (const label of ['O-new', '订单应付金额', '客户怀疑重复扣款', 'P-success', 'P-failed', 'P-processing', '支付成功', '支付失败', '支付处理中', '此前已退金额', '1.23', '70.00']) expect(displayed).toHaveTextContent(label)
    expect(displayed).not.toHaveTextContent('可办理')
    expect(displayed).not.toHaveTextContent('已退款')
  })
  it('does not use invalid or missing payments as trusted evidence', () => {
    expect(readBusinessFacts({ ...facts, payments: [{ ...facts.payments[1], refunded_amount_fen: 100 }] })).toBeNull()
    expect(readBusinessFacts({ ...facts, payments: [] })).toBeNull()
    render(<BusinessFacts facts={{ ...facts, order: { ...facts.order, amount_fen: 70.1 } }} />)
    expect(screen.getByRole('status')).toHaveTextContent('订单或支付事实不完整')
    expect(screen.queryByTestId('business-facts')).not.toBeInTheDocument()
  })
})
