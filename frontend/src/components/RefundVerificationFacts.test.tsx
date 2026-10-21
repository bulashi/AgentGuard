import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { RefundVerificationFacts } from './RefundVerificationFacts'

const row = { trusted_action_slot: 'slot-1', verification_status: 'VERIFIED', original_transaction_id: 'transaction-1',
  refund_reason_code: 'DUPLICATE_CHARGE', refundable_amount_fen: 7000, evidence_reference: 'verification-1',
  verified_at: 1760000000, payment_verification_status: 'PENDING', transaction_refundable_amount_fen: 9000 }

describe('trusted business facts from ticket records', () => {
  it('does not show a preset answer before a raw-fact case has run', () => {
    render(<RefundVerificationFacts value={undefined} ticket={{ source: 'facts', business_facts: { schema_version: '1.0',
      order: { order_id: 'O-facts', amount_fen: 7000, currency: 'CNY' }, claim_text: '请核对支付',
      payments: [{ transaction_id: 'P-facts', amount_fen: 7000, status: 'SUCCESS', refunded_amount_fen: 0 }] } }} />)
    expect(screen.getByTestId('refund-verification-facts')).toHaveTextContent('待运行核验')
    expect(screen.getByTestId('business-facts')).toHaveTextContent('P-facts')
    expect(screen.queryByText('已核验')).not.toBeInTheDocument()
  })
  it('shows a concrete trusted reason and evidence when fact evaluation rejected a refund', () => {
    render(<RefundVerificationFacts value={undefined} ticket={{ source: 'facts', business_verification: {
      status: 'REJECTED', reason: '只有 P-one 支付成功，P-two 支付失败，没有第二笔成功扣款。',
      evidence_ids: ['P-one', 'P-two'], refundable_amount_fen: 0,
    } }} compact />)
    const displayed = screen.getByTestId('refund-verification-facts')
    expect(displayed).toHaveTextContent('不符合办理条件')
    expect(displayed).toHaveTextContent('只有 P-one 支付成功，P-two 支付失败')
    expect(displayed).toHaveTextContent('依据：P-one、P-two')
    expect(displayed).toHaveTextContent('0.00')
  })
  it('renders every supplied business verification field independently of any model summary', () => {
    render(<RefundVerificationFacts value={[row]} />)
    const facts = screen.getByTestId('refund-verification-facts')
    for (const value of ['已核验', '待核验', 'slot-1', 'transaction-1', 'DUPLICATE_CHARGE', 'verification-1', '70.00', '90.00']) {
      expect(facts).toHaveTextContent(value)
    }
    expect(facts).not.toHaveTextContent('已退款')
    expect(facts).not.toHaveTextContent('累计已办理')
  })
  it.each([['PENDING', '待核验'], ['REJECTED', '不符合办理条件'], ['unexpected', '核验状态未提供']])(
    'does not upgrade %s to VERIFIED', (status, label) => {
      render(<RefundVerificationFacts value={[{ ...row, verification_status: status }]} compact />)
      expect(screen.getByTestId('refund-verification-facts')).toHaveTextContent(label)
      expect(screen.queryByText('已核验')).not.toBeInTheDocument()
    },
  )
  it('does not infer verification from a natural language summary or missing structured fields', () => {
    render(<RefundVerificationFacts value={[{ summary: '交易已核验并且可以退款', refundable_amount_fen: -1 }]} compact />)
    expect(screen.getByTestId('refund-verification-facts')).toHaveTextContent('核验状态未提供')
    expect(screen.getByTestId('refund-verification-facts')).toHaveTextContent('未提供')
    expect(screen.queryByText('已核验')).not.toBeInTheDocument()
  })
  it('does not display a compact verification strip when no record was returned', () => {
    render(<RefundVerificationFacts value={undefined} compact />)
    expect(screen.queryByTestId('refund-verification-facts')).not.toBeInTheDocument()
  })
  it('shows already processed and remaining funds from the snapshot without rewriting historical business facts', () => {
    render(<RefundVerificationFacts value={undefined} ticket={{ already_processed: true,
      transaction_remaining_fen: 0, original_transaction_id: 'transaction-original' }} compact />)
    expect(screen.getByTestId('refund-verification-facts')).toHaveTextContent('已处理')
    expect(screen.getByTestId('refund-verification-facts')).toHaveTextContent('交易剩余额')
    expect(screen.getByTestId('refund-verification-facts')).toHaveTextContent('0.00')
    expect(screen.queryByText('可办理')).not.toBeInTheDocument()
  })
})
