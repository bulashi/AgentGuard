import { describe, expect, it } from 'vitest'
import type { BusinessTicket } from './api'
import { businessTicketKey, ticketBusinessStatus, ticketCanRefund } from './businessTickets'

const ticket: BusinessTicket = { tenant_id: '企业甲', ticket_id: 'T20001', customer_id: '客户甲', title: '重复扣款',
  verification_status: 'VERIFIED', payment_verification_status: 'VERIFIED', transaction_remaining_fen: 7000,
  refundable_amount_fen: 7000, can_refund: true, already_processed: false, in_progress: false }

describe('ticket eligibility projection', () => {
  it('keeps a raw business case unresolved until a trusted task evaluation is available', () => {
    expect(ticketBusinessStatus({ ...ticket, source: 'facts', business_verification: null })).toBe('待运行核验')
    expect(ticketBusinessStatus({ ...ticket, source: 'facts', business_verification: { status: 'REJECTED' } as BusinessTicket['business_verification'] })).toBe('不符合办理条件')
    expect(ticketBusinessStatus({ ...ticket, source: 'facts', business_verification: { status: 'PENDING' } as BusinessTicket['business_verification'] })).toBe('资料待核验')
    expect(ticketBusinessStatus({ ...ticket, source: 'facts', business_verification: { status: 'VERIFIED' } as BusinessTicket['business_verification'] })).toBe('核验通过')
  })
  it('distinguishes the same ticket identifier across tenants', () => {
    expect(businessTicketKey(ticket)).not.toBe(businessTicketKey({ ...ticket, tenant_id: '企业乙' }))
  })
  it('accepts only affirmative structured eligibility facts', () => {
    expect(ticketCanRefund(ticket)).toBe(true)
    expect(ticketBusinessStatus(ticket)).toBe('可办理')
  })
  it.each([
    [{ already_processed: true }, '已处理'], [{ in_progress: true }, '办理中'],
    [{ verification_status: 'PENDING' }, '资料待核验'], [{ payment_verification_status: 'UNKNOWN' }, '资料待核验'],
    [{ payment_verification_status: 'REJECTED' }, '不符合办理条件'], [{ transaction_remaining_fen: 0 }, '无可退余额'],
    [{ can_refund: false }, '暂不可办理'], [{ can_refund: undefined }, '暂不可办理'],
    [{ transaction_remaining_fen: -1 }, '暂不可办理'], [{ already_processed: undefined }, '暂不可办理'],
  ] as const)('does not treat a noneligible or incomplete record as refundable: %j', (change, label) => {
    const value = { ...ticket, ...change }
    expect(ticketCanRefund(value)).toBe(false)
    expect(ticketBusinessStatus(value)).toBe(label)
  })
})
