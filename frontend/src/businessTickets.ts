import type { BusinessTicket } from './api'

export function businessTicketKey(ticket: BusinessTicket): string {
  return JSON.stringify([ticket.tenant_id, ticket.ticket_id])
}

export function ticketCanRefund(ticket: BusinessTicket): boolean {
  return ticket.can_refund === true && ticket.verification_status === 'VERIFIED'
    && ticket.payment_verification_status === 'VERIFIED' && ticket.already_processed === false
    && ticket.in_progress === false && Number.isSafeInteger(ticket.transaction_remaining_fen)
    && Number(ticket.transaction_remaining_fen) > 0
}

export function ticketBusinessStatus(ticket: BusinessTicket): string {
  if (ticket.already_processed === true) return '已处理'
  if (ticket.in_progress === true) return '办理中'
  if (ticket.source === 'facts' || ticket.business_facts) {
    if (!ticket.business_verification) return '待运行核验'
    if (ticket.business_verification.status === 'REJECTED') return '不符合办理条件'
    if (ticket.business_verification.status === 'PENDING') return '资料待核验'
    if (ticket.business_verification.status === 'VERIFIED') return '核验通过'
  }
  if (ticket.verification_status === 'REJECTED' || ticket.payment_verification_status === 'REJECTED') return '不符合办理条件'
  if (ticket.verification_status !== 'VERIFIED' || ticket.payment_verification_status !== 'VERIFIED') return '资料待核验'
  if (ticketCanRefund(ticket)) return '可办理'
  if (ticket.transaction_remaining_fen === 0) return '无可退余额'
  return '暂不可办理'
}
