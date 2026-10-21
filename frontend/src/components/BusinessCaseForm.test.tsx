import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { App as AntApp } from 'antd'
import { describe, expect, it, vi } from 'vitest'
import { api, ApiError } from '../api'
import type { BusinessFactsRecord } from '../api'
import { BusinessCaseForm, businessCaseInput } from './BusinessCaseForm'
import type { BusinessCaseFormValues } from './BusinessCaseForm'

const facts: BusinessFactsRecord = { schema_version: '1.0', order: { order_id: 'O-original', amount_fen: 7000, currency: 'CNY' },
  payments: [{ transaction_id: 'P-original', amount_fen: 7000, status: 'SUCCESS', refunded_amount_fen: 123 }], claim_text: '请核对是否重复扣款。' }
const values: BusinessCaseFormValues = { tenant_id: '企业甲', customer_id: '客户甲', ticket_id: 'T-new', order_id: 'O-new',
  order_amount_yuan: '70.00', claim_text: facts.claim_text,
  payments: [{ transaction_id: 'P-one', amount_yuan: '70.00', status: 'SUCCESS', refunded_amount_yuan: '0.00' }], cloud_shareable: false }

describe('business case raw facts', () => {
  it('sends exact integer cents and only facts, without an eligibility answer', () => {
    const result = businessCaseInput({ ...values, order_amount_yuan: '1.23', payments: [{ ...values.payments[0], amount_yuan: '1.23', refunded_amount_yuan: '0.01' }] })
    expect(result.order_amount_fen).toBe(123)
    expect(result.payments[0]).toEqual({ transaction_id: 'P-one', amount_fen: 123, status: 'SUCCESS', refunded_amount_fen: 1 })
    expect(Object.keys(result).sort()).toEqual(['claim_text', 'cloud_shareable', 'customer_id', 'order_amount_fen', 'order_id', 'payments', 'tenant_id', 'ticket_id'])
  })
  it.each([
    ['70.001', '最多两位小数'], ['90071992547409.92', '超出支持范围'], ['0.00', '大于 0'],
  ])('rejects invalid order money %s before submitting', (amount, expected) => {
    expect(() => businessCaseInput({ ...values, order_amount_yuan: amount })).toThrow(expected)
  })
  it.each(['FAILED', 'PROCESSING'] as const)('does not permit prior refunds on a %s payment', (status) => {
    expect(() => businessCaseInput({ ...values, payments: [{ ...values.payments[0], status, refunded_amount_yuan: '0.01' }] })).toThrow('此前已退金额必须为 0 元')
  })
  it('rejects a refund balance larger than the successful payment and duplicate evidence IDs', () => {
    expect(() => businessCaseInput({ ...values, payments: [{ ...values.payments[0], refunded_amount_yuan: '70.01' }] })).toThrow('不能超过支付金额')
    expect(() => businessCaseInput({ ...values, payments: [values.payments[0], values.payments[0]] })).toThrow('支付流水编号不能重复')
  })
  it('rejects no payments, more than eight payments, and a total exceeding safe integer precision', () => {
    expect(() => businessCaseInput({ ...values, payments: [] })).toThrow('1 至 8')
    expect(() => businessCaseInput({ ...values, payments: Array.from({ length: 9 }, (_, index) => ({ ...values.payments[0], transaction_id: `P${index}` })) })).toThrow('1 至 8')
    expect(() => businessCaseInput({ ...values, payments: [{ ...values.payments[0], amount_yuan: '90071992547409.91' }, { ...values.payments[0], transaction_id: 'P-two' }] })).toThrow('金额合计超出支持范围')
  })
})

describe('BusinessCaseForm', () => {
  it('starts with one payment and requires an explicit status on an additional payment', async () => {
    render(<AntApp><BusinessCaseForm open onCancel={vi.fn()} onCreated={vi.fn()} /></AntApp>)
    await waitFor(() => expect(screen.getByLabelText('订单应付金额（元）')).toHaveValue('70.00'))
    expect(screen.getByRole('region', { name: '支付流水 1' })).toHaveTextContent('支付成功')
    expect(screen.getByRole('button', { name: '删除支付流水 1' })).toBeDisabled()
    fireEvent.click(screen.getByRole('button', { name: '增加支付流水' }))
    expect(screen.getByRole('region', { name: '支付流水 2' })).toHaveTextContent('选择实际支付状态')
    expect(screen.queryByLabelText('业务核验状态')).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '删除支付流水 2' }))
    expect(screen.queryByRole('region', { name: '支付流水 2' })).not.toBeInTheDocument()
  })
  it('submits a created business case separately and defaults cloud sharing to off', async () => {
    const result = { ticket_id: 'T-created', tenant_id: 'tenant-A', customer_id: 'customer-A', facts_hash: 'facts-hash', business_facts: facts }
    const create = vi.spyOn(api, 'createBusinessCase').mockResolvedValue(result)
    const onCreated = vi.fn()
    try {
      render(<AntApp><BusinessCaseForm open onCancel={vi.fn()} onCreated={onCreated} /></AntApp>)
      await waitFor(() => expect(screen.getByLabelText('业务租户')).toHaveValue('tenant-A'))
      fireEvent.change(screen.getByLabelText('客户申诉'), { target: { value: '同一订单有两次支付，请核对。' } })
      fireEvent.change(screen.getByLabelText('订单应付金额（元）'), { target: { value: '1.23' } })
      fireEvent.click(screen.getByRole('button', { name: '保存业务工单' }))
      await waitFor(() => expect(onCreated).toHaveBeenCalledWith(result))
      expect(create).toHaveBeenCalledWith(expect.objectContaining({ order_amount_fen: 123, cloud_shareable: false, claim_text: '同一订单有两次支付，请核对。' }))
      expect(create.mock.calls[0][0]).not.toHaveProperty('verification_status')
      expect(await screen.findByText('业务工单已创建，请继续创建待授权任务')).toBeInTheDocument()
    } finally { create.mockRestore() }
  })
  it('copies original facts but gives the new case new IDs and independent cloud consent', async () => {
    render(<AntApp><BusinessCaseForm open seed={{ tenant_id: 'tenant-Z', customer_id: 'customer-Z', business_facts: facts }} onCancel={vi.fn()} onCreated={vi.fn()} /></AntApp>)
    await waitFor(() => expect(screen.getByLabelText('业务租户')).toHaveValue('tenant-Z'))
    expect((screen.getByLabelText('新工单编号') as HTMLInputElement).value).toMatch(/^T/)
    expect(screen.getByLabelText('订单编号')).not.toHaveValue('O-original')
    expect(screen.getByLabelText('流水编号 1')).not.toHaveValue('P-original')
    expect(screen.getByLabelText('订单应付金额（元）')).toHaveValue('70.00')
    expect(screen.getByLabelText('此前已退金额 1（元）')).toHaveValue('1.23')
    expect(screen.getByLabelText('客户申诉')).toHaveValue(facts.claim_text)
    expect(screen.getByRole('checkbox', { name: '合成资料可用于云端演示' })).not.toBeChecked()
  })
  it('keeps invalid or conflicting server input available for correction', async () => {
    const create = vi.spyOn(api, 'createBusinessCase').mockRejectedValue(new ApiError(409, 'BUSINESS_CASE_CONFLICT', '工单编号已存在，请换一个编号'))
    const onCreated = vi.fn()
    try {
      render(<AntApp><BusinessCaseForm open onCancel={vi.fn()} onCreated={onCreated} /></AntApp>)
      await waitFor(() => expect(screen.getByLabelText('业务租户')).toHaveValue('tenant-A'))
      fireEvent.change(screen.getByLabelText('客户申诉'), { target: { value: '请核对支付。' } })
      fireEvent.click(screen.getByRole('button', { name: '保存业务工单' }))
      expect(await screen.findByText('工单编号已存在，请换一个编号')).toBeInTheDocument()
      expect(onCreated).not.toHaveBeenCalled()
      expect(screen.getByLabelText('客户申诉')).toHaveValue('请核对支付。')
    } finally { create.mockRestore() }
  })
})
