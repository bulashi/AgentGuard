import { useEffect, useState } from 'react'
import { App, Checkbox, Form, Input, InputNumber, Modal, Select } from 'antd'
import { Plus, Trash2 } from 'lucide-react'
import { api, ApiError } from '../api'
import type { BusinessCaseInput, BusinessCaseResult, BusinessFactsRecord, PaymentStatus } from '../api'
import { isBusinessIdentifier, isProtocolIdentifier } from '../businessIdentifiers'
import { fenToYuan, yuanToFen } from '../money'
import { LiquidGlassButton } from './LiquidGlassButton'

export interface BusinessCaseSeed {
  tenant_id: string
  customer_id: string
  business_facts?: BusinessFactsRecord
}

export interface BusinessCaseFormValues {
  tenant_id: string
  customer_id: string
  ticket_id: string
  order_id: string
  order_amount_yuan: string
  claim_text: string
  payments: Array<{ transaction_id: string; amount_yuan: string; status: PaymentStatus; refunded_amount_yuan: string }>
  cloud_shareable: boolean
}

function newIdentifier(prefix: string): string {
  return `${prefix}${Date.now().toString(36).toUpperCase()}${Math.random().toString(36).slice(2, 5).toUpperCase()}`
}

function initialValues(seed?: BusinessCaseSeed | null): BusinessCaseFormValues {
  const facts = seed?.business_facts
  return {
    tenant_id: seed?.tenant_id || 'tenant-A', customer_id: seed?.customer_id || 'customer-A',
    ticket_id: newIdentifier('T'), order_id: newIdentifier('O'),
    order_amount_yuan: facts ? fenToYuan(facts.order.amount_fen) : '70.00',
    claim_text: facts?.claim_text ?? '',
    payments: facts ? facts.payments.map((payment) => ({ transaction_id: newIdentifier('P'),
      amount_yuan: fenToYuan(payment.amount_fen), status: payment.status,
      refunded_amount_yuan: fenToYuan(payment.refunded_amount_fen) }))
      : [{ transaction_id: newIdentifier('P'), amount_yuan: '70.00', status: 'SUCCESS', refunded_amount_yuan: '0.00' }],
    cloud_shareable: false,
  }
}

export function businessCaseInput(values: BusinessCaseFormValues): BusinessCaseInput {
  if (!isBusinessIdentifier(values.tenant_id) || !isBusinessIdentifier(values.customer_id)) throw new Error('请输入有效的租户和客户')
  if (!isProtocolIdentifier(values.ticket_id) || !isProtocolIdentifier(values.order_id)) throw new Error('请输入有效的工单编号和订单编号')
  const orderAmount = yuanToFen(values.order_amount_yuan)
  if (orderAmount <= 0) throw new Error('订单应付金额必须大于 0 元')
  if (typeof values.claim_text !== 'string' || !values.claim_text.trim() || values.claim_text.length > 4000) throw new Error('请填写客户申诉，最多 4000 字')
  if (!Array.isArray(values.payments) || values.payments.length < 1 || values.payments.length > 8) throw new Error('请填写 1 至 8 笔支付流水')
  const identifiers = new Set<string>()
  const payments = values.payments.map((payment, index) => {
    const prefix = `第 ${index + 1} 笔流水：`
    if (!isProtocolIdentifier(payment.transaction_id)) throw new Error(`${prefix}请输入有效的流水编号`)
    if (identifiers.has(payment.transaction_id)) throw new Error('支付流水编号不能重复')
    identifiers.add(payment.transaction_id)
    if (!['SUCCESS', 'FAILED', 'PROCESSING'].includes(payment.status)) throw new Error(`${prefix}请选择支付状态`)
    const amount = yuanToFen(payment.amount_yuan)
    const refunded = yuanToFen(payment.refunded_amount_yuan)
    if (amount <= 0) throw new Error(`${prefix}支付金额必须大于 0 元`)
    if (refunded > amount) throw new Error(`${prefix}此前已退金额不能超过支付金额`)
    if (payment.status !== 'SUCCESS' && refunded !== 0) throw new Error(`${prefix}支付未成功，此前已退金额必须为 0 元`)
    return { transaction_id: payment.transaction_id, amount_fen: amount, status: payment.status, refunded_amount_fen: refunded }
  })
  const total = payments.reduce((sum, payment) => sum + BigInt(payment.amount_fen), 0n)
  if (total > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('支付金额合计超出支持范围')
  return { tenant_id: values.tenant_id, customer_id: values.customer_id, ticket_id: values.ticket_id,
    order_id: values.order_id, order_amount_fen: orderAmount, claim_text: values.claim_text,
    payments, cloud_shareable: values.cloud_shareable === true }
}

const identifierRule = { validator: (_: unknown, value: unknown) => isProtocolIdentifier(value)
  ? Promise.resolve() : Promise.reject(new Error('只能包含字母、数字和 . _ : -')) }
const businessIdentifierRule = { validator: (_: unknown, value: unknown) => isBusinessIdentifier(value)
  ? Promise.resolve() : Promise.reject(new Error('请输入中文、字母或数字，不可含空白')) }
const positiveMoneyRule = { validator: (_: unknown, value: unknown) => {
  try { if (yuanToFen(value) <= 0) throw new Error('金额必须大于 0 元'); return Promise.resolve() }
  catch (error) { return Promise.reject(error) }
} }
const moneyRule = { validator: (_: unknown, value: unknown) => {
  try { yuanToFen(value); return Promise.resolve() } catch (error) { return Promise.reject(error) }
} }

export function BusinessCaseForm({ open, seed, onCancel, onCreated }: {
  open: boolean
  seed?: BusinessCaseSeed | null
  onCancel: () => void
  onCreated: (result: BusinessCaseResult) => void
}) {
  const [form] = Form.useForm<BusinessCaseFormValues>()
  const [busy, setBusy] = useState(false)
  const { message } = App.useApp()
  useEffect(() => {
    if (!open) return
    form.resetFields()
    form.setFieldsValue(initialValues(seed))
  }, [form, open, seed])

  const create = async (values: BusinessCaseFormValues) => {
    if (busy) return
    let body: BusinessCaseInput
    try { body = businessCaseInput(values) } catch (error) {
      message.error(error instanceof Error ? error.message : '请检查订单和支付记录')
      return
    }
    setBusy(true)
    try {
      const result = await api.createBusinessCase(body)
      onCreated(result)
      message.success('业务工单已创建，请继续创建待授权任务')
    } catch (error) {
      message.error(error instanceof ApiError ? error.message : '业务工单创建失败，请稍后重试')
    } finally { setBusy(false) }
  }

  return <Modal open={open} title={seed?.business_facts ? '复制为新业务案例' : '新建业务工单'} width={720}
    onCancel={() => { if (!busy) onCancel() }} footer={null} destroyOnHidden maskClosable={!busy} closable={!busy}>
    <p className="detail-muted">填写订单、支付流水和客户申诉；办理结论由运行后的核验产生。</p>
    {seed?.business_facts ? <p className="detail-muted">已复制原始事实，并生成新的工单、订单和流水编号。保存后保留原记录。</p> : null}
    <Form name="business-case" form={form} layout="vertical" preserve={false} onFinish={create} disabled={busy}>
      <div className="form-grid">
        <Form.Item name="tenant_id" label="业务租户" rules={[{ required: true, message: '请输入租户' }, businessIdentifierRule]}><Input maxLength={128} /></Form.Item>
        <Form.Item name="customer_id" label="业务客户" rules={[{ required: true, message: '请输入客户' }, businessIdentifierRule]}><Input maxLength={128} /></Form.Item>
        <Form.Item name="ticket_id" label="新工单编号" rules={[{ required: true, message: '请输入工单编号' }, identifierRule]}><Input maxLength={128} /></Form.Item>
        <Form.Item name="order_id" label="订单编号" rules={[{ required: true, message: '请输入订单编号' }, identifierRule]}><Input maxLength={128} /></Form.Item>
        <Form.Item name="order_amount_yuan" label="订单应付金额（元）" rules={[{ required: true, message: '请输入订单应付金额' }, positiveMoneyRule]}>
          <InputNumber stringMode min="0.01" step="0.01" className="full-width" />
        </Form.Item>
      </div>
      <Form.Item name="claim_text" label="客户申诉" rules={[{ required: true, whitespace: true, message: '请填写客户申诉' }, { max: 4000, message: '客户申诉最多 4000 字' }]}>
        <Input.TextArea rows={3} maxLength={4000} placeholder="例如：我怀疑这笔订单被重复扣款，请核对支付记录。" />
      </Form.Item>
      <Form.List name="payments" rules={[{ validator: (_, values) => Array.isArray(values) && values.length >= 1 && values.length <= 8
        ? Promise.resolve() : Promise.reject(new Error('请填写 1 至 8 笔支付流水')) }]}>
        {(rows, { add, remove }, { errors }) => <>
          <h3>支付流水</h3>
          {rows.map((row, index) => <section className="refund-verification-row" key={row.key} aria-label={`支付流水 ${index + 1}`}>
            <div className="form-grid">
              <Form.Item name={[row.name, 'transaction_id']} label={`流水编号 ${index + 1}`} rules={[{ required: true, message: '请输入流水编号' }, identifierRule]}><Input maxLength={128} /></Form.Item>
              <Form.Item name={[row.name, 'status']} label={`支付状态 ${index + 1}`} rules={[{ required: true, message: '请选择支付状态' }]}>
                <Select className="record-select" placeholder="选择实际支付状态" virtual={false} classNames={{ popup: { root: 'record-select-dropdown' } }} options={[
                  { value: 'SUCCESS', label: '支付成功' }, { value: 'FAILED', label: '支付失败' }, { value: 'PROCESSING', label: '支付处理中' },
                ]} />
              </Form.Item>
              <Form.Item name={[row.name, 'amount_yuan']} label={`支付金额 ${index + 1}（元）`} rules={[{ required: true, message: '请输入支付金额' }, positiveMoneyRule]}>
                <InputNumber stringMode min="0.01" step="0.01" className="full-width" />
              </Form.Item>
              <Form.Item name={[row.name, 'refunded_amount_yuan']} label={`此前已退金额 ${index + 1}（元）`} rules={[{ required: true, message: '请输入此前已退金额' }, moneyRule]}>
                <InputNumber stringMode min="0" step="0.01" className="full-width" />
              </Form.Item>
            </div>
            <LiquidGlassButton icon={<Trash2 size={14} />} disabled={busy || rows.length === 1} onClick={() => remove(row.name)} aria-label={`删除支付流水 ${index + 1}`}>删除流水</LiquidGlassButton>
          </section>)}
          <Form.ErrorList errors={errors} />
          <LiquidGlassButton icon={<Plus size={14} />} disabled={busy || rows.length >= 8}
            onClick={() => add({ transaction_id: newIdentifier('P'), amount_yuan: form.getFieldValue('order_amount_yuan'), refunded_amount_yuan: '0.00' })}>增加支付流水</LiquidGlassButton>
        </>}
      </Form.List>
      <Form.Item name="cloud_shareable" valuePropName="checked" style={{ marginTop: 20 }}>
        <Checkbox>合成资料可用于云端演示</Checkbox>
      </Form.Item>
      <div className="modal-actions"><LiquidGlassButton disabled={busy} onClick={onCancel}>取消</LiquidGlassButton>
        <LiquidGlassButton type="primary" htmlType="submit" icon={<Plus size={16} />} loading={busy}>保存业务工单</LiquidGlassButton></div>
    </Form>
  </Modal>
}
