export function fenToYuan(value: number): string {
  if (!Number.isSafeInteger(value)) return '—'
  const amount = BigInt(value)
  const absolute = amount < 0n ? -amount : amount
  return `${amount < 0n ? '-' : ''}${absolute / 100n}.${String(absolute % 100n).padStart(2, '0')}`
}

export function yuanToFen(value: unknown): number {
  const text = typeof value === 'string' || typeof value === 'number' ? String(value) : ''
  if (!/^\d+(?:\.\d{1,2})?$/.test(text)) throw new Error('请输入非负金额，最多两位小数')
  const [whole, fraction = ''] = text.split('.')
  const amount = BigInt(whole) * 100n + BigInt(fraction.padEnd(2, '0'))
  if (amount > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('退款预算超出支持范围')
  return Number(amount)
}
