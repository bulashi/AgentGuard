export function isBusinessIdentifier(value: unknown): value is string {
  return typeof value === 'string' && value.length >= 1 && value.length <= 128
    && /^[A-Za-z0-9\u3007\u3400-\u4dbf\u4e00-\u9fff]/u.test(value)
    && !/[^A-Za-z0-9\u3007\u3400-\u4dbf\u4e00-\u9fff._:()\u00b7\uff08\uff09-]/u.test(value)
}

export function isProtocolIdentifier(value: unknown): value is string {
  return typeof value === 'string' && value.length >= 1 && value.length <= 128
    && /^[A-Za-z0-9]/.test(value) && !/[^A-Za-z0-9._:-]/.test(value)
}
