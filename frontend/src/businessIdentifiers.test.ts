import { describe, expect, it } from 'vitest'
import { isBusinessIdentifier, isProtocolIdentifier } from './businessIdentifiers'

describe('Chinese tenant and customer identifiers', () => {
  it.each(['演示企业', '张三', '公司（华东）', '公司(华东)', '张三·测试', '客户-C9527', 'tenant-A'])('keeps exact business text %s', (value) => {
    expect(isBusinessIdentifier(value)).toBe(true)
  })
  it.each(['', ' 张三', '张三 ', '张 三', '张三\n', '张三\r', '张三\0', '张\u200b三', '张\u202e三', '张三/四', '<script>', '张'.repeat(129)])('rejects unsafe or ambiguous business text %j', (value) => {
    expect(isBusinessIdentifier(value)).toBe(false)
  })
  it('never widens protocol identities', () => {
    expect(isProtocolIdentifier('中文任务')).toBe(false)
    expect(isProtocolIdentifier('TASK-123')).toBe(true)
  })
})
