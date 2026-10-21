import { describe, expect, it } from 'vitest'
import names from './customerDisplayNames.json'
import { customerLabel } from './customerDisplay'

describe('customer display aliases', () => {
  it('keeps each prepared alias fixed independently of page, ordering or refresh', () => {
    const entries = Object.entries(names)
    expect(new Set(entries.map(([, label]) => label)).size).toBe(entries.length)
    for (const [id, label] of entries.reverse()) {
      expect(customerLabel(id)).toBe(label)
      expect(customerLabel(id)).toMatch(/^客户-[A-Z]+$/)
    }
  })
  it('retains readable business names and uses a stable short label for a new long identifier', () => {
    expect(customerLabel('张三')).toBe('张三')
    expect(customerLabel('C9593')).toBe('C9593')
    expect(customerLabel('C-12345678901234567890123456789012')).toBe('客户-12345678')
  })
})
