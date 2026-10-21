import { describe, expect, it } from 'vitest'
import { fenToYuan, yuanToFen } from './money'

describe('yuan input and integer-fen authorization', () => {
  it.each([['70.00', 7000], ['1.23', 123], ['0.29', 29], ['0.01', 1], ['0', 0], ['90071992547409.91', Number.MAX_SAFE_INTEGER]])(
    'converts %s yuan exactly into %s fen and back', (yuan, fen) => {
      expect(yuanToFen(yuan)).toBe(fen)
      expect(yuanToFen(fenToYuan(fen))).toBe(fen)
    },
  )
  it.each(['-1', '1.234', 'NaN', 'Infinity', '1e3', '90071992547409.92', '', null])(
    'rejects invalid or overflowing amount %s', (input) => expect(() => yuanToFen(input)).toThrow(),
  )
})
