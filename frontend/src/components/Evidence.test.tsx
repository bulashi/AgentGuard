import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { BooleanTag, ShortHash, StatusTag, TimeValue } from './Evidence'

describe('evidence primitives', () => {
  it('does not treat an epoch-zero timestamp as an absent value', () => {
    render(<TimeValue value={0} />)
    expect(screen.queryByText('无')).not.toBeInTheDocument()
    expect(screen.getByText(new Date(0).toLocaleString('zh-CN', { hour12: false }))).toBeInTheDocument()
  })

  it('does not treat a truthy nonboolean validity marker as true', () => {
    render(<BooleanTag value={'true' as unknown as boolean} />)
    expect(screen.getByText('无效')).toBeInTheDocument()
    expect(screen.queryByText('有效')).not.toBeInTheDocument()
  })

  it('keeps valid and denied evidence visually distinct', () => {
    render(<><StatusTag value="ALLOW" /><StatusTag value="DENY" /><BooleanTag value /></>)
    expect(screen.getByText('允许')).toBeInTheDocument()
    expect(screen.getByText('拒绝')).toBeInTheDocument()
    expect(screen.getByText('有效')).toBeInTheDocument()
  })

  it('does not discard the full hash from copy evidence', () => {
    const hash = 'a'.repeat(64)
    render(<ShortHash value={hash} size={6} />)
    expect(screen.getByText(/aaaaaa…aaaaaa/)).toBeInTheDocument()
    expect(screen.getByText(/aaaaaa…aaaaaa/)).toHaveAttribute('title', hash)
  })
  it('keeps hash hints without nesting a copy button inside a clickable record', () => {
    const hash = 'b'.repeat(64)
    const { container } = render(<button type="button"><ShortHash value={hash} size={6} copyable={false} /></button>)
    expect(container.querySelectorAll('button')).toHaveLength(1)
    expect(screen.getByText(/bbbbbb…bbbbbb/)).toHaveAttribute('title', hash)
  })
})
