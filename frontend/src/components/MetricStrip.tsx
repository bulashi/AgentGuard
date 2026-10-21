import type { ReactNode } from 'react'

export function MetricStrip({ items }: { items: Array<{ label: string; value: ReactNode }> }) {
  return (
    <div className="metric-strip">
      {items.map((item) => (
        <div className="metric-item" key={item.label}>
          <span className="metric-label">{item.label}</span>
          <strong>{item.value}</strong>
        </div>
      ))}
    </div>
  )
}
