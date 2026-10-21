import type { ReactNode } from 'react'

export function SectionHeader({
  title,
  status,
  actions,
}: {
  title: string
  status?: ReactNode
  actions?: ReactNode
}) {
  return (
    <div className="section-header">
      <div className="section-heading-row">
        <h1>{title}</h1>
        {status}
      </div>
      {actions ? <div className="section-actions">{actions}</div> : null}
    </div>
  )
}
