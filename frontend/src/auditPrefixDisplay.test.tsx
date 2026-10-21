import { render, screen, within } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { AuditEvidence } from './sections/AuditEvidence'
import { EvidenceDrawer } from './components/EvidenceDrawer'
import { savedSnapshot } from './test/fixtures'
import { mockAuditPrefixReport } from './test/auditPrefixFixtures'

const event = savedSnapshot.audit_events[0]
const mockReport = mockAuditPrefixReport(event)

describe('task-bound audit prefix rendering with synthetic server reports', () => {
  it('shows the same exact checkpoint in the table and event details, even without overview', async () => {
    render(<>
      <AuditEvidence snapshot={savedSnapshot} overview={null} auditPrefix={mockReport} />
      <EvidenceDrawer selection={{ kind: 'audit', event }} snapshot={savedSnapshot} overview={null}
        auditPrefix={mockReport} onSelect={vi.fn()} onClose={vi.fn()} />
    </>)
    const table = screen.getByTestId('audit-evidence')
    expect(within(table).getByLabelText('服务端核验：已覆盖（ANCHORED）')).toBeInTheDocument()
    const details = await screen.findByTestId('evidence-detail')
    expect(within(details).getByLabelText('服务端核验：已覆盖（ANCHORED）')).toBeInTheDocument()
    expect(JSON.parse(within(details).getByTestId('verified-checkpoint-json').textContent ?? 'null'))
      .toEqual(mockReport.checkpoint?.signed_checkpoint)
    expect(within(details).getByText(/非浏览器独立验签/)).toBeInTheDocument()
  })

  it('removes positive coverage when a same-sequence projection field changes', () => {
    const changed = { ...event, timestamp: event.timestamp + 2 }
    render(<AuditEvidence snapshot={{ ...savedSnapshot, audit_events: [changed] }} overview={null} auditPrefix={mockReport} />)
    expect(screen.queryByLabelText(/（ANCHORED）/)).not.toBeInTheDocument()
    expect(screen.getByLabelText('逐事件覆盖未核验（NOT_CHECKED）')).toBeInTheDocument()
  })

  it('does not substitute a task-mismatched report for a missing one', () => {
    render(<AuditEvidence snapshot={savedSnapshot} overview={null} auditPrefix={{ ...mockReport, task_id: 'TASK-other' }} />)
    expect(screen.queryByLabelText(/（ANCHORED）/)).not.toBeInTheDocument()
    expect(screen.getByLabelText('逐事件覆盖未核验（NOT_CHECKED）')).toBeInTheDocument()
  })
})
