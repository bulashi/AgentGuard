import { useMemo, useState } from 'react'
import { Empty, Input, Select, Table } from 'antd'
import { ArrowUpRight, Search } from 'lucide-react'
import { Fen, ShortHash, StatusTag, TimeValue } from '../components/Evidence'
import { LiquidGlassButton } from '../components/LiquidGlassButton'
import { reasonLabel, toolLabel } from '../labels'
import type { EvidenceSelection } from '../executionModel'
import type { ExecutionView, TaskSnapshot } from '../types'
import { RequestEvidencePanel } from '../components/RequestEvidencePanel'
import { activeWorkflow } from '../workflowModel'

export function ExecutionRecords({ snapshot, onInspect }: { snapshot: TaskSnapshot | null; onInspect: (selection: EvidenceSelection) => void }) {
  const [query, setQuery] = useState('')
  const [decision, setDecision] = useState('all')
  const records = useMemo(() => (snapshot?.executions ?? []).filter((item) =>
    (decision === 'all' || item.decision === decision)
    && `${toolLabel(item.tool_name)} ${item.tool_name} ${item.execution_id} ${item.reason_code ?? ''} ${reasonLabel(item.reason_code ?? '')}`.toLowerCase().includes(query.trim().toLowerCase())), [decision, query, snapshot])
  const run = activeWorkflow(snapshot)
  return <section className="execution-records" data-testid="execution-records">
    <div className="record-filters"><Input prefix={<Search size={17} />} placeholder="搜索工具、执行编号或原因" aria-label="搜索执行记录" value={query} onChange={(event) => setQuery(event.target.value)} allowClear />
      <Select value={decision} onChange={setDecision} aria-label="筛选网关裁决" options={[{ value: 'all', label: '全部裁决' }, { value: 'ALLOW', label: '允许' }, { value: 'DENY', label: '拒绝' }]} /><span>{records.length} 笔记录</span></div>
    <Table<ExecutionView> rowKey="execution_id" dataSource={records} size="middle" scroll={{ x: 860 }} pagination={{ pageSize: 10, showSizeChanger: false, hideOnSinglePage: true }}
      onRow={(execution) => ({ className: 'interactive-row', onClick: () => onInspect({ kind: 'execution', execution }) })}
      locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无匹配执行记录" /> }}
      columns={[
        { title: '工具请求', width: 210, render: (_, item) => <div><strong>{toolLabel(item.tool_name)}</strong><div className="table-secondary mono">{item.tool_name}</div></div> },
        { title: '网关裁决', dataIndex: 'decision', width: 110, render: (value: string | null) => <StatusTag value={value} /> },
        { title: '执行结果', dataIndex: 'state', width: 115, render: (value: string) => <StatusTag value={value} /> },
        { title: '业务记录', width: 150, render: (_, item) => {
          const refund = snapshot?.business_effects.refunds.find((effect) => effect.execution_id === item.execution_id)
          const notice = snapshot?.business_effects.notifications.find((effect) => effect.execution_id === item.execution_id)
          return refund ? <Fen value={refund.amount_fen} /> : notice ? '通知已记录' : item.business_effect_id ? '结果已关联' : '无副作用'
        } },
        { title: '执行编号', dataIndex: 'execution_id', width: 170, render: (value: string) => <ShortHash value={value} size={7} /> },
        { title: '时间', dataIndex: 'created_at', width: 180, render: (value: number) => <TimeValue value={value} /> },
        { title: '', width: 50, render: (_, execution) => <LiquidGlassButton size="small" icon={<ArrowUpRight size={15} />} aria-label={`查看执行 ${execution.execution_id}`} onClick={(event) => { event.stopPropagation(); onInspect({ kind: 'execution', execution }) }} /> },
      ]} />
    <details className="record-comparison"><summary>单笔请求与授权范围</summary><RequestEvidencePanel snapshot={snapshot} run={run} events={run?.events ?? []} replay={false} onInspect={onInspect} /></details>
  </section>
}
