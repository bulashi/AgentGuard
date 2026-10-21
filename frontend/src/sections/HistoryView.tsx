import { CustomerName } from '../components/CustomerName'
import { useEffect, useState } from 'react'
import { Alert, Empty, Input, Select, Table, Tooltip } from 'antd'
import { ArrowUpRight, ChevronDown, Clock3, RefreshCw, Search } from 'lucide-react'
import { api, ApiError } from '../api'
import { Fen, ShortHash, StatusTag, TimeValue } from '../components/Evidence'
import { LiquidGlassButton } from '../components/LiquidGlassButton'
import { WorkflowStatusTag } from '../components/WorkflowStatusTag'
import type { TaskSummary } from '../types'
import { modelDisplayLabel, MODE_LABELS } from '../workflowModel'
import { reasonLabel } from '../labels'

export function HistoryView({ tasks, selectedTaskId, onSelect }: {
  tasks: TaskSummary[]; selectedTaskId: string | null; onSelect: (taskId: string) => void
}) {
  const businessResult = (record: TaskSummary) => {
    if (record.business_verification_status === 'REJECTED' || record.business_payment_verification_status === 'REJECTED') {
      return { value: 'BUSINESS_STOPPED', label: '退款未执行 · 业务核验未通过' }
    }
    if ((record.refund_count ?? 0) > 0) {
      return { value: 'COMPLETED', label: `退款已提交${(record.notification_count ?? 0) > 0 ? ` · 通知已发送 ${record.notification_count} 条` : ' · 通知未发送'}` }
    }
    if (record.workflow_state) return null
    return { value: 'NOT_RECORDED', label: '尚未建立协作记录 · 请打开任务查看结果' }
  }
  const [items, setItems] = useState(tasks)
  const [query, setQuery] = useState('')
  const [search, setSearch] = useState('')
  const [status, setStatus] = useState('all')
  const [loading, setLoading] = useState(false)
  const [hasMore, setHasMore] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [revision, setRevision] = useState(0)
  const [offset, setOffset] = useState(0)
  useEffect(() => {
    if (query === search) return
    const timer = window.setTimeout(() => { setSearch(query); setOffset(0) }, 300)
    return () => window.clearTimeout(timer)
  }, [query, search])
  useEffect(() => {
    let active = true
    setLoading(true); setError(null)
    api.tasks({ offset, search, status: status === 'all' ? '' : status }).then((result) => {
      if (!active) return
      setItems((previous) => offset ? [...previous, ...result.items.filter((item) => !previous.some((old) => old.task_id === item.task_id))] : result.items)
      setHasMore(result.has_more ?? result.items.length === 40)
    }).catch((failure: unknown) => {
      if (active) setError(failure instanceof ApiError ? `${reasonLabel(failure.reasonCode)}：${failure.message}` : '历史记录读取失败')
    }).finally(() => { if (active) setLoading(false) })
    return () => { active = false }
  }, [offset, search, status, revision])
  return <section className="history-view" data-testid="history-view">
    <div className="workspace-toolbar"><div className="workspace-heading"><span className="page-eyebrow">运行档案</span><h1>历史记录</h1></div>
      <Tooltip title="刷新历史记录"><LiquidGlassButton icon={<RefreshCw size={16} />} aria-label="刷新历史记录" onClick={() => { setOffset(0); setRevision((value) => value + 1) }} loading={loading} /></Tooltip>
    </div>
    <div className="history-controls"><Input value={query} onChange={(event) => setQuery(event.target.value)} prefix={<Search size={16} />} allowClear
      placeholder="搜索工单、客户或任务编号" aria-label="搜索历史记录" maxLength={200} className="history-search" />
      <Select value={status} onChange={(value) => { setStatus(value); setOffset(0) }} aria-label="历史任务状态"
        options={[{ value: 'all', label: '全部根授权状态' }, { value: 'AUTHORIZED', label: '根授权已签发' }, { value: 'PENDING_AUTHORIZATION', label: '待签发根授权' }, { value: 'REVOKED', label: '根授权已撤销' }]} />
      <span className="history-count"><Clock3 size={14} />已加载 {items.length} 条</span>
    </div>
    {error ? <Alert showIcon type="error" message={error} className="history-error" /> : null}
    <div className="history-table">
      <Table<TaskSummary> rowKey="task_id" dataSource={items} loading={loading} size="middle" scroll={{ x: 920 }}
        pagination={{ pageSize: 10, showSizeChanger: false, hideOnSinglePage: true }}
        locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="没有匹配的历史记录" /> }}
        rowClassName={(record) => record.task_id === selectedTaskId ? 'selected-row interactive-row' : 'interactive-row'}
        onRow={(record) => ({ onClick: () => onSelect(record.task_id) })}
        columns={[
          { title: '业务任务', key: 'task', width: 240, render: (_, record) => <button type="button" className="history-task-link" data-testid={`history-task-${record.task_id}`}
            onClick={(event) => { event.stopPropagation(); onSelect(record.task_id) }}><strong>{record.ticket_id} / <CustomerName id={record.customer_id} /></strong><small className="mono">{record.task_id}</small></button> },
          { title: '根授权状态', dataIndex: 'status', width: 145, render: (value: string) => <StatusTag value={value} label={value === 'AUTHORIZED' ? '根授权已签发' : undefined} /> },
          { title: '退款业务结果', key: 'workflow', width: 250, render: (_, record) => <div>{businessResult(record) ? <StatusTag {...businessResult(record)!} /> : <WorkflowStatusTag state={record.workflow_state ?? 'NOT_RECORDED'} reasonCode={record.workflow_reason_code} />}
            {record.runtime_mode ? <div className="table-secondary">{MODE_LABELS[record.runtime_mode]}{record.model ? ` / ${modelDisplayLabel(record.model)}` : ''}</div> : null}</div> },
          { title: '退款上限', dataIndex: 'refund_total_fen', width: 125, render: (value: number) => <Fen value={value} /> },
          { title: '凭证 / 工具请求', key: 'counts', width: 145, render: (_, record) => <span className="history-numeric">{record.credential_count} / {record.execution_count}</span> },
          { title: '创建时间', dataIndex: 'created_at', width: 180, render: (value: number) => <TimeValue value={value} /> },
          { title: '租户', dataIndex: 'tenant_id', width: 100, render: (value: string) => <ShortHash value={value} size={6} /> },
          { title: '', key: 'open', width: 50, render: (_, record) => <Tooltip title="打开运行与完整记录"><LiquidGlassButton size="small" icon={<ArrowUpRight size={16} />} aria-label={`打开任务 ${record.task_id}`}
            onClick={(event) => { event.stopPropagation(); onSelect(record.task_id) }} /></Tooltip> },
        ]} />
    </div>
    <div className="history-load-more"><LiquidGlassButton icon={<ChevronDown size={15} />} onClick={() => setOffset((value) => value + 40)} disabled={!hasMore || Boolean(error) || loading} loading={loading}>加载更早记录</LiquidGlassButton>
      {!hasMore ? <span>已到最早记录</span> : null}</div>
  </section>
}
