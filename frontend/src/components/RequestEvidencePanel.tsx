import { useEffect, useMemo, useState } from 'react'
import type { ReactNode } from 'react'
import { Empty, Select, Tooltip } from 'antd'
import { ArrowRight, ArrowUpRight, Clock3, FileCheck2, FileText, ShieldCheck, ShieldX, WalletCards } from 'lucide-react'
import type { EvidenceSelection } from '../executionModel'
import { agentLabel, reasonLabel, statusLabel, toolLabel } from '../labels'
import { publicObject, requestEvidenceForRun } from '../requestEvidence'
import type { RequestEvidence } from '../requestEvidence'
import type { TaskSnapshot, WorkflowEvent, WorkflowRun } from '../types'
import { Fen, ShortHash, StatusTag } from './Evidence'
import { LiquidGlassButton } from './LiquidGlassButton'
import { observeReceipt } from '../sourceVerification'

const FIELD_LABELS: Record<string, string> = {
  ticket_id: '工单', customer_id: '客户', amount_fen: '金额', template_id: '通知模板', related_business_effect_id: '关联业务副作用',
}

function Value({ value, field }: { value: unknown; field: string }) {
  if (field === 'amount_fen' && typeof value === 'number') return <Fen value={value} />
  if (value == null) return <>未记录</>
  if (Array.isArray(value)) return <>{value.join('、')}</>
  return <>{typeof value === 'object' ? JSON.stringify(value) : String(value)}</>
}

function Parameters({ entry, snapshot }: { entry: RequestEvidence; snapshot: TaskSnapshot }) {
  const parameters = publicObject(entry.request?.details.parameters)
  const ids = entry.request?.details.credential_ids
  const leafId = Array.isArray(ids) ? ids[ids.length - 1] : null
  const credential = snapshot.credentials.find((item) => item.credential_id === leafId)
  const capability = credential?.capabilities.find((item) => item.tool === entry.tool
    && (typeof entry.request?.details.tool_service !== 'string' || item.service === entry.request.details.tool_service)
    && (typeof entry.request?.details.tool_version !== 'string' || item.version === entry.request.details.tool_version)
    && (!entry.execution || item.service === entry.execution.tool_service && item.version === entry.execution.tool_version))
  const projected = capability?.resources !== undefined && capability.constraints !== undefined
  const bounds: Record<string, ReactNode> = {
    ticket_id: capability?.resources?.ticket_ids?.join('、') ?? <>任务：{snapshot.task.ticket_id}</>,
    customer_id: capability?.resources?.customer_ids?.join('、') ?? <>任务：{snapshot.task.customer_id}</>,
    amount_fen: capability?.constraints?.single_max_fen !== undefined
      ? <>单笔 ≤ <Fen value={capability.constraints.single_max_fen} /></> : <>任务累计 ≤ <Fen value={snapshot.task.refund_total_fen} /></>,
    template_id: capability?.constraints?.template_ids?.join('、') ?? '未记录模板授权范围',
    related_business_effect_id: '关联规则：同任务已提交退款',
  }
  if (!Object.keys(parameters).length) return <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="此记录没有保存原始参数，不补造历史输入" />
  return <div className="request-parameter-table" role="table" aria-label="请求与授权字段对照">
    <div className="request-parameter-head" role="row"><span role="columnheader">字段</span><span role="columnheader">请求值 · 观测记录</span><span role="columnheader">{projected ? '叶子范围 / 业务规则' : '任务范围（未投影叶子约束）'}</span></div>
    {Object.entries(parameters).map(([field, value]) => <div role="row" className="request-parameter-row" key={field}>
      <span role="cell">{FIELD_LABELS[field] ?? field}</span><strong role="cell"><Value value={value} field={field} /></strong><span role="cell">{bounds[field] ?? '未投影此项约束'}</span>
    </div>)}
  </div>
}

export function RequestEvidencePanel({ snapshot, run, events, replay, onInspect }: {
  snapshot: TaskSnapshot | null; run: WorkflowRun | null; events: WorkflowEvent[]; replay: boolean
  onInspect: (selection: EvidenceSelection) => void
}) {
  const entries = useMemo(() => requestEvidenceForRun(snapshot, run, events, !replay), [events, replay, run, snapshot])
  const [selectedKey, setSelectedKey] = useState<string | null>(null)
  useEffect(() => { setSelectedKey(null) }, [snapshot?.task.task_id, run?.run_id])
  const current = entries.find((entry) => entry.key === selectedKey)
    ?? [...entries].reverse().find((entry) => entry.tool === 'refund.create') ?? entries[entries.length - 1]
  const execution = current?.execution ?? null
  const refunds = snapshot?.business_effects.refunds.filter((item) => item.execution_id === execution?.execution_id) ?? []
  const notices = snapshot?.business_effects.notifications.filter((item) => item.execution_id === execution?.execution_id) ?? []
  const receipts = snapshot?.receipts.filter((item) => item.execution_id === execution?.execution_id) ?? []
  const audits = snapshot?.audit_events.filter((item) => item.execution_id === execution?.execution_id) ?? []
  const denied = execution ? execution.decision === 'DENY' : current?.decisionEvent?.status === 'DENIED'
  const VerdictIcon = denied ? ShieldX : execution?.decision === 'ALLOW' ? ShieldCheck : Clock3
  const openRequest = () => {
    if (current?.request && current.runId) onInspect({ kind: 'workflow', runId: current.runId, sequence: current.request.sequence })
    else if (execution) onInspect({ kind: 'execution', execution })
  }
  return <section className="request-evidence-panel" aria-label="单笔工具请求证据" data-testid="request-evidence-panel">
    <div className="request-evidence-heading"><div><FileText size={16} /><h3>单笔请求与真实结果</h3><span>{entries.length} 笔记录</span></div>
      <Select value={current?.key} onChange={setSelectedKey} aria-label="选择工具请求" placeholder="暂无请求" disabled={!entries.length}
        options={entries.map((entry, index) => ({ value: entry.key, label: `${String(index + 1).padStart(2, '0')} · ${toolLabel(entry.tool)} · ${entry.execution ? statusLabel(entry.execution.state) : '无执行关联'}` }))} />
    </div>
    {current && snapshot ? <>
      <div className="request-focus-meta"><span>{current.agentId ? agentLabel(current.agentId) : '角色未关联'}<ArrowRight size={12} />{toolLabel(current.tool)}</span>
        <span>{replay ? '回放位置 / 当前落库投影' : '已保存证据'}</span>
        <Tooltip title={current.association === 'request_hash' ? '观测请求与执行记录的请求/参数摘要一致；不等于独立验签' : current.association === 'legacy_sequence' ? '旧记录没有完整请求摘要，以同角色相邻裁决与参数摘要关联；不是密码学证明' : '此记录缺少唯一匹配的请求观测，不从工具名称猜测关联'}>
          <span className="request-association">{current.association === 'request_hash' ? '请求摘要关联' : current.association === 'legacy_sequence' ? '旧序列关联 · 非签名证据' : current.association === 'execution_only' ? '仅执行记录' : '尚无唯一执行关联'}</span>
        </Tooltip>
      </div>
      <div className="request-evidence-layout">
        <div className="request-input"><div className="request-section-heading"><h4>请求参数 / 授权范围</h4>
          <Tooltip title="字段对照来自观测与公开授权投影，不是网关逐项验证日志"><span>字段对照</span></Tooltip></div>
          <Parameters entry={current} snapshot={snapshot} />
          <button type="button" className="text-link" onClick={openRequest}>查看请求记录<ArrowUpRight size={13} /></button>
        </div>
        <div className="request-outcome"><div className="request-section-heading"><h4>网关裁决 / 执行记录</h4>{execution ? <StatusTag value={execution.state} /> : null}</div>
          <div className={`request-verdict ${denied ? 'request-denied' : execution?.decision === 'ALLOW' ? 'request-allowed' : 'request-pending'}`}>
            <VerdictIcon size={20} /><div><strong>{execution?.decision === 'ALLOW' ? '网关允许' : denied ? execution ? '网关拒绝' : '拒绝观测 · 无执行关联' : '无已关联裁决'}</strong>
              <span>{execution?.reason_code ? reasonLabel(execution.reason_code) : current.decisionEvent?.details.reason_code ? reasonLabel(String(current.decisionEvent.details.reason_code)) : '未记录裁决原因'}</span></div>
          </div>
          {execution ? <><div className="request-execution-id"><span>执行编号</span><ShortHash value={execution.execution_id} size={7} /></div>
            <button type="button" className="text-link" onClick={() => onInspect({ kind: 'execution', execution })}>执行绑定与恢复状态<ArrowUpRight size={13} /></button></> : null}
        </div>
        <div className="request-effects"><div className="request-section-heading"><h4>业务办理记录</h4><WalletCards size={15} /></div>
          <strong className="request-effect-value">{refunds.length ? <Fen value={refunds.reduce((sum, refund) => sum + refund.amount_fen, 0)} />
            : notices.length ? `${notices.length} 条通知` : ['ticket.read', 'knowledge.read_associated'].includes(current.tool) && execution?.state === 'COMMITTED' ? '读取结果已提交' : '未记录业务副作用'}</strong>
          <span className="request-effect-caption">{refunds.length ? `${refunds.length} 笔退款记录` : notices.length ? notices.map((notice) => notice.template_id).join('、') : execution?.business_effect_id ? '执行有副作用编号，但无对应业务表投影' : '本笔执行的当前记录'}</span>
          <div className="request-proof-links">{receipts.length ? receipts.map((receipt) => <button type="button" key={receipt.receipt_id} onClick={() => onInspect({ kind: 'receipt', receipt })}>
            <FileCheck2 size={13} />回执 · {observeReceipt(receipt).label}<ArrowUpRight size={12} /></button>) : <span>回执未记录</span>}
            {audits.length ? <button type="button" onClick={() => onInspect({ kind: 'audit', event: audits[audits.length - 1] })}>审计 #{audits[audits.length - 1].event_sequence}<ArrowUpRight size={12} /></button> : <span>审计未记录</span>}
          </div>
        </div>
      </div>
      <div className="request-evidence-footer"><span>业务记录与关联执行、签名回执分别核对</span>
        <LiquidGlassButton size="small" icon={<ArrowUpRight size={13} />} onClick={() => execution ? onInspect({ kind: 'execution', execution }) : openRequest()}>打开关联详情</LiquidGlassButton></div>
    </> : <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="尚无工具请求或执行记录" />}
  </section>
}
