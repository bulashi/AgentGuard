import type { ReactNode } from 'react'
import { ArrowRight, ChevronRight, FileCheck2, LockKeyhole, ShieldCheck, Sparkles, WalletCards } from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import type { EvidenceSelection } from '../executionModel'
import { visibleAuditEvents } from '../executionModel'
import type { CredentialView, ExecutionView, TaskSnapshot, WorkflowEvent } from '../types'
import { activeWorkflow, MODE_LABELS } from '../workflowModel'
import { Fen } from './Evidence'
import { observeCredential } from '../credentialObservation'
import { observeReceipt, receiptEvidenceIsConsistent } from '../sourceVerification'

type RailState = 'waiting' | 'recorded' | 'denied' | 'invalid'

interface RailItem {
  id: string
  title: string
  icon: LucideIcon
  value: ReactNode
  detail: string
  state: RailState
  selection: EvidenceSelection
}

export function ExecutionEvidenceRail({ snapshot, events, credentials, executions, replay, onInspect, observedAt = Date.now() / 1000 }: {
  snapshot: TaskSnapshot | null
  events: WorkflowEvent[]
  credentials: CredentialView[]
  executions: ExecutionView[]
  replay: boolean
  onInspect: (selection: EvidenceSelection) => void
  observedAt?: number
}) {
  const run = activeWorkflow(snapshot)
  const root = credentials.find((credential) => credential.credential_type === 'ROOT')
  const plans = events.filter((event) => event.action === 'plan' && event.status === 'COMPLETED')
  const proposals = plans.reduce((count, event) => count + (Array.isArray(event.details.intents) ? event.details.intents.length : 0), 0)
  const allowed = executions.filter((execution) => execution.decision === 'ALLOW').length
  const denied = executions.filter((execution) => execution.decision === 'DENY').length
  const undecided = executions.length - allowed - denied
  const executionIds = new Set(executions.map((execution) => execution.execution_id))
  const refunds = snapshot?.business_effects.refunds.filter((refund) => !replay || executionIds.has(refund.execution_id)) ?? []
  const notices = snapshot?.business_effects.notifications.filter((notice) => !replay || executionIds.has(notice.execution_id)) ?? []
  const receipts = snapshot?.receipts.filter((receipt) => !replay || executionIds.has(receipt.execution_id)) ?? []
  const audits = visibleAuditEvents(snapshot, credentials, executions, replay)
  const consistentReceipts = receipts.filter(receiptEvidenceIsConsistent).length
  const receiptState: RailState = receipts.some((receipt) => observeReceipt(receipt).status === 'INVALID') ? 'invalid'
    : consistentReceipts < receipts.length ? 'waiting' : receipts.length ? 'recorded' : 'waiting'
  const rootObservation = root ? observeCredential(root, snapshot?.credentials ?? credentials, observedAt) : null
  const rootState: RailState = !root || ['NOT_YET_VALID', 'EXPIRED'].includes(rootObservation?.code ?? '') ? 'waiting'
    : rootObservation?.code === 'WINDOW_OPEN' ? 'recorded'
    : ['REVOKED', 'ANCESTOR_REVOKED'].includes(rootObservation?.code ?? '') ? 'denied' : 'invalid'
  const rootDetail = root && rootObservation
    ? `${rootObservation.label} · ${snapshot ? `${snapshot.task.max_tool_calls} 次调用` : '任务限额待读取'} · 可再委托 ${root.delegation_depth} 级`
    : '尚无根凭证'
  const latestReturnedModel = [...plans].reverse().find((event) => typeof event.details.model_returned === 'string')?.details.model_returned
  const lastPlan = plans[plans.length - 1]

  const items: RailItem[] = [
    {
      id: 'authorization', title: '任务授权', icon: LockKeyhole,
      value: snapshot ? <Fen value={snapshot.task.refund_total_fen} /> : '未选择任务',
      detail: rootDetail,
      state: rootState, selection: { kind: 'stage', stage: 'authorization', ...(replay ? { auditEvents: audits } : {}) },
    },
    {
      id: 'proposal', title: '候选动作', icon: Sparkles,
      value: `${proposals} 个提议`,
      detail: latestReturnedModel ? 'AI 规划 · 已记录候选动作' : plans.length && run?.runtime_mode === 'deterministic' ? '确定性规则 · 无模型调用' : '尚无实际规划输出',
      state: proposals || plans.length ? 'recorded' : 'waiting',
      selection: run ? { kind: 'workflow', runId: run.run_id, sequence: lastPlan?.sequence } : { kind: 'stage', stage: 'agents' },
    },
    {
      id: 'gateway', title: '网关裁决', icon: ShieldCheck,
      value: <><span>{allowed} 允许</span><span className={denied ? 'rail-denial-count' : 'rail-secondary-count'}> / {denied} 拒绝</span></>,
      detail: undecided ? `${undecided} 条尚未裁决` : executions.length ? '来自执行记录，不由模型决定' : '尚无执行裁决',
      state: denied ? 'denied' : allowed ? 'recorded' : 'waiting', selection: { kind: 'stage', stage: 'gateway' },
    },
    {
      id: 'business', title: '业务结果', icon: WalletCards,
      value: <Fen value={refunds.reduce((total, refund) => total + refund.amount_fen, 0)} />,
      detail: `${refunds.length} 笔退款 · ${notices.length} 条通知`,
      state: refunds.length || notices.length ? 'recorded' : 'waiting', selection: { kind: 'business', resource: 'result' },
    },
    {
      id: 'evidence', title: '签名证据', icon: FileCheck2,
      value: `${consistentReceipts} / ${receipts.length} 回执核对一致`,
      detail: receipts.length ? `${audits.length} 条审计事件 · BFF 签名与来源绑定` : `${audits.length} 条审计事件 · 尚无回执`,
      state: receiptState,
      selection: { kind: 'stage', stage: 'evidence', ...(replay ? { auditEvents: audits } : {}) },
    },
  ]

  return <section className="execution-evidence-band" aria-label="当前任务授权与执行证据链">
    <div className="evidence-band-heading">
      <span><ShieldCheck size={14} />本次任务证据链</span>
      <small>{replay ? '历史事件顺序 · 当前验签与业务投影' : run ? MODE_LABELS[run.runtime_mode] : snapshot ? '已有持久化记录' : '等待任务记录'}</small>
    </div>
    <ol className="execution-evidence-rail">
      {items.map((item, index) => {
        const Icon = item.icon
        return <li key={item.id} className={`rail-item rail-${item.state}`}>
          <button type="button" onClick={() => onInspect(item.selection)} disabled={!snapshot}
            aria-label={`查看${item.title}详情`} data-testid={`evidence-rail-${item.id}`}>
            <span className="rail-item-heading"><Icon size={17} /><span>{item.title}</span><ChevronRight size={12} /></span>
            <strong>{item.value}</strong>
            <small title={item.id === 'authorization' && rootObservation ? `${rootObservation.detail}；本机快照观测，不是网关准入结论` : item.detail}>{item.detail}</small>
          </button>
          {index < items.length - 1 ? <ArrowRight className="rail-connector" size={14} aria-hidden="true" /> : null}
        </li>
      })}
    </ol>
  </section>
}
