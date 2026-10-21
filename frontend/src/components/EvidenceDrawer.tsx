import type { ReactNode } from 'react'
import { Descriptions, Drawer, Empty, Progress, Tabs, Tag, Tooltip, Typography } from 'antd'
import { ArrowLeft, ArrowUpRight, Clock3, Download, ExternalLink, FileCheck2, ShieldCheck, ShieldX } from 'lucide-react'
import type { EvidenceSelection, StageKey } from '../executionModel'
import { auditChainIsConsistent, coauthorizationBindingStatus, coauthorizationRoot, executionForTrace, isCoauthorizationAuditEvent } from '../executionModel'
import { agentLabel, actionLabel, credentialTypeLabel, eventLabel, quotaLabel, reasonLabel, revocationCaptureLabel, revocationObservationLabel, revocationSourceLabel, scenarioCategoryLabel, scenarioInvariantLabel, toolLabel } from '../labels'
import type { AuditEventView, CredentialView, ExecutionView, Overview, SourceVerification, TaskSnapshot } from '../types'
import { BooleanTag, Fen, ShortHash, StatusTag, TimeValue } from './Evidence'
import { CredentialObservationTag } from './CredentialObservationTag'
import { observeCredential } from '../credentialObservation'
import { AgentProcessDetails, BusinessContextDetails, WorkflowEventDetails, WorkflowTimeline } from './WorkflowDetails'
import { activeWorkflow, MODE_LABELS } from '../workflowModel'
import { LiquidGlassButton } from './LiquidGlassButton'
import { NotificationPreview } from './NotificationPreview'
import { WorkflowStatusTag } from './WorkflowStatusTag'
import { observationForExecution, publicObject } from '../requestEvidence'
import { resolveEvidenceSelection } from '../evidenceSelection'
import { observeReceipt, sourceVerificationState } from '../sourceVerification'
import { auditPrefixObservation, auditPrefixSummary, coauthorizationRevocationBindingStatus, coauthorizationRevocationProjection, type AuditPrefixReport } from '../auditPrefixBinding'

const { Text } = Typography

function displayProjection(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(displayProjection)
  if (!value || typeof value !== 'object') return value
  return Object.fromEntries(Object.entries(value).map(([key, item]) => [
    key,
    ['model', 'model_requested', 'model_returned'].includes(key) && item ? 'AI 规划器' : displayProjection(item),
  ]))
}
const STAGE_TITLES: Record<StageKey, string> = {
  request: '任务请求', authorization: '根授权', agents: '智能体与委托',
  gateway: '安全网关', tools: '受保护工具与业务结果', evidence: '回执与审计证据',
}

function Fields({ items }: { items: Array<[string, ReactNode]> }) {
  return <Descriptions column={1} size="small" colon={false} className="detail-fields"
    items={items.map(([label, children], index) => ({ key: `${label}-${index}`, label, children: children ?? <Text type="secondary">未记录</Text> }))} />
}

function RecordLink({ title, subtitle, status, onClick }: {
  title: string; subtitle?: string; status?: ReactNode; onClick: () => void
}) {
  return <button type="button" className="record-link" onClick={onClick}>
    <FileCheck2 size={17} /><span className="record-link-copy"><strong>{title}</strong>{subtitle ? <small>{subtitle}</small> : null}</span>
    {typeof status === 'string' ? <StatusTag value={status} /> : status}<ArrowUpRight size={15} />
  </button>
}

function RevocationDetails({ event, task }: { event: AuditEventView; task?: TaskSnapshot['task'] }) {
  const projection = coauthorizationRevocationProjection(event)
  const binding = coauthorizationRevocationBindingStatus(event)
  const text = (record: Record<string, unknown>, field: string) => {
    const value = record[field]
    return typeof value === 'string' ? value : null
  }
  const time = (record: Record<string, unknown>, field: string) => {
    const value = record[field]
    return <TimeValue value={typeof value === 'number' ? value : null} />
  }
  const evidence = projection?.evidence
  const taskRoots = projection && task && evidence?.tenant_id === task.tenant_id
    ? projection.roots.filter((root) => root.task_id === task.task_id) : []
  const created = taskRoots.filter((root) => root.root_revocation_created === true).length
  const sourceKind = evidence ? text(evidence, 'source_kind') : null
  const targetLabel = sourceKind === 'AUTHORIZATION_WITHDRAWN' ? '单根目标（根凭证编号）'
    : sourceKind === 'APPROVAL_POLICY_REVOKED' ? '策略目标（策略修订）' : '公钥目标（审批密钥标识）'
  return <>
    <h3 className="detail-heading">共同授权撤销详情</h3>
    <Fields items={[
      ['服务端原文 / 摘要 / 元数据绑定', <StatusTag value={binding} label={binding === 'BINDING_CHECKED' ? '已核对' : binding === 'INVALID' ? '未通过' : '待核对'} />],
      ['核对边界', '服务端原文、摘要与元数据绑定核对；不是浏览器验签，也不代表实际撤销主体已鉴权'],
      ['事件保护方式', '本事件无单独 SM2 签名；仅在逐事件精确绑定确认覆盖后，才归入已有签名独立检查点保护范围'],
      ['待处理状态', '待追加、待核对或尚未覆盖均不表示核验通过'],
      ['执行边界', '已准入执行不追溯取消'],
    ]} />
    {projection && evidence ? <>
      <Fields items={[
        ['证据版本', text(evidence, 'schema_version')], ['记录类型', text(evidence, 'record_type')],
        ['撤销观察编号', String(evidence.revocation_event_id)], ['租户', text(evidence, 'tenant_id')],
        ['撤销来源', <span title={sourceKind ?? undefined}>{revocationSourceLabel(sourceKind ?? '')}</span>],
        [targetLabel, <ShortHash value={text(evidence, 'source_identifier')} />],
        ['原始观察时间', time(evidence, 'observed_at')],
        ['观察上下文', revocationObservationLabel(text(evidence, 'observation_context') ?? '')],
        ['数据库操作者', text(evidence, 'database_actor')],
        ['捕获方式', revocationCaptureLabel(text(evidence, 'capture_kind') ?? '')],
        ['审计捕获时间', time(evidence, 'captured_at')],
        ['是否旧观察后续关联', evidence.capture_kind === 'LEGACY_OBSERVATION_LINK'
          ? '是：关联此前的观察，不把捕获时间当作原观察或原撤销时间' : '否：事务内捕获'],
        ['本次来源页码', `第 ${evidence.page_number} / ${evidence.page_count} 页（从 1 起）`],
        ['本页全部任务根', `${projection.roots.length} 个（每页至多 32 个）`],
        ['本次来源全部页匹配根', `${evidence.matched_root_count} 个（全部任务）`],
        ['本次来源全部页新撤销根', `${evidence.created_root_revocation_count} 个（全部任务）`],
        ['当前任务', <ShortHash value={task?.task_id} />],
        ['本任务本页关联根', `${taskRoots.length} 个`],
        ['本任务本页本次新撤销', `${created} 个`],
        ['本任务本页保留原撤销', `${taskRoots.length - created} 个`],
        ['本页非当前任务根', `${projection.roots.length - taskRoots.length} 个，不计入本任务结果；原文保留`],
      ]} />
      {task && evidence.tenant_id !== task.tenant_id ? <Text type="warning">该页租户与当前任务不一致，不展示为本任务撤销结果。</Text> : null}
      <h3 className="detail-heading">本任务本页关联根</h3>
      {taskRoots.length ? taskRoots.map((root, index) => <div key={`${root.root_credential_id}-${index}`}>
        <h3 className="detail-heading">关联根 #{index + 1}</h3>
        <Fields items={[
          ['根凭证编号', <ShortHash value={text(root, 'root_credential_id')} />],
          ['根凭证摘要', <ShortHash value={text(root, 'root_credential_hash')} />],
          ['任务编号', <ShortHash value={text(root, 'task_id')} />],
          ['共同审批挑战', <ShortHash value={text(root, 'challenge_id')} />],
          ['策略修订', text(root, 'policy_revision')],
          ['审批载荷摘要', <ShortHash value={text(root, 'approval_payload_hash')} />],
          ['审批包摘要', <ShortHash value={text(root, 'bundle_hash')} />],
          ['企业审批密钥', text(root, 'enterprise_key_id')], ['财务审批密钥', text(root, 'finance_key_id')],
          ['本次是否新建根撤销', <StatusTag value="REVOKED" label={root.root_revocation_created === true ? '本次新撤销' : '保留原撤销（非本次新增）'} />],
          ['实际原撤销时间', time(root, 'revoked_at')], ['实际原撤销者', text(root, 'revoked_by')],
          ['实际原撤销原因', text(root, 'revocation_reason')],
        ]} />
      </div>) : <Text type="secondary">本页没有可归入当前任务的根；其他任务根不作为本任务撤销结果。</Text>}
    </> : <Text type="warning">撤销投影缺失或与约定的 v3 事件 / v1 载荷不一致，未作为有效撤销详情；保留原始 JSON。</Text>}
    <h3 className="detail-heading">撤销证据原文（完整页，含其他任务根）</h3>
    {event.revocation_evidence !== null && event.revocation_evidence !== undefined
      ? <pre className="projection-json">{JSON.stringify(event.revocation_evidence, null, 2)}</pre>
      : <Text type="secondary">未记录</Text>}
  </>
}

function SourceVerificationDetails({ source, profile }: { source?: SourceVerification; profile: SourceVerification['profile'] }) {
  const state = sourceVerificationState(source, profile)
  const observed = state === 'INCOMPLETE' ? undefined : source
  const flag = (value: unknown) => <StatusTag value={typeof value === 'boolean' ? value ? 'VALID' : 'INVALID' : 'INCOMPLETE'} label={typeof value === 'boolean' ? value ? '一致' : '不一致' : '未核对'} />
  const items: Array<[string, ReactNode]> = [
    ['冻结原文 Schema', flag(observed?.schema_valid)],
    ['SM3 存储摘要', flag(observed?.stored_hash_valid)],
    ['原文与数据库列绑定', flag(observed?.row_binding_valid)],
  ]
  if (profile === 'RECEIPT_EXECUTION_BINDING_V1') items.push(['请求 / 授权链 / 裁决 / 结果绑定', flag(observed?.execution_binding_valid)])
  items.push(
    ['核对边界', profile === 'RECEIPT_EXECUTION_BINDING_V1' ? '当前执行记录及结果摘要；不重验 Holder Proof、预算、幂等键或外部资金' : '签名元数据列；预算使用量、撤销状态不在原凭证签名内'],
  )
  return <><h3 className="detail-heading">签名来源核对 · BFF 投影</h3><Fields items={items} /></>
}

function CredentialDetails({ credential, credentials, observedAt }: { credential: CredentialView; credentials: CredentialView[]; observedAt: number }) {
  const observation = observeCredential(credential, credentials, observedAt)
  return <>
    <div className="detail-verdict pending"><ShieldCheck size={18} /><div><strong>当前快照观测</strong><span><CredentialObservationTag observation={observation} /></span></div></div>
    <Fields items={[
      ['凭证编号', <ShortHash value={credential.credential_id} />],
      ['凭证类型', credentialTypeLabel(credential.credential_type)],
      ['本机快照观测时间', <TimeValue value={observedAt} />],
      ['持有者', agentLabel(credential.holder_agent_id)], ['持有者密钥', credential.holder_key_id],
      ['签发者', credential.issuer_subject_id], ['签发密钥', credential.issuer_key_id],
      ['剩余委托深度', credential.delegation_depth],
      ['签名校验', <BooleanTag value={credential.signature.valid === true} />],
      ['存储哈希校验', <BooleanTag value={credential.stored_hash_valid} />],
      ['签名算法', credential.signature.algorithm], ['签名摘要', <ShortHash value={credential.signature.fingerprint_sm3} />],
      ['父授权', <ShortHash value={credential.parent_credential_id} />],
      ['父签名对象哈希', <ShortHash value={credential.parent_credential_hash} />],
      ['签名对象哈希', <ShortHash value={credential.signed_object_hash} />],
      ['签发时间', <TimeValue value={credential.issued_at} />], ['生效时间', <TimeValue value={credential.not_before} />],
      ['到期时间', <TimeValue value={credential.expires_at} />], ['撤销时间', <TimeValue value={credential.revoked_at} />],
      ['撤销原因', credential.revocation_reason ?? '无'],
      ['撤销操作主体', credential.revoked_by ?? '无'],
    ]} />
    <SourceVerificationDetails source={credential.source_verification} profile="CREDENTIAL_ROW_BINDING_V1" />
    <h3 className="detail-heading">授权能力</h3>
    <div className="capability-list">{credential.capabilities.map((capability) => <div key={capability.tool}>
      <strong>{toolLabel(capability.tool)}</strong><small className="mono">{capability.service} / {capability.tool}@{capability.version}</small>
      <div className="detail-capability-bounds">{capability.resources === undefined ? '旧投影未保存资源范围' : <>
        {capability.resources.ticket_ids ? <div>工单：{capability.resources.ticket_ids.join('、')}</div> : null}
        {capability.resources.customer_ids ? <div>客户：{capability.resources.customer_ids.join('、')}</div> : null}
        {capability.resources.document_ids ? <div>文档：{capability.resources.document_ids.join('、')}</div> : null}
      </>}
        {capability.constraints?.single_max_fen !== undefined ? <div>单笔上限：<Fen value={capability.constraints.single_max_fen} /></div> : null}
        {capability.constraints?.template_ids ? <div>模板：{capability.constraints.template_ids.join('、')}</div> : null}
      </div>
    </div>)}</div>
    <h3 className="detail-heading">当前共享预算</h3>
    {credential.budgets.map((budget) => <div className="detail-budget" key={budget.quota_type}>
      <div><strong>{quotaLabel(budget.quota_type)}</strong><span>已占用 {budget.quota_type === 'refund_total_fen' ? <><Fen value={budget.reserved + budget.committed} /> / <Fen value={budget.limit} /></> : `${budget.reserved + budget.committed} / ${budget.limit} 次`}</span></div>
      <Progress percent={budget.limit ? Math.min(100, ((budget.reserved + budget.committed) / budget.limit) * 100) : 0} showInfo={false} size="small" strokeColor="var(--success)" />
      <small>剩余 {budget.quota_type === 'refund_total_fen' ? <Fen value={budget.remaining} /> : `${budget.remaining} 次`} · 预留 {budget.quota_type === 'refund_total_fen' ? <Fen value={budget.reserved} /> : `${budget.reserved} 次`} · 已提交 {budget.quota_type === 'refund_total_fen' ? <Fen value={budget.committed} /> : `${budget.committed} 次`} · 版本 {budget.version}</small>
    </div>)}
  </>
}

function ExecutionDetails({ execution }: { execution: ExecutionView }) {
  const tone = execution.decision === 'DENY' || execution.state === 'DENIED' ? 'denied' : execution.decision === 'ALLOW' ? 'allowed' : 'pending'
  const Icon = tone === 'denied' ? ShieldX : tone === 'allowed' ? ShieldCheck : Clock3
  return <>
    {execution.reason_code ? <div className={`detail-verdict ${tone}`}><Icon size={20} /><div><strong>{reasonLabel(execution.reason_code)}</strong><code>{execution.reason_code}</code></div></div> : null}
    <Fields items={[
      ['执行编号', <ShortHash value={execution.execution_id} />],
      ['工具', <span title={execution.tool_name}>{toolLabel(execution.tool_name)}</span>],
      ['服务 / 版本', `${execution.tool_service} / ${execution.tool_version}`],
      ['网关裁决', <StatusTag value={execution.decision} />], ['执行状态', <StatusTag value={execution.state} />],
      ['回执状态', <StatusTag value={execution.receipt_status} />],
      ['业务动作（幂等标识）', <ShortHash value={execution.business_action_id} />],
      ['业务副作用编号', <ShortHash value={execution.business_effect_id} />],
      ['请求哈希', <ShortHash value={execution.request_hash} />],
      ['凭证链哈希', <ShortHash value={execution.credential_chain_hash} />],
      ['参数哈希', <ShortHash value={execution.parameter_hash} />],
      ['业务结果哈希', <ShortHash value={execution.business_result_hash} />],
      ['创建时间', <TimeValue value={execution.created_at} />], ['更新时间', <TimeValue value={execution.updated_at} />],
    ]} />
  </>
}

export function EvidenceDrawer({ selection: requestedSelection, snapshot, overview, auditPrefix = null, prefixError, onSelect, onClose, onBack, observedAt = Date.now() / 1000 }: {
  selection: EvidenceSelection | null; snapshot: TaskSnapshot | null; overview: Overview | null
  onSelect: (selection: EvidenceSelection) => void; onClose: () => void
  onBack?: () => void
  observedAt?: number
  auditPrefix?: AuditPrefixReport | null
  prefixError?: string | null
}) {
  const selection = resolveEvidenceSelection(requestedSelection, snapshot)
  const scopedPrefix = auditPrefix?.task_id === snapshot?.task.task_id ? auditPrefix : null
  let title = '记录详情'
  let raw: unknown = selection
  let summary: ReactNode = null
  let related: ReactNode = null
  let projectionLabel = 'BFF 只读投影'

  const executionLinks = (executions: ExecutionView[]) => executions.length ? executions.map((execution) =>
    <RecordLink key={execution.execution_id} title={toolLabel(execution.tool_name)} subtitle={execution.execution_id}
      status={execution.state} onClick={() => onSelect({ kind: 'execution', execution })} />) : <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="尚无执行记录" />
  const credentialLinks = (credentials: CredentialView[]) => credentials.length ? credentials.map((credential) =>
    <RecordLink key={credential.credential_id} title={`${credentialTypeLabel(credential.credential_type)} · ${agentLabel(credential.holder_agent_id)}`}
      subtitle={credential.credential_id} status={<CredentialObservationTag observation={observeCredential(credential, snapshot?.credentials ?? credentials, observedAt)} />}
      onClick={() => onSelect({ kind: 'credential', credential })} />) : <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="尚无授权记录" />
  const credentialForReference = (credentialId: unknown) => {
    const matches = snapshot?.credentials.filter((credential) => typeof credentialId === 'string' && credential.credential_id === credentialId) ?? []
    return matches.length === 1 ? matches[0] : undefined
  }
  const effectDetails = (executionId?: string) => {
    const refunds = snapshot?.business_effects.refunds.filter((item) => !executionId || item.execution_id === executionId) ?? []
    const notifications = snapshot?.business_effects.notifications.filter((item) => !executionId || item.execution_id === executionId) ?? []
    return <>
      <Fields items={[
        ['已记录退款', `${refunds.length} 笔`], ['退款金额', <Fen value={refunds.reduce((sum, item) => sum + item.amount_fen, 0)} />],
        ['已记录通知', `${notifications.length} 条`],
      ]} />
      {refunds.map((refund) => <Fields key={refund.refund_id} items={[
        ['退款编号', <ShortHash value={refund.refund_id} />], ['金额', <Fen value={refund.amount_fen} />],
        ['关联执行', <ShortHash value={refund.execution_id} />],
        ['状态', <StatusTag value={refund.status} />], ['时间', <TimeValue value={refund.created_at} />],
      ]} />)}
      {notifications.map((notice) => <Fields key={notice.notification_id} items={[
        ['通知编号', <ShortHash value={notice.notification_id} />], ['模板', notice.template_id],
        ['关联执行', <ShortHash value={notice.execution_id} />], ['状态', <StatusTag value={notice.status} />],
        ['关联副作用', <ShortHash value={notice.related_business_effect_id} />], ['时间', <TimeValue value={notice.created_at} />],
      ]} />)}
    </>
  }
  const relationsForExecution = (executionId: string) => <>
    <h3 className="detail-heading">签名回执</h3>
    {snapshot?.receipts.filter((item) => item.execution_id === executionId).map((receipt) =>
      <RecordLink key={receipt.receipt_id} title={receipt.decision === 'DENY' ? '拒绝回执' : '执行结果回执'} subtitle={receipt.receipt_id}
        status={<StatusTag value={observeReceipt(receipt).status} label={observeReceipt(receipt).label} />} onClick={() => onSelect({ kind: 'receipt', receipt })} />)}
    <h3 className="detail-heading">审计事件</h3>
    {snapshot?.audit_events.filter((item) => item.execution_id === executionId).map((event) =>
      <RecordLink key={event.event_sequence} title={`#${event.event_sequence} · ${eventLabel(event.event_type)}`} subtitle={event.event_hash}
        onClick={() => onSelect({ kind: 'audit', event })} />)}
    <h3 className="detail-heading">业务结果</h3>{effectDetails(executionId)}
  </>

  if (requestedSelection && !selection) {
    title = '记录暂不可用'
    projectionLabel = '记录不可用状态（不是原记录）'
    raw = { kind: requestedSelection.kind, task_id: requestedSelection.taskId ?? null, availability: 'NOT_IN_CURRENT_SNAPSHOT_OR_AMBIGUOUS' }
    summary = <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={requestedSelection.kind === 'credential'
      ? '所选凭证不在当前任务快照中'
      : '当前任务快照无法唯一关联所选记录'} />
  } else if (selection?.kind === 'agent') {
    title = `${agentLabel(selection.agentId)} · 运行逻辑`
    const run = activeWorkflow(snapshot)
    const events = run?.events.filter((event) => event.agent_id === selection.agentId) ?? []
    raw = { agent_id: selection.agentId, run_id: run?.run_id, events }
    summary = <AgentProcessDetails agentId={selection.agentId} snapshot={snapshot} onSelect={onSelect} />
    const executionIds = new Set(events.map((event) => event.details.execution_id))
    related = <><h3 className="detail-heading">本角色授权</h3>{credentialLinks(snapshot?.credentials.filter((item) => item.holder_agent_id === selection.agentId) ?? [])}
      <h3 className="detail-heading">本角色执行</h3>{executionLinks(snapshot?.executions.filter((item) => executionIds.has(item.execution_id)) ?? [])}</>
  } else if (selection?.kind === 'workflow') {
    const run = snapshot?.workflow_runs?.find((item) => item.run_id === selection.runId)
    const event = run?.events.find((item) => item.sequence === selection.sequence)
    title = event ? `过程 #${event.sequence} · ${agentLabel(event.agent_id)}` : '完整协作过程'
    raw = event ?? run
    if (event && run) {
      summary = <WorkflowEventDetails event={event} run={run} />
      const execution = executionForTrace(snapshot, event)
      const credential = credentialForReference(event.details.credential_id)
      related = <>{credential ? credentialLinks([credential]) : null}{execution ? <>{executionLinks([execution])}{relationsForExecution(execution.execution_id)}</> : null}
        <h3 className="detail-heading">角色记录</h3><RecordLink title={agentLabel(event.agent_id)} onClick={() => onSelect({ kind: 'agent', agentId: event.agent_id })} /></>
    } else if (run) {
      summary = <><Fields items={[
        ['运行编号', <ShortHash value={run.run_id} />], ['状态', <WorkflowStatusTag state={run.state} reasonCode={run.reason_code} />], ['运行模式', MODE_LABELS[run.runtime_mode]],
        ['场景', run.scenario === 'policy_injection' ? '污染关联知识返回副本' : '正常业务协作'],
        ['记录数量', run.events.length], ['证据边界', '操作观测记录；安全结论需查看执行回执与审计链'],
      ]} /><WorkflowTimeline run={run} onSelect={onSelect} /></>
    }
  } else if (selection?.kind === 'business') {
    title = selection.resource === 'ticket' ? '业务工单' : selection.resource === 'knowledge' ? '关联知识与输入来源'
      : selection.resource === 'notifications' ? '客户通知记录' : '业务结果'
    raw = selection.resource === 'notifications' ? { notification_templates: snapshot?.business_context?.notification_templates ?? [], notifications: snapshot?.business_effects.notifications ?? [] }
      : selection.resource === 'result' ? snapshot?.business_effects : { business_context: snapshot?.business_context, knowledge_event: activeWorkflow(snapshot)?.events.find((event) => event.action === 'knowledge_result') }
    summary = selection.resource === 'notifications' ? snapshot ? <NotificationPreview snapshot={snapshot} /> : null
      : selection.resource === 'result' ? effectDetails() : <BusinessContextDetails resource={selection.resource} snapshot={snapshot} />
    const tools = selection.resource === 'ticket' ? ['ticket.read'] : selection.resource === 'knowledge' ? ['knowledge.read_associated'] : ['refund.create', 'notification.send_template']
    related = executionLinks(snapshot?.executions.filter((item) => tools.includes(item.tool_name)) ?? [])
  } else if (selection?.kind === 'task' && snapshot) {
    title = '任务详情'; raw = snapshot.task
    summary = <Fields items={[
      ['任务编号', <ShortHash value={snapshot.task.task_id} />], ['租户', snapshot.task.tenant_id],
      ['工单', snapshot.task.ticket_id], ['客户', snapshot.task.customer_id],
      ['状态', <StatusTag value={snapshot.task.status} />], ['退款上限', <Fen value={snapshot.task.refund_total_fen} />],
      ['工具调用上限', snapshot.task.max_tool_calls], ['创建时间', <TimeValue value={snapshot.task.created_at} />],
      ['到期时间', <TimeValue value={snapshot.task.expires_at} />],
    ]} />
    related = <><h3 className="detail-heading">授权凭证</h3>{credentialLinks(snapshot.credentials)}<h3 className="detail-heading">执行记录</h3>{executionLinks(snapshot.executions)}</>
  } else if (selection?.kind === 'credential') {
    const credential = selection.credential
    title = `${credentialTypeLabel(credential.credential_type)}详情`; raw = credential
    summary = snapshot
      ? <CredentialDetails credential={credential} credentials={snapshot.credentials} observedAt={observedAt} />
      : <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="所选凭证不在当前任务快照中" />
    if (credential) related = credentialLinks(snapshot?.credentials.filter((item) => item.credential_id === credential.parent_credential_id || item.parent_credential_id === credential.credential_id) ?? [])
  } else if (selection?.kind === 'execution') {
    const observation = observationForExecution(snapshot, selection.execution.execution_id)
    const cancellation = snapshot?.dispatch_cancellations?.find((record) => record.execution_id === selection.execution.execution_id || record.denial_execution_id === selection.execution.execution_id)
    title = `${toolLabel(selection.execution.tool_name)} · 执行详情`
    raw = { execution: selection.execution, request_observation: observation, dispatch_cancellation: cancellation ?? null }
    summary = <><ExecutionDetails execution={selection.execution} />
      {cancellation ? <><h3 className="detail-heading">派发前取消记录</h3><Fields items={[
        ['取消编号', <ShortHash value={cancellation.cancellation_id} />],
        ['原准入', '允许；保留原裁决，未向工具发出请求'],
        ['后续派发', '拒绝；释放预留额度，无业务副作用'],
        ['派发拒绝码', reasonLabel(cancellation.reason_code)],
        ['取消时间', <TimeValue value={cancellation.cancelled_at} />],
        ['原准入执行', <ShortHash value={cancellation.execution_id} />],
        ['独立拒绝执行', <ShortHash value={cancellation.denial_execution_id} />],
      ]} /></> : null}
      <h3 className="detail-heading">请求观测与公开绑定</h3>
      {observation?.request ? <>
        <Fields items={[
          ['关联口径', observation.association === 'request_hash' ? '请求、参数、凭证链摘要关联；非独立验签' : '旧同角色事件序列与参数摘要关联；非签名证据'],
          ['提出角色', agentLabel(observation.request.agent_id)], ['观测请求 ID', String(observation.request.details.request_id ?? '旧记录未保存')],
          ['观测持有者密钥', String(observation.request.details.holder_key_id ?? '旧记录未保存')],
          ['观测完整请求摘要', typeof observation.request.details.request_hash === 'string' ? <ShortHash value={observation.request.details.request_hash} /> : '旧记录未保存'],
        ]} />
        <Fields items={Object.entries(publicObject(observation.request.details.parameters)).map(([field, value]) => [
          ({ ticket_id: '请求工单', customer_id: '请求客户', amount_fen: '请求金额', template_id: '通知模板', related_business_effect_id: '关联业务副作用' } as Record<string, string>)[field] ?? field,
          field === 'amount_fen' && typeof value === 'number' ? <Fen value={value} /> : typeof value === 'object' ? JSON.stringify(value) : String(value),
        ])} />
      </> : <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="没有唯一请求观测，不推测或补造参数" />}
    </>
    const credentialIds = observation?.request?.details.credential_ids
    related = <>{observation?.runId && observation.request ? <RecordLink title="实际请求观测事件" subtitle={`过程 #${observation.request.sequence}`}
      onClick={() => onSelect({ kind: 'workflow', runId: observation.runId!, sequence: observation.request!.sequence })} /> : null}
      {Array.isArray(credentialIds) ? <><h3 className="detail-heading">请求引用的授权链</h3>{credentialLinks(snapshot?.credentials.filter((item) => credentialIds.includes(item.credential_id)) ?? [])}</> : null}
      {cancellation ? <><h3 className="detail-heading">准入与派发的关联裁决</h3>{executionLinks(snapshot?.executions.filter((item) => item.execution_id === cancellation.execution_id || item.execution_id === cancellation.denial_execution_id) ?? [])}</> : null}
      {relationsForExecution(selection.execution.execution_id)}</>
  } else if (selection?.kind === 'trace') {
    title = `${agentLabel(selection.step.agent_id)} · ${actionLabel(selection.step.action)}`; raw = selection.step
    projectionLabel = '历史轨迹观测（非当前 BFF 记录）'
    const execution = executionForTrace(snapshot, selection.step)
    const credential = credentialForReference(selection.step.details.credential_id)
    summary = <>
      <Fields items={[
        ['步骤序号', selection.step.sequence], ['智能体', agentLabel(selection.step.agent_id)],
        ['动作', actionLabel(selection.step.action)], ['状态', <StatusTag value={selection.step.status} />],
      ]} />
      <h3 className="detail-heading">步骤数据</h3>
      <Fields items={Object.entries(selection.step.details).map(([key, value]) => [
        ({ child_agent_id: '委托对象', credential_id: '凭证编号', tool: '工具', execution_id: '执行编号', planner: '候选规划器',
          source: '来源', reason_code: '原因码', model_requested: '请求模型', model_returned: '实际模型', seed: '随机种子',
          temperature: '温度', response_sm3: '模型响应 SM3', message: '服务消息', intents: '候选动作', provider: '模型提供者',
          prompt_text_consumed: '使用提示输入', total_duration_ns: '模型耗时（ns）', prompt_eval_count: '输入 Token', eval_count: '输出 Token',
        } as Record<string, string>)[key] ?? key,
        ['model_requested', 'model_returned'].includes(key) ? value ? 'AI 规划器' : '未记录'
          : typeof value === 'object' ? <pre className="inline-json">{JSON.stringify(value, null, 2)}</pre> : String(value),
      ])} />
    </>
    related = <>
      {credential ? credentialLinks([credential]) : null}
      {execution ? <>{executionLinks([execution])}{relationsForExecution(execution.execution_id)}</> : null}
      {!credential && !execution ? <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="本步骤无可唯一关联的执行或凭证" /> : null}
    </>
  } else if (selection?.kind === 'receipt') {
    const receipt = selection.receipt; title = '签名回执详情'; raw = receipt
    summary = <><Fields items={[
      ['回执编号', <ShortHash value={receipt.receipt_id} />], ['执行编号', <ShortHash value={receipt.execution_id} />],
      ['类型', receipt.receipt_type], ['裁决', <StatusTag value={receipt.decision} />], ['原因码', receipt.reason_code],
      ['综合核对', <StatusTag value={observeReceipt(receipt).status} label={observeReceipt(receipt).label} />],
      ['签名校验', <BooleanTag value={receipt.signature.valid} />], ['签名算法', receipt.signature.algorithm],
      ['签名密钥', receipt.signature.key_id], ['签名摘要', <ShortHash value={receipt.signature.fingerprint_sm3} />],
      ['回执哈希', <ShortHash value={receipt.receipt_hash} />], ['回执状态', <StatusTag value={receipt.receipt_status} />],
      ['记录创建时间', <TimeValue value={receipt.created_at} />],
    ]} /><SourceVerificationDetails source={receipt.source_verification} profile="RECEIPT_EXECUTION_BINDING_V1" /></>
    related = executionLinks(snapshot?.executions.filter((item) => item.execution_id === receipt.execution_id) ?? [])
  } else if (selection?.kind === 'audit') {
    const event = selection.event; title = `审计事件 #${event.event_sequence}`
    const prefix = auditPrefixObservation(snapshot?.task.task_id ?? '', event, auditPrefix)
    const checkpoint = prefix.checkpoint?.signed_checkpoint
    raw = { event, prefix_observation: prefix, verifier_report: scopedPrefix ? {
      ...scopedPrefix, event_bindings: scopedPrefix.event_bindings.filter((binding) => binding.event_id === event.event_id && binding.event_sequence === event.event_sequence),
    } : null }
    const coauthorized = isCoauthorizationAuditEvent(event)
    const revocation = event.event_type === 'COAUTH_REVOCATION_APPLIED' || event.schema_version === '3.0'
    const credentialRevocationText = (field: string) => {
      const value = event.credential_revocation_evidence?.[field]
      return typeof value === 'string' ? value : null
    }
    const evidence = event.coauthorization_evidence
    const evidenceText = (field: string) => {
      const value = evidence?.[field]
      return typeof value === 'string' ? value : null
    }
    const root = coauthorizationRoot(event, snapshot?.credentials ?? [])
    summary = <><Fields items={[
      ['事件类型', eventLabel(event.event_type)], ['事件编号', <ShortHash value={event.event_id} />],
      ['事件版本', event.schema_version],
      ['执行编号', event.execution_id === null ? '无执行关联' : <ShortHash value={event.execution_id} />], ['时间', <TimeValue value={event.timestamp} />],
      ['证据引用', <ShortHash value={event.evidence_reference} />], ['载荷哈希', <ShortHash value={event.payload_hash} />],
      ['前一事件哈希', <ShortHash value={event.previous_event_hash} />], ['当前事件哈希', <ShortHash value={event.event_hash} />],
    ]} />
      <h3 className="detail-heading">精确检查点与事件绑定</h3>
      <Fields items={[
        ['服务端核验观察', <StatusTag value={prefix.status} label={prefix.label} />],
        ['核验读取异常', prefixError ?? '无'],
        ['本次实际检查点', checkpoint?.payload.checkpoint_sequence],
        ['本次检查点末序号', checkpoint?.payload.latest_event_sequence],
        ['本次检查点末哈希', <ShortHash value={checkpoint?.payload.latest_event_hash} />],
        ['完整检查点摘要', <ShortHash value={prefix.checkpoint?.signed_object_hash} />],
        ['本次检查点签发者', checkpoint?.signature.key_id],
        ['检查点签发时间', <TimeValue value={checkpoint?.payload.timestamp} />],
        ['信任边界', '受信审计服务报告；非浏览器独立验签，非任务归属的独立签名'],
      ]} />
      {checkpoint ? <><h3 className="detail-heading">本次检查点公开原文</h3>
        <pre className="projection-json" data-testid="verified-checkpoint-json">{JSON.stringify(checkpoint, null, 2)}</pre></> : null}
      {revocation ? <RevocationDetails event={event} task={snapshot?.task} /> : null}
      {event.event_type === 'CREDENTIAL_REVOKED' ? <>
        <h3 className="detail-heading">凭证撤销记录</h3>
        <Fields items={[
          ['来源绑定', <BooleanTag value={event.evidence_binding_valid === true} />],
          ['凭证编号', <ShortHash value={credentialRevocationText('credential_id')} />],
          ['撤销主体', credentialRevocationText('revoked_by')],
          ['撤销原因', credentialRevocationText('reason')],
          ['生效边界', '尚未派发的请求取消；已派发请求继续核对结果，不回退已提交业务'],
        ]} />
        {credentialLinks(snapshot?.credentials.filter((credential) => credential.credential_id === event.evidence_reference) ?? [])}
      </> : null}
      {coauthorized ? <>
        <h3 className="detail-heading">共同审批证据</h3>
        <Fields items={[
          ['结构与摘要绑定核对', <StatusTag value={coauthorizationBindingStatus(event)} />],
          ['证据边界', '未复验审批 SM2 签名及当前审批主体信任'],
          ['证据版本', evidenceText('schema_version')], ['记录类型', evidenceText('record_type')],
          ['租户', evidenceText('tenant_id')], ['任务编号', <ShortHash value={evidenceText('task_id')} />],
          ['共同审批挑战', <ShortHash value={evidenceText('challenge_id')} />], ['策略修订', evidenceText('policy_revision')],
          ['审批载荷哈希', <ShortHash value={evidenceText('approval_payload_hash')} />],
          ['审批包哈希', <ShortHash value={evidenceText('bundle_hash')} />],
          ['根凭证编号', <ShortHash value={evidenceText('root_credential_id')} />],
          ['根凭证哈希', <ShortHash value={evidenceText('root_credential_hash')} />],
          ['授权时间', <TimeValue value={typeof evidence?.authorized_at === 'number' ? evidence.authorized_at : null} />],
        ]} />
        <h3 className="detail-heading">根凭证关联</h3>
        {root ? credentialLinks([root]) : <Text type="secondary">当前快照无匹配根凭证</Text>}
        <h3 className="detail-heading">共同审批公开原文</h3>
        {evidence ? <pre className="projection-json" data-testid="coauthorization-evidence-json">{JSON.stringify(evidence, null, 2)}</pre>
          : <Text type="secondary">未记录</Text>}
      </> : null}
    </>
    related = coauthorized || revocation ? null : executionLinks(snapshot?.executions.filter((item) => item.execution_id === event.execution_id) ?? [])
  } else if (selection?.kind === 'stage' && snapshot) {
    title = STAGE_TITLES[selection.stage]
    const auditEvents = selection.auditEvents ?? snapshot.audit_events
    if (selection.stage === 'request') {
      raw = snapshot.task
      summary = <Fields items={[
        ['工单 / 客户', `${snapshot.task.ticket_id} / ${snapshot.task.customer_id}`], ['租户', snapshot.task.tenant_id],
        ['退款上限', <Fen value={snapshot.task.refund_total_fen} />], ['调用上限', `${snapshot.task.max_tool_calls} 次`],
        ['任务编号', <ShortHash value={snapshot.task.task_id} />], ['创建时间', <TimeValue value={snapshot.task.created_at} />],
      ]} />
    } else if (selection.stage === 'authorization' || selection.stage === 'agents') {
      const credentials = snapshot.credentials.filter((item) => selection.stage === 'agents' || !item.parent_credential_id)
      const coauthorizationEvents = selection.stage === 'authorization' ? auditEvents.filter(isCoauthorizationAuditEvent) : []
      raw = coauthorizationEvents.length ? { credentials, audit_events: coauthorizationEvents } : credentials
      summary = <>{credentialLinks(credentials)}{coauthorizationEvents.length ? <>
        <h3 className="detail-heading">共同审批审计事件</h3>
        {coauthorizationEvents.map((event) => <RecordLink key={event.event_sequence} title={`#${event.event_sequence} · ${eventLabel(event.event_type)}`}
          subtitle={event.evidence_reference} onClick={() => onSelect({ kind: 'audit', event })} />)}
      </> : null}</>
    } else if (selection.stage === 'gateway' || selection.stage === 'tools') {
      raw = selection.stage === 'tools' ? { executions: snapshot.executions, business_effects: snapshot.business_effects } : snapshot.executions
      summary = <>{selection.stage === 'gateway' ? <><h3 className="detail-heading">网关处理逻辑</h3><ol className="control-logic-list">
        <li><strong>规范化与签名绑定</strong><span>严格 JSON 解析、Canonical JSON、SM3 参数摘要、SM2 委托链与持有者证明。</span></li>
        <li><strong>独立校验授权范围</strong><span>检查工单、客户、租户、工具、参数、时间、撤销和单调委托。</span></li>
        <li><strong>原子准入</strong><span>重放防护、业务幂等，以及根、中间、叶子共享预算的原子预留。</span></li>
        <li><strong>签名封装与工具验签</strong><span>网关签名执行信封，工具验证签名、有效期和执行尝试后才产生业务效果。</span></li>
        <li><strong>回执与可交叉核验审计</strong><span>签名回执、审计 Outbox、哈希链和独立检查点；结果重取重新检查授权。</span></li>
      </ol><h3 className="detail-heading">本任务实际执行与裁决</h3></> : null}{executionLinks(snapshot.executions)}{selection.stage === 'tools' ? <><h3 className="detail-heading">真实业务状态</h3>{effectDetails()}</> : null}</>
    } else {
      const prefix = auditPrefixSummary(snapshot.task.task_id, auditEvents, auditPrefix)
      raw = { receipts: snapshot.receipts, audit_events: auditEvents, independent_verification: overview?.audit, prefix_report: scopedPrefix }
      summary = <>
        <Fields items={[
          ['当前任务审计事件', auditEvents.length], ['当前任务签名回执', snapshot.receipts.length],
          ['审计链自洽核对', overview ? <StatusTag value={auditChainIsConsistent(overview) ? 'VALID' : 'INCOMPLETE'} /> : '待返回'],
          ['核对末事件序号', overview?.audit.verification.latest_event_sequence],
          ['另读检查点序号', overview?.audit.checkpoint.checkpoint?.payload.checkpoint_sequence ?? '未返回'],
          ['本次实际检查点', scopedPrefix?.checkpoint?.signed_checkpoint.payload.checkpoint_sequence ?? '未核验'],
          ['逐事件前缀覆盖', <StatusTag value={prefix.status} label={`${prefix.anchored}/${prefix.total} · ${prefix.label}`} />],
          ['核验读取异常', prefixError ?? '无'],
        ]} />
        <h3 className="detail-heading">签名回执</h3>
        {snapshot.receipts.map((receipt) => <RecordLink key={receipt.receipt_id} title={receipt.decision === 'DENY' ? '拒绝回执' : '执行结果回执'} subtitle={receipt.receipt_id}
          status={<StatusTag value={observeReceipt(receipt).status} label={observeReceipt(receipt).label} />} onClick={() => onSelect({ kind: 'receipt', receipt })} />)}
        <h3 className="detail-heading">审计事件</h3>
        {auditEvents.map((event) => {
          const observation = auditPrefixObservation(snapshot.task.task_id, event, auditPrefix)
          return <RecordLink key={event.event_sequence} title={`#${event.event_sequence} · ${eventLabel(event.event_type)}`} subtitle={event.event_hash}
            status={<StatusTag value={observation.status} label={observation.label} />} onClick={() => onSelect({ kind: 'audit', event })} />
        })}
      </>
    }
  } else if (selection?.kind === 'scenario') {
    title = '安全场景详情'; raw = selection.scenario
    const result = selection.scenario.latest_result
    projectionLabel = result ? '场景定义与隔离批次核验投影' : '安全场景定义（非实测结果）'
    summary = <><Fields items={[
      ['场景编号', selection.scenario.id], ['类别', scenarioCategoryLabel(selection.scenario.category)],
      ['攻击者能力', selection.scenario.attacker_capability], ['目标不变量', scenarioInvariantLabel(selection.scenario.target_invariant)],
      ['期望决策', <StatusTag value={selection.scenario.expected_decision} />], ['预期拒绝码', selection.scenario.expected_reason_codes.join(' / ') || '无'],
      ['预期副作用', selection.scenario.expected_business_effects], ['证据引用', selection.scenario.evidence.join('\n')],
      ['唯一测试入口', <code className="detail-test-ref">{selection.scenario.test_ref ?? '未映射'}</code>],
    ]} />
      {result ? <>
        <h3 className="detail-heading">本批次实际核验</h3>
        <Fields items={[
          ['核验状态', <StatusTag value={result.status} />], ['批次编号', result.run_id],
          ['观测边界', '隔离数据库与真实服务；不是当前任务的业务状态'],
          ['源码摘要', <ShortHash value={result.source_snapshot_sha256} />],
          ['实际执行层', result.execution_layer],
          ['退款行数（前 → 后）', `${result.before.counts?.refunds ?? '未记录'} → ${result.after.counts?.refunds ?? '未记录'}`],
          ['通知行数（前 → 后）', `${result.before.counts?.notifications ?? '未记录'} → ${result.after.counts?.notifications ?? '未记录'}`],
          ['执行记录（前 → 后）', `${result.before.counts?.executions ?? '未记录'} → ${result.after.counts?.executions ?? '未记录'}`],
          ['签名回执（前 → 后）', `${result.before.counts?.receipts ?? '未记录'} → ${result.after.counts?.receipts ?? '未记录'}`],
          ['预算观测行数（前 → 后）', `${result.before.budget?.length ?? '未记录'} → ${result.after.budget?.length ?? '未记录'}`],
          ['具体断言', `${result.assertions.filter((item) => item.result === 'PASS').length} / ${result.assertions.length} 项通过`],
        ]} />
        <h3 className="detail-heading">实际裁决与边界</h3>
        {result.observations.map((item, index) => <div className="scenario-observation" key={index}>
          <strong>{item.label ?? item.kind ?? '实际请求'}</strong><span>HTTP {item.status_code ?? '未记录'}</span>
          <code>{item.body?.reason_code ?? item.body?.decision ?? item.body?.state ?? '该边界无网关终态裁决'}</code>
        </div>)}
        <h3 className="detail-heading">逐项断言</h3>
        {result.assertions.map((item, index) => <div className="scenario-assertion" key={index}>
          <BooleanTag value={item.result === 'PASS'} /><span>{item.name}</span>
        </div>)}
      </> : <Text type="secondary">此处只有场景定义，没有与当前源码绑定的实测结果。</Text>}
    </>
  } else if (selection?.kind === 'pipeline') {
    title = `${selection.title} · 点击时观测`
    raw = { observation_kind: 'CLICK_CAPTURED_PIPELINE_OBSERVATION', task_id: selection.taskId ?? null, title: selection.title, value: selection.value }
    projectionLabel = '点击时流水线观测（非当前 BFF 记录）'
    summary = <><Text type="secondary">点击时观测，不随任务快照刷新；非当前执行记录，非逐阶段验签结果。</Text>
      <pre className="projection-json">{JSON.stringify(selection.value, null, 2)}</pre></>
  }

  const download = () => {
    const url = URL.createObjectURL(new Blob([JSON.stringify(raw, null, 2)], { type: 'application/json' }))
    const link = document.createElement('a'); link.href = url; link.download = `agentguard-${requestedSelection?.kind ?? 'record'}.json`; link.click()
    URL.revokeObjectURL(url)
  }

  return <Drawer open={Boolean(requestedSelection)} onClose={onClose} title={title} width="min(720px, 100vw)" destroyOnHidden
    className="evidence-drawer" extra={<>{onBack ? <LiquidGlassButton size="small" icon={<ArrowLeft size={16} />} aria-label="返回上一条记录" title="返回上一条记录" onClick={onBack} /> : null}<Tag bordered={false}>只读记录</Tag></>}>
    <div data-testid="evidence-detail">
      <Tabs key={`${selection?.kind}-${title}`} defaultActiveKey="summary" items={[
        { key: 'summary', label: '详情', children: summary ?? <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="等待任务记录" /> },
        ...(related ? [{ key: 'related', label: <span className="tab-label"><ExternalLink size={14} />关联记录</span>, children: related }] : []),
        { key: 'projection', label: '投影 JSON', children: <>
          <div className="projection-header"><Tooltip title="规划记录使用模型展示别名；导出保留实际模型字段"><span>{projectionLabel}</span></Tooltip><LiquidGlassButton icon={<Download size={14} />} onClick={download}>导出原始记录</LiquidGlassButton></div>
          <pre className="projection-json" data-testid="evidence-json">{JSON.stringify(selection && ['agent', 'workflow', 'trace'].includes(selection.kind) ? displayProjection(raw) : raw, null, 2)}</pre>
        </> },
      ]} />
    </div>
  </Drawer>
}
