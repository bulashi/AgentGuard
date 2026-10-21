import type { ReactNode } from 'react'
import { Collapse, Descriptions, Empty } from 'antd'
import { ArrowUpRight, FileText } from 'lucide-react'
import type { EvidenceSelection } from '../executionModel'
import { agentLabel, reasonLabel, toolLabel } from '../labels'
import type { TaskSnapshot, WorkflowEvent, WorkflowRun } from '../types'
import { activeWorkflow, AGENT_DUTIES, agentNodeState, eventTitle, modelDisplayLabel, MODE_LABELS, NODE_STATE_LABELS, PROPOSAL_STAGE_LABELS, STAGE_LABELS, workflowBusinessResults, workflowEventState } from '../workflowModel'
import { WorkflowEventStatusTag } from './WorkflowStatusTag'
import { RefundVerificationFacts } from './RefundVerificationFacts'
import { Fen, ShortHash } from './Evidence'

function Fields({ items }: { items: Array<[string, ReactNode]> }) {
  return <Descriptions column={1} size="small" colon={false} className="detail-fields"
    items={items.map(([label, children]) => ({ key: label, label, children: children ?? '未记录' }))} />
}

function object(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : {}
}

function Knowledge({ value }: { value: unknown }) {
  const data = object(value)
  const documents = Array.isArray(data.documents) ? data.documents.map(object) : []
  const injection = object(data.demo_injection)
  return <div className="knowledge-detail">{typeof data.summary === 'string' ? <p>{data.summary}</p> : null}
    {data.demo_injection ? <div className="knowledge-injection-note">
      <p>本次知识返回副本含{injection.source === 'custom' ? '自定义' : '预设'}不可信资料；原始关联文档保留用于核对。</p>
      {typeof injection.text === 'string' ? <pre style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{injection.text}</pre> : null}
      <Fields items={[
        ['材料 SM3', typeof injection.text_sm3 === 'string' ? <ShortHash value={injection.text_sm3} /> : '历史记录未保存'],
        ['原始返回 SM3', typeof injection.original_result_sm3 === 'string' ? <ShortHash value={injection.original_result_sm3} /> : '未记录'],
        ['注入后返回 SM3', typeof injection.injected_result_sm3 === 'string' ? <ShortHash value={injection.injected_result_sm3} /> : '历史记录未保存'],
      ]} />
    </div> : null}
    {documents.map((document, index) => <div className="knowledge-document" key={String(document.document_id ?? index)}>
      <strong><FileText size={14} />{String(document.title ?? '关联文档')}</strong><small>{String(document.document_id ?? '')}</small><p>{String(document.content ?? '')}</p>
    </div>)}
    {!documents.length ? <p className="detail-muted">未记录知识正文</p> : null}
  </div>
}

function PlanningInput({ value }: { value: unknown }) {
  const input = object(value)
  const authorized = object(input.authorized_task)
  const ticket = object(input.ticket)
  const refund = object(input.committed_refund)
  return <>
    <Fields items={[
      ['授权工单', String(authorized.ticket_id ?? '未记录')], ['授权客户', String(authorized.customer_id ?? '未记录')],
      ['授权退款金额', typeof authorized.refund_amount_fen === 'number' ? <Fen value={authorized.refund_amount_fen} /> : '未记录'],
    ]} />
    {Object.keys(ticket).length ? <><h4 className="detail-subheading">实际工单结果</h4><Fields items={[
      ['工单标题', String(ticket.title ?? '未记录')], ['工单描述', String(ticket.description ?? '未记录')], ['工单客户', String(ticket.customer_id ?? '未记录')],
    ]} /></> : null}
    {Object.keys(ticket).length ? <RefundVerificationFacts value={ticket.refund_verifications} ticket={ticket} /> : null}
    {Object.keys(object(input.knowledge)).length ? <><h4 className="detail-subheading">传入的知识上下文</h4><Knowledge value={input.knowledge} /></> : null}
    {Object.keys(refund).length ? <><h4 className="detail-subheading">已提交的退款结果</h4><Fields items={[
      ['退款编号', <ShortHash value={String(refund.refund_id ?? '')} />], ['退款金额', typeof refund.amount_fen === 'number' ? <Fen value={refund.amount_fen} /> : '未记录'],
    ]} /></> : null}
    {input.untrusted_prompt_text ? <><h4 className="detail-subheading">不可信提示输入</h4><p className="detail-text">{String(input.untrusted_prompt_text)}</p></> : null}
  </>
}

function IntentDetails({ value }: { value: unknown }) {
  const intents = Array.isArray(value) ? value.map(object) : []
  if (!intents.length) return <p className="detail-muted">此阶段不直接提出工具动作</p>
  return <>{intents.map((intent, index) => <div className="intent-detail" key={index}>
    <strong>{toolLabel(String(intent.name))}</strong><small className="mono">{String(intent.service)} / {String(intent.name)}@{String(intent.version)}</small>
    <Fields items={Object.entries(object(intent.parameters)).map(([key, item]) => [
      ({ ticket_id: '工单', customer_id: '客户', amount_fen: '退款金额', template_id: '通知模板', related_business_effect_id: '关联退款' } as Record<string, string>)[key] ?? key,
      key === 'amount_fen' && typeof item === 'number' ? <Fen value={item} /> : String(item),
    ])} />
  </div>)}</>
}

function PlanningDetails({ event }: { event: WorkflowEvent }) {
  const details = event.details
  const intents = Array.isArray(details.intents) ? details.intents.map(object) : []
  const refund = intents.find((intent) => intent.name === 'refund.create')
  const decision = details.decision === 'decline' ? '停止后续执行'
    : event.status !== 'COMPLETED' ? '规划未通过'
      : intents.length ? '已提出候选动作' : '本阶段不调用工具'
  return <Fields items={[
    ['规划阶段', PROPOSAL_STAGE_LABELS[String(details.stage)] ?? String(details.stage ?? '未记录')],
    ['规划决定', decision],
    ['退款候选', refund ? <IntentDetails value={[refund]} /> : '本阶段没有退款候选'],
  ]} />
}

export function PlanningQuote({ event }: { event: WorkflowEvent }) {
  const summary = event.details.summary ?? event.details.message
  return typeof summary === 'string' ? <Collapse ghost className="planning-quote" items={[{
    key: 'original', label: '规划时点原文',
    extra: <small>第 {event.sequence} 条 · {new Date(event.timestamp_ms).toLocaleTimeString('zh-CN', { hour12: false })}</small>,
    children: <div className="agent-public-summary"><p>{summary}</p></div>,
  }]} /> : null
}

export function WorkflowBusinessOutcome({ snapshot, events = [], replay = false }: {
  snapshot: TaskSnapshot | null; events?: WorkflowEvent[]; replay?: boolean
}) {
  const result = workflowBusinessResults(snapshot, events, replay)
  return <section className="workflow-business-outcome" data-testid="workflow-business-outcome">
    <h3>{replay ? '回放位置的业务结果' : '当前业务结果'}</h3>
    <div>{([result.refund, result.notification]).map((item, index) => <div key={index} className={`business-result result-${item.state}`}>
      <strong>{item.label}</strong><span>{item.amountFen !== undefined ? <Fen value={item.amountFen} /> : item.count > 0 ? `${item.count} 条` : null}</span>
    </div>)}</div>
  </section>
}

export function WorkflowEventDetails({ event, run }: { event: WorkflowEvent; run: WorkflowRun }) {
  const details = event.details
  const output = object(details.output)
  return <>
    <Fields items={[
      ['事件序号', event.sequence], ['角色', agentLabel(event.agent_id)], ['处理动作', eventTitle(event)],
      ['状态', <WorkflowEventStatusTag event={event} />], ['运行模式', MODE_LABELS[run.runtime_mode]],
      ['事件时间', new Date(event.timestamp_ms).toLocaleString('zh-CN', { hour12: false })],
      ['存储时间', new Date(event.recorded_at_ms).toLocaleString('zh-CN', { hour12: false })],
      ['运行编号', <ShortHash value={run.run_id} />], ['证据类型', '操作观测日志，非签名回执或审计链'],
    ]} />
    {event.action === 'plan' ? <PlanningDetails event={event} /> : null}
    {event.action === 'business_verification' ? <><h3 className="detail-heading">独立业务核验</h3><Fields items={[
      ['核验结论', details.status === 'VERIFIED' ? '核验通过，尚不代表已退款' : details.status === 'PENDING' ? '资料待核验，未退款' : '不符合退款条件，未退款'],
      ['具体原因', String(details.reason ?? '未记录')], ['本次可退金额', typeof details.refundable_amount_fen === 'number' ? <Fen value={details.refundable_amount_fen} /> : '未记录'],
      ['原交易', String(details.original_transaction_id ?? '无可退交易')], ['规则版本', String(details.policy_version ?? '未记录')],
      ['原始事实摘要', typeof details.facts_hash === 'string' ? <ShortHash value={details.facts_hash} /> : '未记录'],
      ['依据编号', Array.isArray(details.evidence_ids) ? details.evidence_ids.join('、') : '未记录'],
    ]} /></> : null}
    <PlanningQuote event={event} />
    {details.reason_code ? <div className={`detail-verdict ${workflowEventState(event) === 'denied' ? 'denied' : workflowEventState(event) === 'stopped' ? 'stopped' : event.status === 'COMPLETED' ? 'allowed' : 'pending'}`}><strong>{reasonLabel(String(details.reason_code))}</strong><code>{String(details.reason_code)}</code></div> : null}
    {details.stage ? <><h3 className="detail-heading">规划溯源</h3><Fields items={[
      ['阶段', STAGE_LABELS[String(details.stage)] ?? String(details.stage)],
      ['请求引擎', modelDisplayLabel(details.model_requested ?? run.model)],
      ['实际请求型号', typeof details.model_requested === 'string' ? details.model_requested : run.model ?? '无大模型调用'],
      ['实际返回型号', typeof details.model_returned === 'string' ? details.model_returned : run.runtime_mode === 'deterministic' ? '规则规划，无模型调用' : '本事件未记录模型返回'],
      ['调用耗时', typeof details.duration_ms === 'number' ? `${details.duration_ms} ms` : '未记录'],
      ['输入 / 输出 Token', details.prompt_eval_count != null ? `${details.prompt_eval_count} / ${details.eval_count ?? '未记录'}` : '未记录'],
      ['响应 SM3', typeof details.response_sm3 === 'string' ? <ShortHash value={details.response_sm3} /> : '未记录'],
      ['提示词版本', typeof details.prompt_profile === 'string' ? details.prompt_profile : '此记录未保存'],
      ['提示消息 SM3', typeof details.prompt_messages_sm3 === 'string' ? <ShortHash value={details.prompt_messages_sm3} /> : '此记录未保存'],
      ['思考模式设置', details.thinking_mode === 'disabled' ? '显式非思考模式，仍非确定性模型' : '本事件未记录此设置'],
    ]} /></> : null}
    {details.intents ? <><h3 className="detail-heading">候选工具动作</h3><IntentDetails value={details.intents} /></> : null}
    {details.parameters ? <><h3 className="detail-heading">请求参数 · 操作观测</h3><IntentDetails value={[{ name: details.tool, service: details.tool_service ?? '旧记录未保存服务', version: details.tool_version ?? '旧记录未保存版本', parameters: details.parameters }]} /></> : null}
    <Collapse ghost className="workflow-input-collapse" items={[
      ...(typeof details.system_prompt === 'string' ? [{ key: 'system-prompt', label: '实际系统提示词', children: <p className="detail-text">{details.system_prompt}</p> }] : []),
      ...(typeof details.user_prompt === 'string' ? [{ key: 'user-prompt', label: '实际任务消息', children: <pre className="inline-json">{details.user_prompt}</pre> }] : []),
      ...(details.output_schema ? [{ key: 'output-schema', label: '候选动作输出契约', children: <pre className="inline-json">{JSON.stringify(details.output_schema, null, 2)}</pre> }] : []),
      ...(details.input ? [{ key: 'input', label: '实际输入上下文', children: <PlanningInput value={details.input} /> }] : []),
      ...(details.output ? [{ key: 'output', label: '实际输出数据', children: Array.isArray(output.documents) ? <Knowledge value={output} /> : <pre className="inline-json">{JSON.stringify(details.output, null, 2)}</pre> }] : []),
    ]} />
  </>
}

export function WorkflowTimeline({ run, events = run.events, onSelect }: {
  run: WorkflowRun; events?: WorkflowEvent[]; onSelect: (selection: EvidenceSelection) => void
}) {
  return <div className="detail-workflow-timeline">{events.map((event) => <button type="button" key={event.sequence}
    onClick={() => onSelect({ kind: 'workflow', runId: run.run_id, sequence: event.sequence })}>
    <span className="mono">{String(event.sequence).padStart(2, '0')}</span><div><strong>{eventTitle(event)}</strong><small>{agentLabel(event.agent_id)} / {new Date(event.timestamp_ms).toLocaleTimeString('zh-CN', { hour12: false })}</small></div>
    <WorkflowEventStatusTag event={event} /><ArrowUpRight size={13} />
  </button>)}{!events.length ? <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="尚无已保存过程事件" /> : null}</div>
}

export function AgentProcessDetails({ agentId, snapshot, onSelect }: {
  agentId: string; snapshot: TaskSnapshot | null; onSelect: (selection: EvidenceSelection) => void
}) {
  const run = activeWorkflow(snapshot)
  const own = run?.events.filter((event) => event.agent_id === agentId) ?? []
  const plan = [...own].reverse().find((event) => event.action === 'plan')
  const credential = snapshot?.credentials.find((item) => item.holder_agent_id === agentId)
  return <>
    <Fields items={[
      ['角色职责', AGENT_DUTIES[agentId]], ['角色标识', <span className="mono">{agentId}</span>],
      ['签名身份', credential?.holder_key_id ?? '尚未收到该角色凭证'],
      ['过程状态', NODE_STATE_LABELS[agentNodeState(agentId, own, snapshot, run?.state === 'INTERRUPTED')]],
      ['运行模式', run ? MODE_LABELS[run.runtime_mode] : '旧任务未保存角色模式'],
      ['规划引擎', plan?.details.model_returned ? 'AI 规划器 · 已记录响应' : plan?.details.planner === 'deterministic' ? '确定性规则，无大模型调用' : '尚无实际模型返回记录'],
      ['规划调用', `${own.filter((event) => event.action === 'plan_started').length} 次`],
      ['安全边界', '角色提出动作；运行层签名；网关独立裁决；工具验签后执行'],
    ]} />
    <WorkflowBusinessOutcome snapshot={snapshot} />
    {plan ? <><h3 className="detail-heading">最近一次规划</h3><PlanningDetails event={plan} /><PlanningQuote event={plan} /></> : null}
    <h3 className="detail-heading">角色处理过程</h3>
    {run ? <WorkflowTimeline run={run} events={own} onSelect={onSelect} /> : <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="该旧任务没有持久化角色过程，不补造历史轨迹" />}
  </>
}

export function BusinessContextDetails({ resource, snapshot }: { resource: 'ticket' | 'knowledge'; snapshot: TaskSnapshot | null }) {
  if (resource === 'ticket') {
    const ticket = snapshot?.business_context?.ticket
    return ticket ? <><Fields items={[
      ['工单编号', ticket.ticket_id], ['客户编号', ticket.customer_id], ['业务标题', ticket.title], ['工单描述', ticket.description], ['工单状态', ticket.status],
    ]} /><RefundVerificationFacts value={ticket.refund_verifications} ticket={ticket} /></> : <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="尚无匹配工单摘要" />
  }
  const event = activeWorkflow(snapshot)?.events.find((item) => item.action === 'knowledge_result')
  return <><Fields items={[
    ['关联工单', snapshot?.task.ticket_id], ['知识文档数量', snapshot?.business_context?.documents.length ?? 0],
    ['读取内容', event?.details.injection_applied ? '含附加流程指令，原始文档保留' : event ? '原始关联文档' : '尚未读取'],
    ['原始工具结果 SM3', typeof event?.details.original_result_sm3 === 'string' ? <ShortHash value={event.details.original_result_sm3} /> : '尚未记录'],
  ]} />
    {event ? <Knowledge value={event.details.output} /> : <>{snapshot?.business_context?.documents.map((document) => <div className="knowledge-document" key={document.document_id}><strong>{document.title}</strong><small>{document.document_id} / {document.sensitivity}</small></div>)}
      <p className="detail-muted">这里只显示关联文档摘要。受控读取后才有本次协作使用的正文记录。</p></>}
  </>
}
