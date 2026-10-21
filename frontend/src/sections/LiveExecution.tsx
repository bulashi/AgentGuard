import { customerLabel } from '../customerDisplay'
import { CustomerName } from '../components/CustomerName'
import { useEffect, useMemo, useRef, useState, type RefObject } from 'react'
import { Button, Empty, Grid, Segmented, Slider, Tooltip } from 'antd'
import { Background, Controls, Handle, MarkerType, Position, ReactFlow, useNodesInitialized, useReactFlow, useStore, type Edge, type Node, type NodeProps } from '@xyflow/react'
import { Activity, ArrowDown, ArrowUpRight, Bot, Check, ChevronLeft, ChevronRight, FileCheck2, KeyRound, LocateFixed, Pause, Play, RotateCcw, ShieldCheck, Wallet, Wrench } from 'lucide-react'
import type { DemoRunState } from '../App'
import type { EvidenceSelection, StageKey } from '../executionModel'
import { buildExecutionSteps, credentialLevel, executionForTrace, runOutcome } from '../executionModel'
import { Fen, StatusTag } from '../components/Evidence'
import { observeCredential } from '../credentialObservation'
import { observeReceipt, receiptEvidenceIsConsistent } from '../sourceVerification'
import { auditPrefixSummary, type AuditPrefixReport } from '../auditPrefixBinding'
import type { DemoResult, Overview, TaskSnapshot } from '../types'
import { businessOutcome } from '../workflowModel'

const STAGES: Array<{ key: StageKey; title: string; icon: typeof Bot }> = [
  { key: 'request', title: '任务请求', icon: FileCheck2 },
  { key: 'authorization', title: '根授权', icon: KeyRound },
  { key: 'agents', title: '智能体委托', icon: Bot },
  { key: 'gateway', title: '安全网关', icon: ShieldCheck },
  { key: 'tools', title: '受保护工具', icon: Wrench },
  { key: 'evidence', title: '回执与审计', icon: FileCheck2 },
]

type StageState = 'pending' | 'active' | 'complete' | 'denied'
type StageData = { stage: StageKey; title: string; subtitle: string; caption: string; state: StageState; vertical: boolean; onInspect: () => void }
type StageFlowNode = Node<StageData, 'stage'>

function StageButton({ data }: { data: StageData }) {
  const Icon = STAGES.find((item) => item.key === data.stage)?.icon ?? FileCheck2
  return <button type="button" className={`stage-button stage-${data.state} nodrag`} onClick={data.onInspect}
      data-testid={`stage-${data.stage}`} aria-label={`查看${data.title}详情`}>
      <div className="stage-top"><span className="stage-icon"><Icon size={20} /></span><span className="stage-state-dot">{data.state === 'complete' ? <Check size={12} /> : null}</span></div>
      <strong>{data.title}</strong><span className="stage-subtitle" title={data.subtitle}>{data.subtitle}</span>
      <div className="stage-caption"><span>{data.caption}</span><ArrowUpRight size={13} /></div>
    </button>
}

function StageNode({ data }: NodeProps<StageFlowNode>) {
  return <><Handle type="target" position={Position.Left} /><StageButton data={data} /><Handle type="source" position={Position.Right} /></>
}

const NODE_TYPES = { stage: StageNode }

function FitOnLayout({ host }: { host: RefObject<HTMLDivElement | null> }) {
  const initialized = useNodesInitialized()
  const { fitView } = useReactFlow()
  const width = useStore((state) => state.width)
  const height = useStore((state) => state.height)
  const geometry = useStore((state) => [...state.nodeLookup.values()].map((node) => `${node.position.x},${node.position.y},${node.measured?.width},${node.measured?.height}`).join(';'))
  useEffect(() => {
    if (!initialized || !host.current) return
    let frame = 0
    const fit = () => {
      cancelAnimationFrame(frame)
      frame = requestAnimationFrame(() => { void fitView({ padding: 0.04, maxZoom: 1 }) })
    }
    const observer = new ResizeObserver(fit)
    observer.observe(host.current)
    fit()
    return () => { observer.disconnect(); cancelAnimationFrame(frame) }
  }, [fitView, geometry, height, host, initialized, width])
  return null
}

export function LiveExecution({ snapshot, demo, runState, auditPrefix = null, onInspect, onHistory, observedAt = Date.now() / 1000 }: {
  snapshot: TaskSnapshot | null; demo: DemoResult | null; runState: DemoRunState; overview: Overview | null
  onInspect: (selection: EvidenceSelection) => void; onHistory: () => void
  observedAt?: number
  auditPrefix?: AuditPrefixReport | null
}) {
  const matchingDemo = demo?.task_id === snapshot?.task.task_id ? demo : null
  const steps = useMemo(() => runState.phase === 'requesting' ? [] : buildExecutionSteps(snapshot, matchingDemo), [snapshot, matchingDemo, runState.phase])
  const [cursor, setCursor] = useState(matchingDemo ? 0 : steps.length)
  const [playing, setPlaying] = useState(Boolean(matchingDemo))
  const [speed, setSpeed] = useState(1)
  const graphHost = useRef<HTMLDivElement>(null)
  const screens = Grid.useBreakpoint()
  const vertical = !screens.md
  const current = cursor > 0 ? steps[Math.min(cursor - 1, steps.length - 1)] : undefined
  const failureIndex = steps.findIndex((step) => ['DENIED', 'DENY', 'FAILED', 'INVALID'].includes(step.status))
  const requesting = runState.phase === 'requesting'
  const outcome = runOutcome(snapshot)
  const outcomeEvidence = businessOutcome(snapshot)
  const denied = outcome.status === 'DENIED' || outcomeEvidence.status === 'BUSINESS_STOPPED'
  const validReceipts = snapshot?.receipts.filter(receiptEvidenceIsConsistent).length ?? 0
  const prefix = auditPrefixSummary(snapshot?.task.task_id ?? '', snapshot?.audit_events ?? [], auditPrefix)
  const refundFen = outcomeEvidence.refundFen
  const root = snapshot?.credentials.find((item) => item.credential_type === 'ROOT')
  const rootObservation = observeCredential(root, snapshot?.credentials ?? [], observedAt)
  const refundBudget = root?.budgets.find((item) => item.quota_type === 'refund_total_fen')

  useEffect(() => {
    if (!playing || !steps.length) return
    const timer = window.setTimeout(() => {
      if (cursor >= steps.length) { setPlaying(false); return }
      setCursor(cursor + 1)
      if (cursor + 1 >= steps.length) setPlaying(false)
    }, 750 / speed)
    return () => window.clearTimeout(timer)
  }, [cursor, playing, speed, steps.length])

  const inspect = (selection: EvidenceSelection) => { setPlaying(false); onInspect(selection) }
  const seek = (value: number) => { setPlaying(false); setCursor(value) }
  const graph = useMemo(() => {
    const visible = steps.slice(0, cursor)
    const atEnd = steps.length > 0 && cursor >= steps.length
    const observedIds = new Set(visible.flatMap((step) => {
      const selected = step.selection
      if (selected.kind === 'execution') return [selected.execution.execution_id]
      if (selected.kind === 'audit') return [selected.event.execution_id]
      if (selected.kind === 'receipt') return [selected.receipt.execution_id]
      if (selected.kind === 'trace') {
        const execution = executionForTrace(snapshot, selected.step)
        return execution ? [execution.execution_id] : []
      }
      return []
    }))
    const observedExecutions = snapshot?.executions.filter((item) => atEnd || observedIds.has(item.execution_id)) ?? []
    const allowed = observedExecutions.some((item) => item.decision === 'ALLOW')
    const blocked = observedExecutions.some((item) => item.decision === 'DENY')
    const committed = observedExecutions.some((item) => item.state === 'COMMITTED')
    const credentials = snapshot?.credentials ?? []
    const levels = credentials.map((item) => credentialLevel(item, credentials)).filter((level): level is number => level !== null)
    const actualDepth = Math.max(0, ...levels)
    const nodes: StageFlowNode[] = STAGES.map((stage, index) => {
      const relevant = visible.filter((step) => step.stage === stage.key)
      let state: StageState = relevant.length ? 'complete' : 'pending'
      if (stage.key === 'request' && snapshot) state = 'complete'
      if (current?.stage === stage.key && playing) state = 'active'
      if (relevant.some((step) => ['DENIED', 'DENY', 'FAILED', 'INVALID'].includes(step.status))) state = 'denied'
      if (stage.key === 'evidence' && atEnd && snapshot?.receipts.length) {
        state = validReceipts === snapshot.receipts.length ? 'complete'
          : snapshot.receipts.some((receipt) => observeReceipt(receipt).status === 'INVALID') ? 'denied' : 'pending'
      }
      if (stage.key === 'gateway' && (allowed || blocked)) state = blocked ? 'denied' : 'complete'
      if (stage.key === 'tools' && blocked && !allowed) state = 'pending'
      if (stage.key === 'tools' && committed && atEnd) state = 'complete'
      if (stage.key === 'tools' && outcomeEvidence.status === 'BUSINESS_STOPPED' && atEnd) state = 'denied'
      if (stage.key === 'agents' && atEnd && credentials.length > 1) state = 'complete'
      if (requesting) state = index === 0 ? 'active' : 'pending'
      if (stage.key === 'authorization' && root && !requesting) state = rootObservation.windowOpen ? 'complete'
        : ['NOT_YET_VALID', 'EXPIRED'].includes(rootObservation.code) ? 'pending' : 'denied'
      const subtitles: Record<StageKey, string> = {
        request: snapshot ? `${snapshot.task.ticket_id} / ${customerLabel(snapshot.task.customer_id)}` : '工单与客户',
        authorization: root ? `SM2 签名 · 可再委托 ${root.delegation_depth} 级` : '等待人工确认',
        agents: credentials.length ? `${new Set(credentials.map((item) => item.holder_agent_id)).size} 个持有者 · ${actualDepth ? `${actualDepth} 级委托` : '无子委托'}` : '权限逐级收窄',
        gateway: blocked ? '存在拒绝记录' : '验签 · 原子准入 · 预算',
        tools: snapshot?.executions.length ? `${snapshot.executions.length} 次请求 · ${outcomeEvidence.status === 'COMPLETED' && refundFen ? `退款 ${refundFen / 100} 元` : outcomeEvidence.label}` : outcomeEvidence.status === 'BUSINESS_STOPPED' ? '业务核验未通过 · 未分发' : '工单 / 知识 / 退款 / 通知',
        evidence: `${validReceipts} 份核对一致回执 · ${snapshot?.audit_events.length ?? 0} 个事件`,
      }
      return { id: stage.key, type: 'stage', draggable: false, selectable: false,
        initialWidth: 210, initialHeight: 164,
        position: { x: index * 244 + 30, y: 65 },
        data: { stage: stage.key, title: stage.title, subtitle: subtitles[stage.key], state, vertical,
          caption: stage.key === 'authorization' && root && !requesting ? `${rootObservation.label} · 快照观测`
            : stage.key === 'tools' && outcomeEvidence.status === 'BUSINESS_STOPPED' ? '业务核验未通过 · 未分发'
            : stage.key === 'tools' && blocked && !allowed ? '网关拒绝 · 未分发'
            : stage.key === 'agents' && atEnd && credentials.length === 1 ? '本次无子委托'
              : state === 'active' ? requesting ? '请求中' : '回放到此步骤' : state === 'denied' ? '拒绝证据' : state === 'complete' ? '查看记录' : '等待记录',
          onInspect: () => { setPlaying(false); onInspect({ kind: 'stage', stage: stage.key }) } },
      }
    })
    const edges: Edge[] = nodes.slice(0, -1).map((node, index) => {
      const active = playing && current?.stage === nodes[index + 1].id
      const complete = node.data.state === 'complete' || node.data.state === 'active'
      return { id: `${node.id}-${nodes[index + 1].id}`, source: node.id, target: nodes[index + 1].id,
        type: 'smoothstep', animated: active, className: active ? 'run-edge-active' : '',
        markerEnd: { type: MarkerType.ArrowClosed, width: 18, height: 18 },
        style: { stroke: active ? 'var(--accent)' : complete ? 'var(--success)' : 'var(--line)', strokeWidth: active ? 2.5 : 1.6 },
      }
    })
    return { nodes, edges }
  }, [cursor, current?.stage, denied, onInspect, outcomeEvidence.status, playing, refundFen, requesting, root, rootObservation.code, rootObservation.label, rootObservation.windowOpen, snapshot, steps, validReceipts, vertical])

  return <section data-testid="live-execution" className="run-workspace">
    <div className="run-summary-row">
      <div className="run-summary-main"><span className="run-kicker">{matchingDemo ? matchingDemo.planner === 'llm' ? 'AI 规划运行' : '四智能体协作' : '已保存的运行记录'}</span>
        <h2>{snapshot ? `工单 ${snapshot.task.ticket_id}` : '新的受控任务'}<span>{snapshot ? <CustomerName id={snapshot.task.customer_id} /> : '等待任务'}</span></h2>
        <button type="button" className="text-link" onClick={() => inspect({ kind: 'task' })} disabled={!snapshot}>任务详情<ArrowUpRight size={13} /></button>
      </div>
      <div className={`run-outcome ${denied ? 'is-denied' : ''}`} data-testid="execution-decision"><span className="outcome-icon"><ShieldCheck size={22} /></span>
        <div><small>业务裁决</small><strong>{requesting ? '处理中' : playing && cursor < steps.length ? '回放中' : outcomeEvidence.label}</strong>
          <span>{requesting || playing && cursor < steps.length ? '等待最终结果' : outcomeEvidence.detail}</span></div>
      </div>
    </div>

    <div className="run-facts" aria-label="当前任务证据摘要">
      <button type="button" onClick={() => inspect({ kind: 'stage', stage: 'agents' })}><Bot size={15} /><span>授权凭证</span><strong>{snapshot?.credentials.length ?? 0}</strong></button>
      <button type="button" onClick={() => inspect({ kind: 'stage', stage: 'gateway' })}><Wrench size={15} /><span>工具请求</span><strong>{snapshot?.executions.length ?? 0}</strong></button>
      <button type="button" onClick={() => inspect({ kind: 'stage', stage: 'evidence' })}><FileCheck2 size={15} /><span>核对一致回执</span><strong>{validReceipts}</strong></button>
      <button type="button" onClick={() => inspect({ kind: 'stage', stage: 'evidence' })}><ShieldCheck size={15} /><span>审计事件</span><strong>{snapshot?.audit_events.length ?? 0}</strong></button>
    </div>

    <div className="run-graph-band">
      <div className="graph-heading"><div><Activity size={16} /><h3>授权到业务效果</h3><span className={`graph-mode ${requesting || playing ? 'is-active' : ''}`}><i />{requesting ? '等待服务响应' : matchingDemo ? '服务轨迹回放' : '持久化事件回放'}</span></div>
        <Button type="text" icon={<RotateCcw size={14} />} onClick={() => { setCursor(0); setPlaying(true) }} disabled={!steps.length}>重放</Button>
      </div>
      <div ref={graphHost} className={`run-graph ${vertical ? 'vertical' : ''}`} data-testid="execution-flow">
        {vertical ? <ol className="mobile-stage-chain" aria-label="任务执行图">{graph.nodes.map((node, index) => <li key={node.id}>
          <StageButton data={node.data} />{index < graph.nodes.length - 1 ? <span className={`mobile-connector ${playing && current?.stage === graph.nodes[index + 1].id ? 'active' : ''}`}><ArrowDown size={17} /></span> : null}
        </li>)}</ol> : <div className="run-graph-desktop"><ReactFlow nodes={graph.nodes} edges={graph.edges} nodeTypes={NODE_TYPES}
          fitView fitViewOptions={{ padding: 0.04 }} nodesConnectable={false} nodesDraggable={false} elementsSelectable={false}
          minZoom={0.3} maxZoom={1.2} zoomOnDoubleClick={false} panOnScroll
          ariaLabelConfig={{ 'controls.zoomIn.ariaLabel': '放大执行图', 'controls.zoomOut.ariaLabel': '缩小执行图', 'controls.fitView.ariaLabel': '适应全部执行节点' }}>
          <Background color="var(--line)" gap={24} size={1} />
          <FitOnLayout host={graphHost} />
          <Controls showInteractive={false} />
        </ReactFlow></div>}
      </div>
      <div className="replay-controls">
        <div className="replay-buttons">
          <Tooltip title="上一步"><Button type="text" icon={<ChevronLeft size={17} />} onClick={() => seek(Math.max(0, cursor - 1))} disabled={!cursor || requesting} aria-label="上一步" /></Tooltip>
          <Tooltip title={playing ? '暂停回放' : '播放回放'}><Button type="primary" icon={playing ? <Pause size={16} /> : <Play size={16} />} aria-label={playing ? '暂停回放' : '播放回放'}
            disabled={!steps.length || requesting} onClick={() => { if (cursor >= steps.length) setCursor(0); setPlaying(!playing) }} /></Tooltip>
          <Tooltip title="下一步"><Button type="text" icon={<ChevronRight size={17} />} onClick={() => seek(Math.min(steps.length, cursor + 1))} disabled={cursor >= steps.length || requesting} aria-label="下一步" /></Tooltip>
        </div>
        <div className="replay-slider"><Slider min={0} max={Math.max(1, steps.length)} value={cursor} onChange={seek} disabled={!steps.length || requesting}
          tooltip={{ formatter: (value) => `步骤 ${value} / ${steps.length}` }} ariaLabelForHandle="回放进度" /><span data-testid="replay-position">{cursor} / {steps.length}</span></div>
        <Segmented value={speed} onChange={(value) => setSpeed(Number(value))} options={[{ label: '1×', value: 1 }, { label: '2×', value: 2 }]} size="small" aria-label="回放速度" />
        <Tooltip title="定位首个失败步骤"><Button type="text" icon={<LocateFixed size={16} />} disabled={failureIndex < 0 || requesting}
          aria-label="定位失败步骤" onClick={() => { seek(failureIndex + 1); onInspect(steps[failureIndex].selection) }} /></Tooltip>
      </div>
    </div>

    <div className="run-bottom-layout">
      <section className="run-events">
        <div className="band-heading"><h3>步骤记录 <span>{steps.length}</span></h3><Button type="text" size="small" onClick={onHistory} icon={<ArrowUpRight size={14} />}>历史记录</Button></div>
        {steps.length ? <div className="run-step-list" data-testid="run-step-list">{steps.map((step, index) => <button key={step.id} type="button"
          data-testid={`run-step-${index + 1}`} className={`run-step ${cursor === index + 1 ? 'current' : ''} ${index >= cursor ? 'upcoming' : ''}`}
          onClick={() => { seek(index + 1); onInspect(step.selection) }}>
          <span className={`step-number ${['DENIED', 'FAILED', 'INVALID'].includes(step.status) ? 'denied' : ''}`}>{String(index + 1).padStart(2, '0')}</span>
          <span className="step-copy"><strong>{step.title}</strong><small>{step.subtitle}</small></span><StatusTag value={step.status} /><ArrowUpRight size={14} />
        </button>)}</div> : <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={requesting ? '等待后端返回真实运行记录' : '尚无步骤记录'} />}
      </section>
      <section className="run-result-band">
        <div className="band-heading"><h3>业务与安全结果</h3><ShieldCheck size={17} /></div>
        <button className="result-row" type="button" onClick={() => inspect({ kind: 'stage', stage: 'tools' })}><span>{outcomeEvidence.status === 'COMPLETED' ? '退款已提交' : '退款未执行'}</span><strong>{outcomeEvidence.status === 'COMPLETED' ? <Fen value={refundFen} /> : outcomeEvidence.status === 'UNKNOWN' ? '待确认' : '0.00 元'}</strong><ArrowUpRight size={14} /></button>
        <button className="result-row" type="button" onClick={() => inspect({ kind: 'stage', stage: 'tools' })}><span>{outcomeEvidence.notificationCount ? '通知已发送' : '通知未发送'}</span><strong>{outcomeEvidence.notificationCount} 条</strong><ArrowUpRight size={14} /></button>
        <button className="result-row" type="button" onClick={() => inspect({ kind: 'stage', stage: 'authorization' })}><Wallet size={15} /><span>根授权剩余额度</span><strong>{refundBudget ? <Fen value={refundBudget.remaining} /> : '未记录'}</strong><ArrowUpRight size={14} /></button>
        <button className="result-row audit-prefix-result" type="button" onClick={() => inspect({ kind: 'stage', stage: 'evidence' })}><span>逐事件前缀覆盖</span><strong>{prefix.anchored}/{prefix.total}</strong><StatusTag value={prefix.status} label={prefix.label} /><ArrowUpRight size={14} /></button>
        <div className="current-step-note"><span>当前回放位置</span><strong>{current?.title ?? '起点'}</strong><small>{typeof current?.timestamp === 'number' ? new Date(current.timestamp * 1000).toLocaleString('zh-CN', { hour12: false }) : matchingDemo ? '服务返回的步骤顺序' : '记录时间'}</small></div>
      </section>
    </div>
  </section>
}
