import { CustomerName } from '../components/CustomerName'
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Alert, App, Checkbox, Collapse, Empty, Input, Modal, Segmented, Select, Slider, Tooltip } from 'antd'
import { Background, BaseEdge, Handle, MarkerType, Panel, Position, ReactFlow, useNodesInitialized, useReactFlow, useStore } from '@xyflow/react'
import type { Edge, EdgeProps, Node, NodeProps } from '@xyflow/react'
import {
  ArrowDown, ArrowRight, ArrowUpRight, BookOpen, Bot, Check, ChevronRight,
  Cloud, FileText, GitBranch, History, Layers3, LoaderCircle, LockKeyhole,
  Maximize2, MessageSquare, Minus, Pause, Play, Plus, RotateCcw,
  Settings2, ShieldCheck, ShieldX, UsersRound, WalletCards,
} from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import { api, ApiError } from '../api'
import { ShortHash, StatusTag } from '../components/Evidence'
import { observeCredential } from '../credentialObservation'
import { ExecutionEvidenceRail } from '../components/ExecutionEvidenceRail'
import { LiquidGlassButton } from '../components/LiquidGlassButton'
import { ModelSettingsDialog } from '../components/ModelSettingsDialog'
import { WorkflowStatusTag } from '../components/WorkflowStatusTag'
import { RequestEvidencePanel } from '../components/RequestEvidencePanel'
import { PlanningQuote, WorkflowBusinessOutcome } from '../components/WorkflowDetails'
import type { EvidenceSelection } from '../executionModel'
import { agentLabel, reasonLabel, toolLabel } from '../labels'
import type { CoauthorizationStatus, CredentialView, RuntimeMode, RuntimeProfiles, TaskSnapshot, WorkflowEvent, WorkflowScenario, WorkflowStarted } from '../types'
import {
  activeWorkflow, AGENT_DUTIES, AGENT_IDS, agentNodeState, eventSummary, eventTitle,
  businessOutcome, gatewayNodeState, MODE_LABELS, NODE_STATE_LABELS, PROPOSAL_STAGE_LABELS, TOOL_NAMES, toolNodeState, visibleCredentials, visibleExecutions, workflowActiveRequest, workflowIsRunning, workflowStageStates,
  taskAuthorizationLabel,
} from '../workflowModel'
import type { NodeState } from '../workflowModel'

interface GraphData extends Record<string, unknown> {
  label: string; subtitle: string; icon: LucideIcon; state: NodeState; caption: string
  variant?: 'tool' | 'gateway'; stateLabel?: string; inspect: () => void
}

type BusinessNode = Node<GraphData, 'business'>

interface WorkflowStartIntent {
  taskId: string | null
  selectedTaskId: string | null
  mode: RuntimeMode
  scenario: WorkflowScenario
  coauthorizationRequired: boolean
  customInjectionText: string | null
}

const AGENT_ICONS: Record<string, LucideIcon> = {
  'agent-coordinator': GitBranch, 'agent-knowledge': BookOpen, 'agent-case': FileText, 'agent-refund': WalletCards,
}
const TOOL_ICONS: Record<string, LucideIcon> = {
  'knowledge.read_associated': BookOpen, 'ticket.read': FileText, 'refund.create': WalletCards, 'notification.send_template': MessageSquare,
}

function BusinessNodeCard({ data }: { data: GraphData }) {
  const Icon = data.icon
  const status = <span className={`collab-state state-${data.state}`}>{data.state === 'active' ? <LoaderCircle size={13} className="spin" /> : data.state === 'completed' ? <Check size={13} /> : null}{data.stateLabel ?? NODE_STATE_LABELS[data.state]}</span>
  if (data.variant === 'tool') return <button type="button" className={`collab-node node-tool node-${data.state}`}
    onClick={data.inspect} aria-label={`查看${data.label}`} data-testid={`collab-node-${data.label}`}>
    <span className="collab-icon"><Icon size={20} /></span>
    <div className="collab-tool-content"><strong>{data.label}</strong><span className="collab-subtitle">{data.subtitle}</span>{status}</div>
  </button>
  return <button type="button" className={`collab-node node-${data.state} ${data.variant ? `node-${data.variant}` : ''}`}
      onClick={data.inspect} aria-label={`查看${data.label}`} data-testid={`collab-node-${data.label}`} title={`查看${data.label}的处理记录`}>
      <div className="collab-node-head"><span className="collab-icon"><Icon size={18} /></span>
        {status}
      </div>
      <strong>{data.label}</strong><span className="collab-subtitle">{data.subtitle}</span>
      <small><span title={data.caption}>{data.caption}</span><ChevronRight size={12} /></small>
    </button>
}

function BusinessGraphNode({ id, data }: NodeProps<BusinessNode>) {
  return <><Handle type="target" position={Position.Left} /><BusinessNodeCard data={data} />
    <Handle type="source" position={Position.Right} />
    {id !== 'gateway' ? <Handle type="source" position={id === 'agent-case' ? Position.Bottom : Position.Right} id="tool-request" /> : <>
      <Handle type="target" position={Position.Left} id="knowledge-request" style={{ top: '28%' }} />
      <Handle type="target" position={Position.Left} id="refund-request" style={{ top: '50%' }} />
      <Handle type="target" position={Position.Left} id="case-request" style={{ top: '72%' }} />
    </>}
  </>
}

const NODE_TYPES = { business: BusinessGraphNode }

function RequestRoutes({ reverse = false, activeIndex = -1 }: { reverse?: boolean; activeIndex?: number }) {
  return <svg className={`layered-routes${activeIndex >= 0 ? ' routes-active' : ''}`} viewBox="0 0 800 64" preserveAspectRatio="none" aria-hidden="true">
    {[100, 300, 500, 700].map((x, index) => <path key={x} className={index === activeIndex ? 'route-active' : undefined}
      d={reverse ? `M400 0 V40 H${x} V64` : `M${x} 0 V24 H400 V64`} />)}
  </svg>
}

function WorkflowExecutionOrder({ snapshot, events, replay, onInspect }: {
  snapshot: TaskSnapshot | null; events: WorkflowEvent[]; replay: boolean; onInspect: (selection: EvidenceSelection) => void
}) {
  const run = activeWorkflow(snapshot)
  const stages = workflowStageStates(snapshot, events, replay)
  const stopped = !replay && ['DENIED', 'FAILED', 'INTERRUPTED'].includes(run?.state ?? '')
  return <section className="workflow-execution-order" data-testid="workflow-execution-order">
    <h3>执行顺序</h3>
    <ol>{stages.map((stage, index) => <li key={stage.id}>
      <button type="button" className={`workflow-order-step order-${stage.state}`} data-state={stage.state}
        disabled={!run || !stage.event} onClick={() => {
          if (run && stage.event) onInspect({ kind: 'workflow', runId: run.run_id, sequence: stage.event.sequence })
        }}>
        <span className="workflow-order-number">{index + 1}</span><span><strong>{stage.label}</strong>
          <small>{stage.state === 'waiting' ? stopped ? '未执行' : index === 0 ? '尚未开始' : '等待前序' : NODE_STATE_LABELS[stage.state]}</small></span>
        {stage.event ? <ArrowUpRight size={14} /> : null}
      </button>
      {index < stages.length - 1 ? <ArrowRight className="workflow-order-arrow" size={16} aria-hidden="true" /> : null}
    </li>)}</ol>
  </section>
}

function LayeredCollaboration({ nodes, credentials, onInspect, activeRequest, observedAt }: {
  nodes: BusinessNode[]; credentials: CredentialView[]; onInspect: (selection: EvidenceSelection) => void; activeRequest?: WorkflowEvent; observedAt: number
}) {
  const [tab, setTab] = useState('requests')
  const levelOf = (credential: CredentialView, visited = new Set<string>()): number => {
    if (!credential.parent_credential_id || visited.has(credential.credential_id)) return 0
    visited.add(credential.credential_id)
    const parent = credentials.find((item) => item.credential_id === credential.parent_credential_id)
    return parent ? Math.min(8, 1 + levelOf(parent, visited)) : 0
  }
  const levels = [...new Set(credentials.map((credential) => levelOf(credential)))].sort((a, b) => a - b)
  return <div className="layered-collaboration" data-testid="layered-collaboration">
    <Segmented value={tab} onChange={setTab} aria-label="协作图视角" options={[{ value: 'requests', label: '请求路径' }, { value: 'delegation', label: '委托链' }]} />
    {tab === 'requests' ? <div className="layered-request-map">
      <div className="layered-lane-heading"><h3>智能体协作</h3><span>四个独立角色身份</span></div>
      <div className="layered-agent-grid">{nodes.slice(1, 5).map((node) => <BusinessNodeCard key={node.id} data={node.data} />)}</div>
      <RequestRoutes activeIndex={AGENT_IDS.findIndex((id) => id === activeRequest?.agent_id)} />
      <div className="layered-gateway">{nodes.slice(5, 6).map((node) => <BusinessNodeCard key={node.id} data={node.data} />)}</div>
      <RequestRoutes reverse activeIndex={TOOL_NAMES.findIndex((tool) => tool === activeRequest?.details.tool)} />
      <div className="layered-tool-grid">{nodes.slice(6).map((node) => <BusinessNodeCard key={node.id} data={node.data} />)}</div>
    </div> : <div className="layered-delegation-map" data-testid="layered-delegation-map">
      {levels.length ? levels.map((level) => <div className="delegation-level" key={level}>
        <span className="delegation-level-label">{level === 0 ? '根授权' : `第 ${level} 级子委托`}</span>
        <div>{credentials.filter((credential) => levelOf(credential) === level).map((credential) => {
          const parent = credentials.find((item) => item.credential_id === credential.parent_credential_id)
          const observation = observeCredential(credential, credentials, observedAt)
          return <button type="button" className="delegation-credential" key={credential.credential_id} onClick={() => onInspect({ kind: 'credential', credential })}>
            <GitBranch size={19} /><strong>{agentLabel(credential.holder_agent_id)}</strong><span>{parent ? `${agentLabel(parent.holder_agent_id)} → ${agentLabel(credential.holder_agent_id)}` : credential.parent_credential_id ? '父凭证未投影' : '企业签发'}</span>
            <span>{observation.label}</span><ShortHash value={credential.credential_id} size={7} copyable={false} />
          </button>
        })}</div>
      </div>) : <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="当前任务尚无委托凭证" />}
    </div>}
  </div>
}

function RoutedEdge({ sourceX, sourceY, targetX, targetY, markerEnd, style, data, id }: EdgeProps) {
  // Separate request lanes stay outside role nodes; Tool branches share a dispatch bus.
  const busX = data?.route === 'dispatch' ? targetX - 18 : data?.route === 'knowledge' ? targetX - 50 : targetX - 18
  const path = data?.route === 'case'
    ? `M ${sourceX} ${sourceY} V ${sourceY + 34} H ${targetX - 10} V ${targetY} H ${targetX}`
    : `M ${sourceX} ${sourceY} H ${busX} V ${targetY} H ${targetX}`
  return <BaseEdge id={id} path={path} markerEnd={markerEnd} style={style} />
}

const EDGE_TYPES = { routed: RoutedEdge }

function GraphAutoFit() {
  const initialized = useNodesInitialized({ includeHiddenNodes: true })
  const width = useStore((state) => state.width)
  const height = useStore((state) => state.height)
  const { fitView, viewportInitialized } = useReactFlow()
  const fittedSize = useRef('')
  useEffect(() => {
    if (!initialized || !viewportInitialized || width <= 0 || height <= 0) return
    const size = `${width}:${height}`
    if (fittedSize.current === size) return
    // Wait for every handle to be measured; status polling must not reset zoom.
    const frame = window.requestAnimationFrame(() => {
      fittedSize.current = size
      void fitView({ padding: 0.02, minZoom: 1, maxZoom: 1 })
    })
    return () => window.cancelAnimationFrame(frame)
  }, [fitView, height, initialized, viewportInitialized, width])
  return null
}

function GraphControls() {
  const flow = useReactFlow()
  const duration = () => window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 0 : 180
  return <div className="glass-tool-strip">
    <Tooltip title="放大"><LiquidGlassButton size="small" icon={<Plus size={15} />} aria-label="放大协作图" onClick={() => void flow.zoomIn({ duration: duration() })} /></Tooltip>
    <Tooltip title="缩小"><LiquidGlassButton size="small" icon={<Minus size={15} />} aria-label="缩小协作图" onClick={() => void flow.zoomOut({ duration: duration() })} /></Tooltip>
    <Tooltip title="还原清晰视图"><LiquidGlassButton size="small" icon={<Maximize2 size={15} />} aria-label="适应协作图画布" onClick={() => void flow.fitView({ padding: 0.02, minZoom: 1, maxZoom: 1, duration: duration() })} /></Tooltip>
  </div>
}

function clock(value: number): string {
  return new Date(value).toLocaleTimeString('zh-CN', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

function credentialNodeState(code: string): NodeState {
  if (code === 'WINDOW_OPEN') return 'authorized'
  if (code === 'MISSING' || code === 'NOT_YET_VALID' || code === 'EXPIRED') return 'waiting'
  if (code === 'REVOKED' || code === 'ANCESTOR_REVOKED') return 'denied'
  return 'failed'
}

export function BusinessWorkspace({ snapshot, onInspect, onStarted, onHistory, onAuthorization, connectionError, taskReading = false, startWarning, onStartUnconfirmed, cloudReviewRequest = 0, configurationRevision = 0, observedAt = Date.now() / 1000, presentation = 'full' }: {
  snapshot: TaskSnapshot | null; onInspect: (selection: EvidenceSelection) => void
  onStarted: (started: WorkflowStarted) => Promise<void>; onHistory: () => void; onAuthorization?: () => void
  connectionError?: string | null
  taskReading?: boolean
  cloudReviewRequest?: number
  configurationRevision?: number
  startWarning?: string | null; onStartUnconfirmed?: (message: string, taskId: string | null) => void
  observedAt?: number
  presentation?: 'full' | 'layered' | 'controls'
}) {
  const { message: messageApi } = App.useApp()
  const [profiles, setProfiles] = useState<RuntimeProfiles | null>(null)
  const [profileError, setProfileError] = useState<string | null>(null)
  const [profileRefreshing, setProfileRefreshing] = useState(false)
  const [coauthorization, setCoauthorization] = useState<CoauthorizationStatus | null>(null)
  const [coauthorizationError, setCoauthorizationError] = useState<string | null>(null)
  const [coauthorizationRefreshing, setCoauthorizationRefreshing] = useState(true)
  const [modelSettingsOpen, setModelSettingsOpen] = useState(false)
  const profileRequest = useRef(0)
  const coauthorizationRequest = useRef(0)
  const [mode, setMode] = useState<RuntimeMode>('cloud')
  const modeSelected = useRef(false)
  const [scenario, setScenario] = useState<WorkflowScenario>('normal')
  const [injectionSource, setInjectionSource] = useState<'preset' | 'custom'>('preset')
  const [customInjectionText, setCustomInjectionText] = useState('')
  const selectedInjectionText = scenario === 'policy_injection' && injectionSource === 'custom' ? customInjectionText : null
  const invalidInjection = selectedInjectionText !== null && (!selectedInjectionText.trim() || selectedInjectionText.includes('\0') || Array.from(selectedInjectionText).length > 4096)
  const [starting, setStarting] = useState(false)
  const startInFlight = useRef(false)
  const mounted = useRef(true)
  const currentTaskId = useRef(snapshot?.task.task_id ?? null)
  currentTaskId.current = snapshot?.task.task_id ?? null
  const [localStartWarning, setLocalStartWarning] = useState<string | null>(null)
  const unconfirmedStart = startWarning ?? localStartWarning
  const [cloudModal, setCloudModal] = useState(false)
  const [cloudIntent, setCloudIntent] = useState<WorkflowStartIntent | null>(null)
  const [cloudConfirmed, setCloudConfirmed] = useState(false)
  const [replay, setReplay] = useState(false)
  const [cursor, setCursor] = useState(0)
  const [playing, setPlaying] = useState(false)
  const [speed, setSpeed] = useState(1)
  const [compact, setCompact] = useState(() => window.matchMedia('(max-width: 1000px)').matches)
  const run = activeWorkflow(snapshot)
  const runId = run?.run_id
  const runMode = run?.runtime_mode
  const runScenario = run?.scenario
  const running = workflowIsRunning(run)
  const events = useMemo(() => run?.events ?? [], [run])
  const visible = useMemo(() => replay ? events.slice(0, cursor) : events, [cursor, events, replay])
  const selectedProfile = profiles?.items.find((item) => item.mode === mode)
  const coauthorizationRequired = coauthorization?.enabled === true
  const coauthorizationReady = coauthorization !== null && !coauthorizationRefreshing
  const root = snapshot?.credentials.find((item) => item.credential_type === 'ROOT')
  const rootObservation = observeCredential(root, snapshot?.credentials ?? [], observedAt)
  const outcomeEvidence = businessOutcome(snapshot)
  const outcomeAlertType = outcomeEvidence.status === 'COMPLETED' ? 'success' as const
    : ['BUSINESS_STOPPED', 'DENIED', 'NO_EFFECT', 'INCONSISTENT'].includes(outcomeEvidence.status) ? 'warning' as const : 'info' as const
  const canStartAuthorizedAt = (now: number) => !!snapshot && snapshot.task.status === 'AUTHORIZED'
    && snapshot.credentials.filter((item) => item.credential_type === 'ROOT').length === 1
    && !!root && observeCredential(root, snapshot.credentials, now).windowOpen
    && root.holder_agent_id === 'agent-coordinator' && root.holder_key_id === 'agent-coordinator-key-01'
    && root.delegation_depth >= 2 && now < snapshot.task.expires_at
    && !(snapshot.workflow_runs?.length) && !snapshot.executions.length
    && !snapshot.business_effects.refunds.length && !snapshot.business_effects.notifications.length
  const canStartAuthorized = canStartAuthorizedAt(Date.now() / 1000)
  const currentTaskNeedsAuthorization = snapshot?.task.status === 'PENDING_AUTHORIZATION'
  const ticket = snapshot?.business_context?.ticket
  const currentAgent = [...visible].reverse().find((event) => event.action === 'plan_started')
  const currentPlan = [...visible].reverse().find((event) => event.action === 'plan')
  const activeRequest = !connectionError && (running || replay && playing && cursor < events.length)
    ? workflowActiveRequest(visible) : undefined
  const shownCredentials = visibleCredentials(snapshot, visible, replay)
  const shownExecutions = visibleExecutions(snapshot, visible, replay)
  const refreshProfiles = useCallback(async () => {
    const request = ++profileRequest.current
    setProfileRefreshing(true)
    setProfileError(null)
    try {
      const next = await api.runtimeProfiles()
      if (request === profileRequest.current) setProfiles(next)
    } catch (error: unknown) {
      if (request === profileRequest.current) setProfileError(error instanceof ApiError ? `${reasonLabel(error.reasonCode)}：${error.message}` : '模型配置读取失败')
    } finally { if (request === profileRequest.current) setProfileRefreshing(false) }
  }, [])
  const refreshCoauthorization = useCallback(async () => {
    const request = ++coauthorizationRequest.current
    setCoauthorizationRefreshing(true)
    setCoauthorization(null)
    setCoauthorizationError(null)
    try {
      const next = await api.coauthorizationStatus()
      if (next.schema_version !== '1.0' || typeof next.enabled !== 'boolean'
        || next.policy_source !== 'SERVER_REGISTERED_PUBLIC_KEYS' || next.signing !== 'EXTERNAL_APPROVERS_ONLY') {
        throw new Error('invalid approval configuration')
      }
      if (request === coauthorizationRequest.current) setCoauthorization(next)
    } catch (error: unknown) {
      if (request === coauthorizationRequest.current) {
        setCoauthorization(null)
        setCoauthorizationError(error instanceof ApiError ? `${reasonLabel(error.reasonCode)}：${error.message}` : '共同授权配置读取失败')
      }
    } finally { if (request === coauthorizationRequest.current) setCoauthorizationRefreshing(false) }
  }, [])
  useEffect(() => {
    mounted.current = true
    return () => { mounted.current = false }
  }, [])
  useEffect(() => {
    void refreshProfiles()
    return () => { profileRequest.current += 1 }
  }, [configurationRevision, refreshProfiles])
  useEffect(() => {
    void refreshCoauthorization()
    return () => { coauthorizationRequest.current += 1 }
  }, [refreshCoauthorization])
  useEffect(() => {
    const media = window.matchMedia('(max-width: 1000px)')
    const changed = () => setCompact(media.matches)
    media.addEventListener('change', changed)
    return () => media.removeEventListener('change', changed)
  }, [])
  useEffect(() => {
    setReplay(false); setCursor(0); setPlaying(false)
    if (runMode && runScenario && !cloudReviewRequest) { setMode(runMode === 'local' ? 'cloud' : runMode); setScenario(runScenario) }
  }, [cloudReviewRequest, runId, runMode, runScenario])
  useEffect(() => {
    if (!profiles || runMode || modeSelected.current || cloudReviewRequest) return
    // Unconfigured first launches select rules; cloud failures never switch mode.
    const cloudReady = profiles.items.some((item) => item.mode === 'cloud' && item.available)
    setMode(cloudReady ? 'cloud' : 'deterministic')
  }, [cloudReviewRequest, profiles, runMode])
  useEffect(() => {
    if (cloudReviewRequest) { setMode('cloud'); setScenario('policy_injection') }
  }, [cloudReviewRequest])
  useEffect(() => {
    if (cloudIntent && (cloudIntent.selectedTaskId !== (snapshot?.task.task_id ?? null)
      || cloudIntent.mode !== mode || cloudIntent.scenario !== scenario || cloudIntent.customInjectionText !== selectedInjectionText
      || !coauthorization || cloudIntent.coauthorizationRequired !== coauthorization.enabled)) {
      setCloudModal(false); setCloudIntent(null); setCloudConfirmed(false)
    }
  }, [cloudIntent, coauthorization, mode, scenario, selectedInjectionText, snapshot?.task.task_id])
  useEffect(() => {
    if (unconfirmedStart) { setCloudModal(false); setCloudIntent(null); setCloudConfirmed(false) }
  }, [unconfirmedStart])
  useEffect(() => {
    if (!replay || !playing || running || cursor >= events.length) return
    const timer = window.setTimeout(() => setCursor((value) => Math.min(events.length, value + 1)), 650 / speed)
    return () => window.clearTimeout(timer)
  }, [cursor, events.length, playing, replay, running, speed])

  const start = async (intent: WorkflowStartIntent, cloudAllowed = false) => {
    if (startInFlight.current || unconfirmedStart || invalidInjection) return
    if (taskReading || !coauthorizationReady || connectionError || intent.selectedTaskId !== (snapshot?.task.task_id ?? null)
      || intent.mode !== mode || intent.scenario !== scenario || intent.customInjectionText !== selectedInjectionText
      || intent.coauthorizationRequired !== coauthorizationRequired
      || (coauthorizationRequired && intent.taskId === null)
      || (intent.taskId !== null && (intent.taskId !== snapshot?.task.task_id || !canStartAuthorizedAt(Date.now() / 1000)))) {
      void messageApi.warning('任务或授权配置已变化，请刷新状态后重新确认')
      return
    }
    startInFlight.current = true
    const selectionAtStart = currentTaskId.current
    setStarting(true)
    let queued: WorkflowStarted | null = null
    try {
      const customArgs: [] | [string] = intent.customInjectionText === null ? [] : [intent.customInjectionText]
      const started = intent.taskId !== null
        ? await api.startAuthorizedWorkflow(intent.taskId, intent.mode, intent.scenario, cloudAllowed, ...customArgs)
        : await api.startWorkflow(intent.mode, intent.scenario, cloudAllowed, ...customArgs)
      if (started.state !== 'QUEUED' || started.runtime_mode !== intent.mode || !started.run_id || !started.task_id
        || (intent.taskId !== null && started.task_id !== intent.taskId)) {
        throw new Error('unconfirmed workflow response')
      }
      queued = started
      if (!mounted.current || currentTaskId.current !== selectionAtStart) {
        void messageApi.info(`任务 ${started.task_id} 已接收协作 ${started.run_id}；当前选择保持不变，可在运行档案查看`)
        return
      }
      setCloudModal(false); setCloudIntent(null); setCloudConfirmed(false)
      await onStarted(started)
      void messageApi.success('协作已进入队列，执行结果以保存的记录为准')
    } catch (error) {
      const definiteRejection = error instanceof ApiError && error.reasonCode !== 'WORKFLOW_RESULT_UNCONFIRMED'
        && (error.status < 500 || ['MODEL_MODE_UNAVAILABLE', 'UPSTREAM_UNAVAILABLE', 'CONTROLLED_RESULT_INVALID'].includes(error.reasonCode))
      const uncertain = queued !== null || !definiteRejection
      const message = queued ? `协作 ${queued.run_id} 已接收，但状态刷新失败；请查看运行档案，不要重复启动`
        : uncertain ? '启动结果未确认；请查看任务及运行档案，不要重复启动'
        : error instanceof ApiError ? `${reasonLabel(error.reasonCode)}：${error.message}` : '启动结果未确认'
      if (uncertain && mounted.current) {
        if (!onStartUnconfirmed) setLocalStartWarning(message)
        setCloudModal(false); setCloudIntent(null); setCloudConfirmed(false)
      }
      if (uncertain) onStartUnconfirmed?.(message, queued?.task_id ?? intent.taskId)
      void messageApi.error(message)
    } finally { startInFlight.current = false; if (mounted.current) setStarting(false) }
  }

  const beginStart = () => {
    if (currentTaskNeedsAuthorization) {
      if (!taskReading && !connectionError && !unconfirmedStart) onAuthorization?.()
      return
    }
    if (startInFlight.current || invalidInjection || taskReading || !coauthorizationReady || connectionError || unconfirmedStart) return
    if (coauthorizationRequired && !canStartAuthorized) { onAuthorization?.(); return }
    const intent: WorkflowStartIntent = {
      taskId: canStartAuthorized ? snapshot?.task.task_id ?? null : null,
      selectedTaskId: snapshot?.task.task_id ?? null, mode, scenario, coauthorizationRequired, customInjectionText: selectedInjectionText,
    }
    if (mode === 'cloud') { setCloudIntent(intent); setCloudConfirmed(false); setCloudModal(true) }
    else void start(intent)
  }

  const nodes = useMemo<BusinessNode[]>(() => {
    const make = (id: string, x: number, y: number, data: GraphData): BusinessNode => ({
      id, type: 'business', position: { x, y }, data,
      initialWidth: data.variant === 'tool' ? 240 : 224,
      initialHeight: data.variant === 'tool' ? 104 : 164,
    })
    const authorizationState = credentialNodeState(rootObservation.code)
    const values = [make('authorization', 0, 184, {
      label: '企业授权', subtitle: '工单、客户、预算与有效期', icon: LockKeyhole, state: authorizationState,
      stateLabel: rootObservation.label,
      caption: root ? '查看授权与预算' : '待签发根凭证', inspect: () => onInspect({ kind: 'stage', stage: 'authorization' }),
    })]
    const positions = [{ x: 260, y: 184 }, { x: 520, y: 52 }, { x: 520, y: 324 }, { x: 780, y: 324 }]
      AGENT_IDS.forEach((agentId, index) => {
      const evidence = [...visible].reverse().find((event) => event.agent_id === agentId && event.action === 'plan')
      values.push(make(agentId, positions[index].x, positions[index].y, {
        label: agentLabel(agentId), subtitle: AGENT_DUTIES[agentId], icon: AGENT_ICONS[agentId],
        state: agentNodeState(agentId, visible, snapshot, run?.state === 'INTERRUPTED' && !replay, replay),
        caption: typeof evidence?.details.model_returned === 'string' ? 'AI 规划 · 独立签名身份' : evidence?.details.planner === 'deterministic' ? '规则规划 · 独立签名身份' : '独立角色身份',
        inspect: () => onInspect({ kind: 'agent', agentId }),
      }))
    })
    values.push(make('gateway', 1040, 184, {
      label: '安全网关', subtitle: '验签、约束与原子准入', icon: ShieldCheck, variant: 'gateway',
      state: gatewayNodeState(visible, snapshot, replay), caption: '独立裁决，不信任模型',
      inspect: () => onInspect({ kind: 'stage', stage: 'gateway' }),
    }))
    TOOL_NAMES.forEach((tool, index) => values.push(make(tool, 1300, index * 132 + 16, {
      label: toolLabel(tool), subtitle: '受保护业务工具', icon: TOOL_ICONS[tool], variant: 'tool',
      state: toolNodeState(tool, visible, snapshot, replay), caption: '',
      inspect: () => {
        const execution = [...visibleExecutions(snapshot, visible, replay)].reverse().find((item) => item.tool_name === tool)
        onInspect(execution ? { kind: 'execution', execution } : { kind: 'pipeline', title: `${toolLabel(tool)} · 等待执行`, value: { tool, state: 'NOT_EXECUTED', expected_entry: 'secure-tool-gateway', execution: null } })
      },
    })))
    if (!replay && ['DENIED', 'FAILED', 'INTERRUPTED'].includes(run?.state ?? '')) {
      for (const node of values) {
        if (node.id !== 'authorization' && node.data.state === 'waiting') node.data.stateLabel = '未执行'
      }
    }
    return values
  }, [onInspect, replay, root, rootObservation.code, rootObservation.label, run?.state, snapshot, visible])

  const edges = useMemo<Edge[]>(() => {
    const edge = (source: string, target: string, state: NodeState): Edge => ({
      id: `${source}-${target}`, source, target, type: 'smoothstep',
      animated: state === 'active' && !connectionError, className: state === 'active' && !connectionError ? 'collab-edge-active' : '',
      markerEnd: { type: MarkerType.ArrowClosed, width: 13, height: 13, color: 'var(--muted)' },
      style: { stroke: state === 'active' ? 'var(--accent)' : state === 'completed' || state === 'authorized' ? 'var(--success)' : state === 'denied' ? 'var(--danger)' : 'var(--line)', strokeWidth: state === 'active' ? 2 : 1.3 },
    })
    const credentialFor = (agentId: string) => visibleCredentials(snapshot, visible, replay).find((item) => item.holder_agent_id === agentId)
    const rootState = credentialNodeState(rootObservation.code)
    const values = [edge('authorization', root?.holder_agent_id && AGENT_IDS.includes(root.holder_agent_id as typeof AGENT_IDS[number]) ? root.holder_agent_id : 'agent-coordinator', rootState)]
    for (const [parentId, childId] of [['agent-coordinator', 'agent-knowledge'], ['agent-coordinator', 'agent-case'], ['agent-case', 'agent-refund']]) {
      const credential = credentialFor(childId)
      const parent = credentialFor(parentId)
      const observation = observeCredential(credential, snapshot?.credentials ?? [], observedAt)
      const linked = credential && parent && credential.parent_credential_id === parent.credential_id
      values.push(edge(parentId, childId, linked ? credentialNodeState(observation.code) : 'waiting'))
    }
    for (const agentId of AGENT_IDS.slice(1)) {
      const calls = visible.filter((event) => event.agent_id === agentId && ['gateway_request', 'gateway_decision'].includes(event.action))
      const last = calls[calls.length - 1]
      const requestEdge = edge(agentId, 'gateway', last?.status === 'DENIED' ? 'denied' : last?.action === 'gateway_request' ? 'active' : calls.length ? 'completed' : 'waiting')
      const route = agentId.replace('agent-', '')
      values.push({ ...requestEdge, type: 'routed', sourceHandle: 'tool-request', targetHandle: `${route}-request`,
        data: { route }, style: { ...requestEdge.style, strokeDasharray: '5 5' } })
    }
    TOOL_NAMES.forEach((tool) => values.push({ ...edge('gateway', tool, toolNodeState(tool, visible, snapshot, replay)), type: 'routed', data: { route: 'dispatch' } }))
    return values
  }, [connectionError, observedAt, replay, root, rootObservation.code, snapshot, visible])

  const modeOptions = (['cloud', 'deterministic'] as RuntimeMode[]).map((value) => {
    const profile = profiles?.items.find((item) => item.mode === value)
    const Icon = value === 'cloud' ? Cloud : Layers3
    return { value, disabled: !profile?.available || starting || running || profileRefreshing,
      label: <Tooltip title={!profile ? '正在读取配置' : profile.available ? '运行配置已就绪' : '请检查智能体配置'}><span className="mode-option"><Icon size={15} />{MODE_LABELS[value]}</span></Tooltip> }
  })

  return <section className="business-workspace" data-testid="business-workspace">
    {presentation === 'full' ? <div className="business-context-band">
      <div className="business-subject"><span className="business-category"><FileText size={14} />售后业务 / 退款与通知</span>
        <h2>{ticket?.title ?? (snapshot ? `工单 ${snapshot.task.ticket_id}` : '售后退款任务')}</h2>
        <p>{ticket?.description ?? (snapshot ? '当前任务尚无匹配的工单业务摘要。' : '尚未选择业务任务，无授权或执行结果。')}</p>
        <div className="business-resource-links">
          <button type="button" disabled={!snapshot} onClick={() => onInspect({ kind: 'business', resource: 'ticket' })}><FileText size={14} />{snapshot?.task.ticket_id ?? '工单未选择'}<span>/</span>{snapshot ? <CustomerName id={snapshot.task.customer_id} /> : '客户未选择'}<ArrowUpRight size={12} /></button>
          <button type="button" disabled={!snapshot} onClick={() => onInspect({ kind: 'business', resource: 'knowledge' })}><BookOpen size={14} />{snapshot?.business_context?.documents[0]?.title ?? '关联知识'}<ArrowUpRight size={12} /></button>
        </div>
      </div>
      <button type="button" className="business-run-status" disabled={!snapshot}
        onClick={() => onInspect(run ? { kind: 'workflow', runId: run.run_id } : { kind: 'task' })}>
        <span>{run ? '本次协作运行' : '任务记录'}<ArrowUpRight size={13} /></span>
        {run ? <WorkflowStatusTag state={run.state} reasonCode={run.reason_code} /> : snapshot ? <StatusTag value={snapshot.task.status} label={taskAuthorizationLabel(snapshot.task.status)} /> : <span>未选择任务</span>}
        <small>{run ? `${run.events.length} 条已保存协作事件 · ${clock(run.updated_at_ms)} · ${outcomeEvidence.label}` : snapshot ? `${outcomeEvidence.label} · ${outcomeEvidence.detail}` : '尚无记录'}</small>
      </button>
    </div> : null}

    {snapshot && outcomeEvidence.status !== 'NOT_RUN' ? <Alert
      className="business-outcome-alert"
      type={outcomeAlertType}
      showIcon
      message={`退款业务结果：${outcomeEvidence.label}`}
      description={outcomeEvidence.detail}
      data-testid="business-workspace-outcome"
    /> : null}

    <div className="business-run-controls">
      <div className="model-control"><span className="control-caption">规划方式</span>
        <Segmented name="agent-runtime-mode" value={mode} options={modeOptions} onChange={(value) => { modeSelected.current = true; setMode(value as RuntimeMode) }} aria-label="智能体规划方式" />
        <div className="model-control-actions">
        <LiquidGlassButton icon={<Settings2 size={15} />} onClick={() => setModelSettingsOpen(true)} aria-label="查看模型配置">智能体配置</LiquidGlassButton>
        <Tooltip title="刷新运行与授权配置"><LiquidGlassButton icon={<RotateCcw size={15} />} aria-label="刷新运行与授权配置"
          loading={profileRefreshing || coauthorizationRefreshing} disabled={starting || running}
          onClick={() => { void refreshProfiles(); void refreshCoauthorization() }} /></Tooltip>
        </div>
      </div>
      <div className="scenario-control"><span className="control-caption">业务场景</span><Select value={scenario} onChange={setScenario} aria-label="选择业务场景" disabled={starting || running}
        options={[{ value: 'normal', label: '正常协作' }, { value: 'policy_injection', label: '关联文档指令注入' }]} /></div>
      <LiquidGlassButton className="start-workflow-button" type="primary" icon={running ? <LoaderCircle size={16} className="spin" /> : currentTaskNeedsAuthorization ? <ShieldCheck size={16} /> : <Play size={16} />}
        onClick={beginStart} loading={starting}
        disabled={taskReading || starting || running || !!connectionError || !!unconfirmedStart
          || (currentTaskNeedsAuthorization ? !onAuthorization : invalidInjection || profileRefreshing || !coauthorizationReady
            || (coauthorizationRequired && !canStartAuthorized)
            || !profiles?.workflow_enabled || !selectedProfile?.available)} data-testid="start-business-workflow">
        {taskReading ? '任务详情读取中' : run?.state === 'QUEUED' ? '协作等待运行' : running ? '协作执行中' : currentTaskNeedsAuthorization ? '打开当前任务授权'
          : !coauthorizationReady ? '授权配置未确认' : canStartAuthorized ? '运行当前任务' : coauthorizationRequired ? '当前任务暂不可运行' : '另建标准任务并运行'}
      </LiquidGlassButton>
    </div>
    {scenario === 'policy_injection' ? <div className="knowledge-injection-editor" data-testid="knowledge-injection-editor">
      <span className="control-caption">知识注入材料</span>
      <Select aria-label="注入材料来源" value={injectionSource} disabled={starting || running}
        onChange={setInjectionSource} options={[{ value: 'preset', label: '使用预设伪造复核意见' }, { value: 'custom', label: '编辑自定义不可信资料' }]} />
      {injectionSource === 'custom' ? <>
        <Input.TextArea aria-label="自定义知识注入文本" value={customInjectionText} disabled={starting || running}
          onChange={(event) => setCustomInjectionText(event.target.value)} rows={4} maxLength={4096} showCount />
        {invalidInjection ? <small role="alert">请输入非空材料，且不能包含 NUL 字符</small> : null}
        <small>最多 4096 字符。仅追加到本次知识返回副本；原文与摘要保存在运行记录中，云模式下将发送给模型。</small>
      </> : <small>预设材料会尝试替换客户、增加金额并跳过重新授权。</small>}
      {mode === 'deterministic' ? <small>规则模式可验证执行流程；模型对抗效果请切换智能体审查。</small> : null}
    </div> : null}
    {coauthorizationRequired ? <div className="coauth-workflow-notice" role="status">
      <UsersRound size={17} />
      <div><strong>共同授权已启用</strong><span>{canStartAuthorized
        ? '当前根授权已签发，启动仅使用本任务的原凭证与预算。'
        : run || snapshot?.executions.length ? '当前任务已有处理记录，请查看档案；不会重复启动原任务。'
        : root ? `当前根凭证：${rootObservation.label}。尚未满足当前任务启动条件。` : '当前任务尚无协调者根授权。'}</span></div>
      <LiquidGlassButton size="small" icon={<ArrowUpRight size={14} />} onClick={onAuthorization} disabled={!onAuthorization}>打开当前任务授权</LiquidGlassButton>
    </div> : null}
    {profileError || connectionError || coauthorizationError ? <Alert type="warning" showIcon message={connectionError ?? profileError ?? coauthorizationError} className="business-warning" /> : null}
    {unconfirmedStart ? <Alert type="warning" showIcon message={unconfirmedStart} className="business-warning"
      action={<LiquidGlassButton size="small" icon={<History size={14} />} onClick={onHistory}>查看运行档案</LiquidGlassButton>} /> : null}

    {presentation === 'full' ? <ExecutionEvidenceRail snapshot={snapshot} events={visible} credentials={shownCredentials} executions={shownExecutions} replay={replay} observedAt={observedAt} onInspect={onInspect} /> : null}

    {presentation !== 'controls' ? <>
    <div className="collaboration-heading"><div><GitBranch size={17} /><h3>角色协作和受控执行</h3>
      <span className={`live-indicator ${run?.state === 'RUNNING' && !connectionError ? 'live-active' : ''}`}><i />{connectionError ? '状态暂未刷新' : run?.state === 'QUEUED' ? '等待调度 · 已入队' : running ? '实时运行 · 轮询' : replay ? '历史逐步回放' : run ? '已保存运行记录' : snapshot ? '已有安全记录' : '等待任务'}</span></div>
      <LiquidGlassButton size="small" icon={<History size={14} />} onClick={onHistory}>运行档案</LiquidGlassButton>
    </div>
    <WorkflowBusinessOutcome snapshot={snapshot} events={visible} replay={replay} />
    <WorkflowExecutionOrder snapshot={snapshot} events={visible} replay={replay} onInspect={onInspect} />
    {presentation === 'layered' ? <div data-testid="business-graph"><LayeredCollaboration nodes={nodes} credentials={shownCredentials} onInspect={onInspect} observedAt={observedAt} activeRequest={activeRequest} /></div>
      : <div className={`collaboration-canvas${compact ? ' compact-canvas' : ''}`} data-testid="business-graph">
      {compact ? <div className="compact-collaboration">
        <div className="compact-node-row">{nodes.slice(0, 2).map((node) => <BusinessNodeCard key={node.id} data={node.data} />)}</div>
        <div className="compact-flow-arrow"><ArrowDown size={16} /><span>受约束委托</span></div>
        <div className="compact-node-row">{nodes.slice(2, 5).map((node) => <BusinessNodeCard key={node.id} data={node.data} />)}</div>
        <div className="compact-flow-arrow"><ArrowDown size={16} /><span>候选动作，不具有授权效力</span></div>
        <div className="compact-gateway">{nodes.slice(5, 6).map((node) => <BusinessNodeCard key={node.id} data={node.data} />)}</div>
        <div className="compact-flow-arrow"><ArrowDown size={16} /><span>网关签名封装，工具独立验签</span></div>
        <div className="compact-node-row compact-tool-row">{nodes.slice(6).map((node) => <BusinessNodeCard key={node.id} data={node.data} />)}</div>
      </div> : <div className="collaboration-desktop"><ReactFlow key={snapshot?.task.task_id ?? 'preview'} nodes={nodes} edges={edges} nodeTypes={NODE_TYPES} edgeTypes={EDGE_TYPES}
        minZoom={0.8} maxZoom={1.5} nodesDraggable={false} nodesConnectable={false} elementsSelectable={false} zoomOnScroll={false} preventScrolling={false}>
        <GraphAutoFit /><Background color="var(--line)" gap={22} size={0.7} /><Panel position="bottom-left"><GraphControls /></Panel>
        <Panel position="top-left" className="collab-domain-labels"><span>授权与协作域</span><span><ShieldCheck size={12} />网关裁决 / 工具验签</span></Panel>
      </ReactFlow></div>}
    </div>}

    <div className="collaboration-legend"><span><i className="legend-delegation" />授权与委托</span><span><i className="legend-proposal" />候选工具请求</span><span><ShieldCheck size={12} />网关签名信封 / 工具端验签</span>
      <button type="button" disabled={!snapshot} onClick={() => onInspect({ kind: 'stage', stage: 'agents' })}>{shownCredentials.filter((item) => item.parent_credential_id).length} 份子委托<ChevronRight size={12} /></button></div>

    {run ? <>
      <div className="workflow-playback-controls">
        <Segmented name="workflow-playback-mode" value={replay ? 'replay' : 'records'} options={[{ value: 'records', label: running ? '实时过程' : '完整记录' }, { value: 'replay', label: '逐步回放', disabled: running || !events.length }]}
          onChange={(value) => { setReplay(value === 'replay'); setCursor(0); setPlaying(value === 'replay') }} />
        {replay ? <>
          <Tooltip title={playing && cursor < events.length ? '暂停回放' : '继续回放'}><LiquidGlassButton size="small" icon={playing && cursor < events.length ? <Pause size={15} /> : <Play size={15} />} aria-label="播放或暂停过程回放"
            onClick={() => { if (cursor >= events.length) setCursor(0); setPlaying((value) => cursor >= events.length ? true : !value) }} /></Tooltip>
          <Tooltip title="从头回放"><LiquidGlassButton size="small" icon={<RotateCcw size={15} />} aria-label="重新回放协作过程" onClick={() => { setCursor(0); setPlaying(true) }} /></Tooltip>
          <Slider min={0} max={events.length} value={cursor} onChange={(value) => { setCursor(value); setPlaying(false) }} ariaLabelForHandle="协作过程回放进度" />
          <Select value={speed} onChange={setSpeed} aria-label="协作过程回放速度" options={[1, 2, 4].map((value) => ({ value, label: `${value}x` }))} />
        </> : <span className="workflow-provenance"><Bot size={15} />{MODE_LABELS[run.runtime_mode]}</span>}
        <span className="workflow-progress mono">{visible.length} / {events.length}</span>
        <WorkflowStatusTag state={run.state} reasonCode={run.reason_code} />
      </div>
      {presentation === 'full' ? <RequestEvidencePanel snapshot={snapshot} run={run} events={visible} replay={replay} onInspect={onInspect} /> : null}
      <Collapse ghost className="workflow-observation-collapse" items={[{ key: 'observations',
        label: <span className="workflow-observation-label"><Bot size={14} />角色规划与最近过程<span>{visible.length} 条观测</span></span>,
        children: <div className="workflow-bottom-layout">
        <section className="workflow-activity"><div className="band-heading"><h3>协作过程</h3>
          <LiquidGlassButton size="small" icon={<ArrowUpRight size={14} />} onClick={() => onInspect({ kind: 'workflow', runId: run.run_id })}>完整过程</LiquidGlassButton></div>
          <div className="workflow-event-list">{visible.slice(-6).map((event) => <button type="button" key={event.sequence} className={`workflow-event-row event-${event.status.toLowerCase()}`}
            onClick={() => onInspect({ kind: 'workflow', runId: run.run_id, sequence: event.sequence })}>
            <span className="event-sequence mono">{String(event.sequence).padStart(2, '0')}</span><div><strong>{eventTitle(event)}</strong><small>{eventSummary(event)}</small></div>
            <time>{clock(event.timestamp_ms)}</time><ArrowUpRight size={13} />
          </button>)}{!visible.length ? <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={replay ? '回放尚未开始' : '等待服务端过程事件'} /> : null}</div>
        </section>
        <section className="workflow-current"><div className="band-heading"><h3>最近规划记录</h3><Bot size={16} /></div>
          <span className="workflow-current-role">{currentPlan ? agentLabel(currentPlan.agent_id) : currentAgent ? agentLabel(currentAgent.agent_id) : '协调智能体'}</span>
          {currentPlan ? <><p>{PROPOSAL_STAGE_LABELS[String(currentPlan.details.stage)] ?? '角色规划'} · 第 {currentPlan.sequence} 条</p><PlanningQuote event={currentPlan} /></>
            : <p>{replay ? '当前回放位置尚无规划记录。' : running ? '等待角色规划。' : '本次运行未记录角色规划。'}</p>}
          {['DENIED', 'FAILED'].includes(run.state) && !replay ? <p>{reasonLabel(run.reason_code ?? '')}</p> : null}
          <button type="button" className="text-link" onClick={() => onInspect({ kind: 'agent', agentId: currentPlan?.agent_id ?? currentAgent?.agent_id ?? 'agent-coordinator' })}>查看输入与处理记录<ArrowRight size={13} /></button>
        </section>
      </div> }]} />
      <div className="workflow-source-note"><span><ShieldX size={13} />过程记录不替代签名回执与安全审计</span><span>最新过程 {clock(run.updated_at_ms)} <ShortHash value={run.run_id} size={6} /></span></div>
    </> : <>{presentation === 'full' ? <RequestEvidencePanel snapshot={snapshot} run={null} events={visible} replay={false} onInspect={onInspect} /> : null}
      <div className="workflow-legacy-note"><span>该任务没有新增协作过程记录，图中仅显示已有授权与执行状态。</span><button type="button" onClick={onHistory}>查看历史任务<ArrowUpRight size={13} /></button></div></>}
    </> : null}

    <ModelSettingsDialog open={modelSettingsOpen} initialMode={mode} profiles={profiles} error={profileError} refreshing={profileRefreshing} workInFlight={running || starting}
      onRefresh={() => { void refreshProfiles(); void refreshCoauthorization() }} onClose={() => setModelSettingsOpen(false)} />

    <Modal open={cloudModal} title="确认智能体审查" okText="确认并启动" cancelText="取消" confirmLoading={starting}
      okButtonProps={{ disabled: !cloudConfirmed || !cloudIntent || !coauthorizationReady || !!unconfirmedStart }}
      onOk={() => { if (cloudIntent) void start(cloudIntent, true) }} onCancel={() => { setCloudModal(false); setCloudIntent(null); setCloudConfirmed(false) }}>
      {cloudIntent?.taskId ? <p className="workflow-cloud-target">本次目标：已授权任务 <span className="mono">{cloudIntent.taskId}</span>。不创建新任务或再次签发根授权。</p> : null}
      {!cloudIntent?.taskId ? <p className="workflow-cloud-target">本次将新建任务。目标工单由服务端从符合办理条件的业务工单中选择；当前页面工单仅作上下文参考，实际目标将在运行档案中显示。</p> : null}
      <p>本次协调、知识、工单与退款角色将使用已配置的云端 AI 规划器，可能产生费用。发送范围为已选运行目标工单（新建任务以服务端实际选择为准）、关联知识及本次已返回的业务结果。</p>
      {cloudIntent?.customInjectionText ? <Alert type="warning" showIcon message="将发送自定义不可信知识资料" description={<pre style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', maxHeight: 180, overflow: 'auto' }}>{cloudIntent.customInjectionText}</pre>} /> : null}
      <Checkbox checked={cloudConfirmed} onChange={(event) => setCloudConfirmed(event.target.checked)}>允许本次云端调用，确认数据不含真实个人或企业信息</Checkbox>
    </Modal>
  </section>
}
