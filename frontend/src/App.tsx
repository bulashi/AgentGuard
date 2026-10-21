import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Alert, App as AntdApp, Layout, Result, Spin, Tabs, Tooltip, Typography } from 'antd'
import {
  Activity,
  ArrowLeft,
  BarChart3,
  FileCheck2,
  GitBranch,
  History,
  LockKeyhole,
  Menu,
  RefreshCw,
  ShieldCheck,
  Settings2,
  X,
} from 'lucide-react'
import { api, ApiError, isOperatorSessionError, OPERATOR_START_MESSAGE } from './api'
import { reasonLabel } from './labels'
import { LiquidGlassButton } from './components/LiquidGlassButton'
import { AuditEvidence } from './sections/AuditEvidence'
import { AuthorizationExplorer } from './sections/AuthorizationExplorer'
import { CredentialRevocationPanel } from './sections/CredentialRevocationPanel'
import { Benchmark } from './sections/Benchmark'
import { EvidenceDrawer } from './components/EvidenceDrawer'
import { ModelSettingsDialog } from './components/ModelSettingsDialog'
import { auditChainIsConsistent, taskAuditNeedsRefresh } from './executionModel'
import type { EvidenceSelection } from './executionModel'
import { resolveEvidenceSelection, scopeEvidenceSelection } from './evidenceSelection'
import { HistoryView } from './sections/HistoryView'
import { LiveExecution } from './sections/LiveExecution'
import { SecurityLab } from './sections/SecurityLab'
import { TaskCenter } from './sections/TaskCenter'
import { BusinessWorkspace } from './sections/BusinessWorkspace'
import { TaskOverview } from './sections/TaskOverview'
import { ExecutionRecords } from './sections/ExecutionRecords'
import { activeWorkflow, workflowIsRunning } from './workflowModel'
import { useAuditRefresh } from './useAuditRefresh'
import { useAuditPrefix } from './useAuditPrefix'
import type {
  BenchmarkSummary,
  DemoResult,
  Overview,
  SecurityMatrix,
  TaskSnapshot,
  TaskSummary,
  WorkflowStarted,
  RuntimeProfiles,
} from './types'

const { Header, Content } = Layout
const { Text } = Typography

type ViewKey = 'overview' | 'flow' | 'records' | 'evidence' | 'history' | 'security' | 'benchmark'

type AuxiliaryKey = 'overview' | 'matrix' | 'benchmark'
type AuxiliaryErrors = Partial<Record<AuxiliaryKey, string>>

const AUXILIARY_LABELS: Record<AuxiliaryKey, string> = {
  overview: '审计概览',
  matrix: '确定性安全场景矩阵',
  benchmark: '系统评测记录',
}

const EMPTY_AUXILIARY_LOADING: Record<AuxiliaryKey, boolean> = {
  overview: false, matrix: false, benchmark: false,
}

function formatAuxiliaryError(error: unknown, key: AuxiliaryKey) {
  const detail = error instanceof ApiError ? `${reasonLabel(error.reasonCode)}：${error.message}` : '接口没有返回可读错误'
  return `${AUXILIARY_LABELS[key]}读取失败（${detail}）。当前页面仍可使用已读取的任务与业务结果；点击“重试”获取最新只读数据。`
}

export type DemoRunState = {
  phase: 'idle' | 'requesting' | 'replaying'
  kind: string | null
  startedAt: number | null
}

const NAV_ITEMS: Array<{
  key: ViewKey
  label: string
  icon: typeof Activity
}> = [
  { key: 'overview', label: '任务工作台', icon: Activity },
  { key: 'flow', label: '协作流程', icon: GitBranch },
  { key: 'records', label: '执行记录', icon: FileCheck2 },
  { key: 'history', label: '历史记录', icon: History },
  { key: 'evidence', label: '证据中心', icon: LockKeyhole },
  { key: 'security', label: '安全测试', icon: ShieldCheck },
  { key: 'benchmark', label: '系统评测', icon: BarChart3 },
]

function App() {
  const { message: messageApi } = AntdApp.useApp()
  const [view, setView] = useState<ViewKey>(() => NAV_ITEMS.find((item) => `#${item.key}` === window.location.hash)?.key ?? 'overview')
  const [navCollapsed, setNavCollapsed] = useState(false)
  const [mobileNavOpen, setMobileNavOpen] = useState(false)
  const [compactNav, setCompactNav] = useState(() => window.matchMedia('(max-width: 1000px)').matches)
  const [controlsOpen, setControlsOpen] = useState(false)
  const [modelSettingsOpen, setModelSettingsOpen] = useState(() => new URLSearchParams(window.location.search).get('settings') === 'models')
  const [modelSettingsProfiles, setModelSettingsProfiles] = useState<RuntimeProfiles | null>(null)
  const [configurationRevision, setConfigurationRevision] = useState(0)
  const [operatorReady, setOperatorReady] = useState(false)
  const [operatorError, setOperatorError] = useState<string | null>(null)
  const [evidenceTab, setEvidenceTab] = useState('authorization')
  const [tasks, setTasks] = useState<TaskSummary[]>([])
  const [selectedTaskId, setSelectedTaskId] = useState<string | null>(() => new URLSearchParams(window.location.search).get('task'))
  const [snapshot, setSnapshot] = useState<TaskSnapshot | null>(null)
  const [snapshotObservedAt, setSnapshotObservedAt] = useState<number | undefined>(undefined)
  const [overview, setOverview] = useState<Overview | null>(null)
  const [matrix, setMatrix] = useState<SecurityMatrix | null>(null)
  const [benchmark, setBenchmark] = useState<BenchmarkSummary | null>(null)
  const [demo, setDemo] = useState<DemoResult | null>(null)
  const [demoRun, setDemoRun] = useState<DemoRunState>({ phase: 'idle', kind: null, startedAt: null })
  const selectedTaskRef = useRef<string | null>(selectedTaskId)
  const demosRef = useRef<Record<string, DemoResult>>({})
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [fatal, setFatal] = useState<string | null>(null)
  const [auxiliaryErrors, setAuxiliaryErrors] = useState<AuxiliaryErrors>({})
  const [auxiliaryLoading, setAuxiliaryLoading] = useState(EMPTY_AUXILIARY_LOADING)
  const [taskLoading, setTaskLoading] = useState(false)
  const [selection, setSelection] = useState<EvidenceSelection | null>(null)
  const [selectionStack, setSelectionStack] = useState<EvidenceSelection[]>([])
  const [workspaceTab, setWorkspaceTab] = useState('business')
  const [cloudReviewRequest, setCloudReviewRequest] = useState(0)
  const [taskReadError, setTaskReadError] = useState<string | null>(null)
  const [workflowStartWarning, setWorkflowStartWarning] = useState<{ message: string; taskId: string | null } | null>(null)
  const [authorizationReturnTaskId, setAuthorizationReturnTaskId] = useState<string | null>(null)
  const taskRequestRef = useRef(0)
  const taskListRequestRef = useRef(0)
  const taskSelectionRef = useRef(0)
  const refreshRequestRef = useRef(0)
  const auxiliaryRequestRef = useRef<Record<AuxiliaryKey, number>>({ overview: 0, matrix: 0, benchmark: 0 })
  const authorizationReturnRef = useRef<string | null>(null)
  const loadedTaskSnapshotRef = useRef<TaskSnapshot | null>(null)
  const mounted = useRef(false)

  useEffect(() => {
    let active = true
    void api.bootstrapOperatorSession().then(() => { if (active) setOperatorReady(true) })
      .catch(() => { if (active) { setOperatorError(OPERATOR_START_MESSAGE); setLoading(false) } })
    return () => { active = false }
  }, [])

  useEffect(() => {
    if (!operatorReady || operatorError || loading || fatal || !modelSettingsOpen) return undefined
    let active = true
    setModelSettingsProfiles(null)
    void api.runtimeProfiles().then((next) => { if (active) setModelSettingsProfiles(next) })
      .catch((error: unknown) => { if (active) { setModelSettingsProfiles(null); if (isOperatorSessionError(error)) setOperatorError(OPERATOR_START_MESSAGE) } })
    return () => { active = false }
  }, [configurationRevision, fatal, loading, modelSettingsOpen, operatorError, operatorReady])

  useEffect(() => {
    const media = window.matchMedia('(max-width: 1000px)')
    const resize = () => { setCompactNav(media.matches); setMobileNavOpen(false) }
    const navigate = () => {
      const next = NAV_ITEMS.find((item) => `#${item.key}` === window.location.hash)
      if (next) setView(next.key)
    }
    const escape = (event: KeyboardEvent) => { if (event.key === 'Escape') setMobileNavOpen(false) }
    media.addEventListener('change', resize)
    window.addEventListener('hashchange', navigate)
    window.addEventListener('keydown', escape)
    return () => {
      media.removeEventListener('change', resize)
      window.removeEventListener('hashchange', navigate)
      window.removeEventListener('keydown', escape)
    }
  }, [])
  useEffect(() => {
    if (!operatorReady) return
    setMobileNavOpen(false)
    const url = new URL(window.location.href)
    url.hash = view
    window.history.replaceState(null, '', url)
  }, [operatorReady, view])

  useEffect(() => {
    mounted.current = true
    const requests = auxiliaryRequestRef.current
    return () => {
      mounted.current = false
      taskRequestRef.current += 1
      taskListRequestRef.current += 1
      refreshRequestRef.current += 1
      for (const key of Object.keys(AUXILIARY_LABELS) as AuxiliaryKey[]) requests[key] += 1
    }
  }, [])
  const openEvidence = useCallback((next: EvidenceSelection) => {
    const scoped = scopeEvidenceSelection(next, selectedTaskId)
    setSelectionStack([])
    setSelection(scoped)
  }, [selectedTaskId])

  useEffect(() => {
    setSelection(null)
    setSelectionStack([])
    setDemo(selectedTaskId ? demosRef.current[selectedTaskId] ?? null : null)
    const url = new URL(window.location.href)
    if (selectedTaskId) url.searchParams.set('task', selectedTaskId)
    else url.searchParams.delete('task')
    window.history.replaceState(null, '', url)
  }, [selectedTaskId])

  const loadTask = useCallback(async (taskId: string | null) => {
    if (!mounted.current || selectedTaskRef.current !== taskId) return
    const requestId = ++taskRequestRef.current
    if (!taskId) {
      setSnapshot(null)
      setSnapshotObservedAt(undefined)
      setTaskReadError(null)
      setTaskLoading(false)
      loadedTaskSnapshotRef.current = null
      return
    }
    const current = () => mounted.current && requestId === taskRequestRef.current && selectedTaskRef.current === taskId
    setTaskLoading(true)
    try {
      const next = await api.task(taskId)
      if (next.task?.task_id !== taskId) throw new Error('task snapshot identity mismatch')
      if (current()) {
        setSnapshot(next); setSnapshotObservedAt(Date.now() / 1000); setTaskReadError(null)
        loadedTaskSnapshotRef.current = next
      }
    } catch (error) {
      if (!current()) return
      if (isOperatorSessionError(error)) setOperatorError(OPERATOR_START_MESSAGE)
      const detail = error instanceof ApiError ? `${reasonLabel(error.reasonCode)}：${error.message}` : '任务接口未返回匹配的可用快照'
      setTaskReadError(`任务详情暂不可用（${detail}）。尚未获得新的快照。`)
      throw error
    } finally {
      if (current()) setTaskLoading(false)
    }
  }, [])

  const readAuxiliary = useCallback(async <T,>(key: AuxiliaryKey, read: () => Promise<T>, apply: (next: T) => void): Promise<T> => {
    const requestId = ++auxiliaryRequestRef.current[key]
    const current = () => mounted.current && requestId === auxiliaryRequestRef.current[key]
    if (current()) setAuxiliaryLoading((previous) => ({ ...previous, [key]: true }))
    try {
      const next = await read()
      if (current()) {
        apply(next)
        setAuxiliaryErrors((previous) => {
          const errors = { ...previous }
          delete errors[key]
          return errors
        })
      }
      return next
    } catch (error) {
      if (current()) {
        if (isOperatorSessionError(error)) setOperatorError(OPERATOR_START_MESSAGE)
        setAuxiliaryErrors((previous) => ({ ...previous, [key]: formatAuxiliaryError(error, key) }))
      }
      throw error
    } finally {
      if (current()) setAuxiliaryLoading((previous) => ({ ...previous, [key]: false }))
    }
  }, [])

  const readOverview = useCallback(() => readAuxiliary('overview', api.overview, setOverview), [readAuxiliary])
  const loadAuxiliary = useCallback(() => {
    void readOverview().catch(() => undefined)
    void readAuxiliary('matrix', api.matrix, setMatrix).catch(() => undefined)
    void readAuxiliary('benchmark', api.benchmarks, setBenchmark).catch(() => undefined)
  }, [readAuxiliary, readOverview])

  const loadAll = useCallback(
    async (preferredTaskId?: string, requireTaskSnapshot = false) => {
      const requestId = ++taskListRequestRef.current
      const selectionAtStart = taskSelectionRef.current
      const taskResponse = await api.tasks()
      if (!mounted.current || requestId !== taskListRequestRef.current) return
      const nextTasks = taskResponse.items
      setTasks(nextTasks)
      const candidate =
        (selectionAtStart === taskSelectionRef.current ? preferredTaskId : undefined) ??
        selectedTaskRef.current ?? nextTasks[0]?.task_id ?? null
      if (candidate !== selectedTaskRef.current) {
        taskSelectionRef.current += 1
        taskRequestRef.current += 1
        setSnapshot(null); setSnapshotObservedAt(undefined); setTaskReadError(null)
        loadedTaskSnapshotRef.current = null
        if (authorizationReturnRef.current && authorizationReturnRef.current !== candidate) {
          authorizationReturnRef.current = null
          setAuthorizationReturnTaskId(null)
        }
      }
      selectedTaskRef.current = candidate
      setSelectedTaskId(candidate)
      setFatal(null)
      setLoading(false)
      try {
        await loadTask(candidate)
      } catch (error) {
        // Bootstrap stays usable; callers awaiting a mutation refresh still see its failure.
        if (requireTaskSnapshot || isOperatorSessionError(error)) throw error
      }
    },
    [loadTask],
  )

  useEffect(() => {
    if (!operatorReady || operatorError) return undefined
    let active = true
    setLoading(true)
    loadAll()
      .then(() => { if (active) loadAuxiliary() })
      .catch((error: unknown) => {
        if (!active) return
        if (isOperatorSessionError(error)) {
          setOperatorError(OPERATOR_START_MESSAGE)
          return
        }
        setFatal(
          error instanceof ApiError
            ? `${reasonLabel(error.reasonCode)}：${error.message}`
            : '控制台无法连接到 AgentGuard BFF',
        )
      })
      .finally(() => {
        if (active) setLoading(false)
      })
    return () => {
      active = false
    }
  }, [loadAll, loadAuxiliary, operatorError, operatorReady])

  const selectedWorkflowRunning = snapshot?.task.task_id === selectedTaskId && workflowIsRunning(activeWorkflow(snapshot))
  useEffect(() => {
    if (snapshot && workflowStartWarning?.taskId && workflowStartWarning.taskId === snapshot.task.task_id && snapshot.workflow_runs?.length) {
      setWorkflowStartWarning(null)
    }
  }, [snapshot, workflowStartWarning])
  useEffect(() => {
    if (!operatorReady || operatorError || loading || fatal || !selectedTaskId || taskLoading || (['history', 'benchmark'].includes(view) && !selectedWorkflowRunning && demoRun.phase === 'idle')) return
    let active = true
    let timer = 0
    const interval = selectedWorkflowRunning ? 850 : 2400
    const poll = async () => {
      await loadTask(selectedTaskId).catch(() => undefined)
      if (active) timer = window.setTimeout(() => void poll(), interval)
    }
    timer = window.setTimeout(() => void poll(), interval)
    return () => { active = false; window.clearTimeout(timer) }
  }, [demoRun.phase, fatal, loadTask, loading, operatorError, operatorReady, selectedTaskId, selectedWorkflowRunning, taskLoading, view])

  const auditRefreshRequired = operatorReady && !operatorError && taskAuditNeedsRefresh(snapshot?.task.task_id === selectedTaskId ? snapshot : null, overview)
  useAuditRefresh(auditRefreshRequired, readOverview)

  const refresh = useCallback(
    async (preferredTaskId?: string) => {
      const requestId = ++refreshRequestRef.current
      setRefreshing(true)
      loadAuxiliary()
      try {
        await loadAll(preferredTaskId, true)
      } finally {
        if (mounted.current && requestId === refreshRequestRef.current) setRefreshing(false)
      }
    },
    [loadAll, loadAuxiliary],
  )

  const openCurrentTaskAuthorization = useCallback(() => {
    const taskId = selectedTaskRef.current
    authorizationReturnRef.current = taskId
    setAuthorizationReturnTaskId(taskId)
    setView('evidence')
    setEvidenceTab('authorization')
  }, [])

  const returnToCurrentTask = useCallback(() => {
    authorizationReturnRef.current = null
    setAuthorizationReturnTaskId(null)
    setControlsOpen(true)
    setView('overview')
  }, [])

  const handleAuthorizationChanged = useCallback(async (taskId?: string) => {
    await refresh(taskId)
    if (!taskId || authorizationReturnRef.current !== taskId || selectedTaskRef.current !== taskId
      || view !== 'evidence' || evidenceTab !== 'authorization') return
    const refreshed = loadedTaskSnapshotRef.current
    if (refreshed?.task.task_id === taskId && refreshed.task.status === 'AUTHORIZED') returnToCurrentTask()
  }, [evidenceTab, refresh, returnToCurrentTask, view])

  const handleDemo = useCallback(
    async (result: DemoResult) => {
      setCloudReviewRequest(0)
      taskRequestRef.current += 1
      taskSelectionRef.current += 1
      selectedTaskRef.current = result.task_id
      setSnapshot(null)
      setSnapshotObservedAt(undefined); setTaskReadError(null)
      demosRef.current[result.task_id] = result
      setDemo(result)
      setWorkspaceTab('execution')
      if (result.demo_kind !== 'LIVE_LLM_INJECTION') setView('flow')
      setDemoRun({ phase: 'replaying', kind: result.demo_kind, startedAt: Date.now() })
      setSelectedTaskId(result.task_id)
      await refresh(result.task_id)
    },
    [refresh],
  )

  const startDemo = useCallback((kind: string) => {
    setDemo(null)
    setDemoRun({ phase: 'requesting', kind, startedAt: Date.now() })
    setView(kind === 'LIVE_LLM_INJECTION' ? 'security' : 'flow')
    setWorkspaceTab('execution')
  }, [])

  const cancelDemo = useCallback(() => {
    setDemoRun({ phase: 'idle', kind: null, startedAt: null })
  }, [])

  const handleWorkflowStarted = useCallback(async (started: WorkflowStarted) => {
    setCloudReviewRequest(0)
    taskRequestRef.current += 1
    taskSelectionRef.current += 1
    selectedTaskRef.current = started.task_id
    setSelectedTaskId(started.task_id); setSnapshot(null); setDemo(null); setSelection(null); setSelectionStack([])
    setSnapshotObservedAt(undefined); setTaskReadError(null)
    setDemoRun({ phase: 'idle', kind: null, startedAt: null }); setWorkspaceTab('business'); setView('flow')
    await refresh(started.task_id)
  }, [refresh])

  const availableTasks = useMemo(() => {
    if (!snapshot || snapshot.task.task_id !== selectedTaskId) return tasks
    const current = { ...snapshot.task, credential_count: snapshot.credentials.length, execution_count: snapshot.executions.length }
    return tasks.some((item) => item.task_id === selectedTaskId)
      ? tasks.map((item) => item.task_id === selectedTaskId ? current : item)
      : [current, ...tasks]
  }, [snapshot, selectedTaskId, tasks])
  const currentSnapshot = operatorReady && !operatorError && snapshot?.task.task_id === selectedTaskId ? snapshot : null
  const currentSelection = resolveEvidenceSelection(selection, currentSnapshot)
  const auditPrefix = useAuditPrefix(currentSnapshot, currentSelection?.kind === 'audit' ? currentSelection.event : null)
  const auxiliaryErrorDetails = Object.values(auxiliaryErrors).filter(Boolean).join('；')
  const auxiliaryRefreshing = Object.values(auxiliaryLoading).some(Boolean)
  const auditOverviewFresh = !auxiliaryErrors.overview
  const currentOverview = auditOverviewFresh && !auxiliaryLoading.overview ? overview : null
  const taskDetailsAvailable = currentSnapshot !== null && !taskReadError

  const selectTask = useCallback((taskId: string) => {
    setCloudReviewRequest(0)
    taskRequestRef.current += 1
    taskSelectionRef.current += 1
    selectedTaskRef.current = taskId
    loadedTaskSnapshotRef.current = null
    authorizationReturnRef.current = null
    setAuthorizationReturnTaskId(null)
    setSelectedTaskId(taskId); setSnapshot(null); setSelection(null); setSelectionStack([])
    setSnapshotObservedAt(undefined); setTaskReadError(null)
    setDemoRun({ phase: 'idle', kind: null, startedAt: null })
    setWorkspaceTab('business'); setView('overview'); setControlsOpen(false)
    void loadTask(taskId).catch((error: unknown) => {
      void messageApi.error(error instanceof ApiError ? `${reasonLabel(error.reasonCode)}：${error.message}` : '任务记录读取失败')
    })
  }, [loadTask, messageApi])

  const retryTask = () => {
    if (selectedTaskId) void loadTask(selectedTaskId).catch(() => undefined)
  }

  const closeModelSettings = () => {
    setModelSettingsOpen(false)
    const url = new URL(window.location.href)
    url.searchParams.delete('settings')
    window.history.replaceState(null, '', `${url.pathname}${url.search}${url.hash}`)
  }
  const modelsSettings = <ModelSettingsDialog open={operatorReady && !operatorError && !loading && !fatal && modelSettingsOpen} initialMode="cloud" profiles={modelSettingsProfiles}
    error={null} refreshing={false} workInFlight={workflowIsRunning(activeWorkflow(currentSnapshot)) || demoRun.phase === 'requesting'}
    onRefresh={() => setConfigurationRevision((value) => value + 1)} onClose={closeModelSettings} />

  if (operatorError) {
    return <>{modelsSettings}<Result status="403" title="需要本机启动授权" subTitle={operatorError}
      extra={<LiquidGlassButton icon={<RefreshCw size={16} />} onClick={() => window.location.reload()}>重新连接</LiquidGlassButton>} /></>
  }

  if (!operatorReady || loading) {
    return (
      <>{modelsSettings}<div className="boot-screen">
        <Spin size="large" />
        <Text>{operatorReady ? '正在读取运行证据' : '正在建立本机操作者会话'}</Text>
      </div></>
    )
  }

  if (fatal) {
    return (
        <>{modelsSettings}<Result
          status="error"
          title="AgentGuard 控制台不可用"
        subTitle={fatal}
        extra={
          <LiquidGlassButton type="primary" icon={<RefreshCw size={16} />} onClick={() => window.location.reload()}>
            重新连接
          </LiquidGlassButton>
        }
      /></>
    )
  }

  const businessWorkspace = <BusinessWorkspace snapshot={currentSnapshot} onInspect={openEvidence} presentation={view === 'overview' ? 'controls' : 'layered'}
    onStarted={handleWorkflowStarted} onHistory={() => setView('history')} onAuthorization={openCurrentTaskAuthorization} connectionError={taskReadError}
    taskReading={taskLoading && !currentSnapshot} cloudReviewRequest={cloudReviewRequest} configurationRevision={configurationRevision} observedAt={snapshotObservedAt}
    startWarning={workflowStartWarning?.message}
    onStartUnconfirmed={(message, taskId) => setWorkflowStartWarning({ message, taskId })} />

  return (
    <>{modelsSettings}<Layout className={`app-shell layered-console studio-console${navCollapsed && !compactNav ? ' nav-collapsed' : ''}${mobileNavOpen ? ' mobile-nav-open' : ''}`}>
      {mobileNavOpen ? <button type="button" className="nav-backdrop" aria-label="关闭导航" onClick={() => setMobileNavOpen(false)} /> : null}
      <aside className="app-sider" aria-label="工作区导航" inert={compactNav && !mobileNavOpen}>
        <div className="brand-block">
          <div className="brand-mark"><ShieldCheck size={22} /></div>
          <div className="brand-copy">
            <strong>AgentGuard</strong>
          </div>
        </div>
        <nav className="side-nav" aria-label="AgentGuard 功能区">
          <span className="nav-group-label">工作空间</span>
          {NAV_ITEMS.map((item, index) => {
            const Icon = item.icon
            return (
              <div key={item.key}>{index === 4 ? <span className="nav-group-label">验证与评测</span> : null}<Tooltip title={navCollapsed && !compactNav ? item.label : undefined} placement="right">
                <button
                  type="button"
                  className={view === item.key ? 'nav-button active' : 'nav-button'}
                  onClick={() => { setView(item.key); setMobileNavOpen(false) }}
                  aria-current={view === item.key ? 'page' : undefined}
                  data-testid={`nav-${item.key}`}
                  aria-label={item.label}
                >
                  <Icon size={18} />
                  <span>{item.label}</span>
                </button>
              </Tooltip>{item.key === 'evidence' && view === 'evidence' && (!navCollapsed || compactNav) ? <nav className="evidence-subnav" aria-label="证据分类">
                {[['authorization', '授权凭证'], ['revocation', '撤销控制'], ['receipts', '执行回执'], ['audit', '审计记录']].map(([key, label]) => <button type="button" key={key} aria-current={evidenceTab === key ? 'page' : undefined} onClick={() => { setEvidenceTab(key); setMobileNavOpen(false) }}>{label}</button>)}
              </nav> : null}</div>
            )
          })}
        </nav>
      </aside>

      <Layout>
        <Header className="app-header">
          <div className="header-context">
            <Tooltip title={compactNav ? '打开导航' : navCollapsed ? '展开导航' : '收起导航'}><button className="nav-toggle" type="button" aria-label={compactNav ? mobileNavOpen ? '关闭导航' : '打开导航' : navCollapsed ? '展开导航' : '收起导航'} aria-expanded={compactNav ? mobileNavOpen : !navCollapsed} onClick={() => compactNav ? setMobileNavOpen((value) => !value) : setNavCollapsed((value) => !value)}>{mobileNavOpen ? <X size={20} /> : <Menu size={20} />}</button></Tooltip>
            <span className="header-label">企业任务</span><span className="breadcrumb-divider">/</span><strong>{NAV_ITEMS.find((item) => item.key === view)?.label}</strong>
          </div>
          <div className="header-actions">
            <Tooltip title="配置模型服务"><LiquidGlassButton icon={<Settings2 size={17} />} aria-label="配置模型服务" onClick={() => setModelSettingsOpen(true)} /></Tooltip>
            <Tooltip title={auxiliaryErrors.overview ?? (auxiliaryLoading.overview ? '正在读取审计概览，已有报告不代表本次读取结果' : overview?.audit.verification ? `独立审计报告核对至 #${overview.audit.verification.latest_event_sequence}${auditRefreshRequired ? '；当前任务有新事件待核验' : ''}` : '独立审计结果尚未返回')}>
            <button type="button" className="audit-health" onClick={() => { setView('evidence'); setEvidenceTab('audit') }} aria-label="查看独立审计核验">
              <span className={auditOverviewFresh && !auxiliaryLoading.overview && auditChainIsConsistent(overview) && !auditRefreshRequired ? 'health-dot healthy' : 'health-dot'} />
                <span>审计链 {auxiliaryLoading.overview ? '读取中' : auxiliaryErrors.overview ? '最新读取失败' : auditRefreshRequired ? '新事件待核验' : overview?.audit.verification ? auditChainIsConsistent(overview) ? '报告自洽' : '无效或不完整' : '待核验'}</span>
            </button>
            </Tooltip>
            <Tooltip title="刷新运行状态">
              <LiquidGlassButton
                className="header-refresh"
                icon={<RefreshCw size={17} className={refreshing ? 'spin' : ''} />}
                onClick={() => void refresh().catch(() => messageApi.error('刷新失败，当前显示上次读取的记录'))}
                loading={refreshing || auxiliaryRefreshing}
                aria-label="刷新运行状态"
              />
            </Tooltip>
          </div>
        </Header>

        <Content className="app-content">
          <div className="content-inner">
            {auxiliaryErrorDetails ? <Alert
              className="business-warning"
              type="warning"
              showIcon
              message="主工作台可继续使用，部分只读数据暂不可用"
              description={auxiliaryErrorDetails}
              action={<LiquidGlassButton
                size="small"
                icon={<RefreshCw size={14} />}
                loading={refreshing || auxiliaryRefreshing}
                onClick={loadAuxiliary}
              >重试</LiquidGlassButton>}
            /> : null}
            {['overview', 'flow', 'records', 'evidence'].includes(view) ? <>
              <TaskCenter tasks={availableTasks} selectedTaskId={selectedTaskId} onSelect={selectTask} compact={view === 'overview' && currentSnapshot !== null}
                onChanged={refresh} onDemo={handleDemo} onDemoStart={startDemo} onDemoError={cancelDemo} onInspect={openEvidence}
                onAuthorization={openCurrentTaskAuthorization}
                pageTitle={NAV_ITEMS.find((item) => item.key === view)?.label}
                businessMode={view !== 'evidence'} currentTaskReady={taskDetailsAvailable}
                requesting={demoRun.phase === 'requesting' || workflowIsRunning(activeWorkflow(currentSnapshot))} />
              {taskReadError ? <Alert className="business-warning" type="warning" showIcon message={taskReadError}
                description={currentSnapshot ? '以下保留上次成功读取的任务快照，尚未确认最新状态。' : '尚无当前任务详情，可以重试读取或切换其他任务。'}
                action={<LiquidGlassButton size="small" icon={<RefreshCw size={14} />} loading={taskLoading} onClick={retryTask}>重试读取</LiquidGlassButton>} /> : taskLoading && !currentSnapshot ? <div className="business-warning" role="status"><Spin size="small" /> <Text type="secondary">正在读取当前任务详情</Text></div> : null}
            </> : null}
            {view === 'overview' ? <TaskOverview snapshot={currentSnapshot} observedAt={snapshotObservedAt ?? Date.now() / 1000} onInspect={openEvidence}
              onFlow={() => { setView('flow'); setWorkspaceTab('business') }} onRecords={() => setView('records')}
              onAuthorization={openCurrentTaskAuthorization} onConfigure={() => setControlsOpen((value) => !value)} controlsOpen={controlsOpen} controls={businessWorkspace} /> : null}
            {view === 'flow' ? <Tabs className="flow-page-tabs" activeKey={workspaceTab} onChange={setWorkspaceTab} items={[
              { key: 'business', label: <span className="workspace-tab-label"><GitBranch size={15} />请求流程</span> },
              { key: 'execution', label: <span className="workspace-tab-label"><Activity size={15} />控制链路回放</span> },
            ]} /> : null}
            {view === 'flow' ? <div hidden={workspaceTab !== 'business'}>{businessWorkspace}</div> : null}
            {view === 'flow' && workspaceTab === 'execution' ? <LiveExecution key={`${currentSnapshot?.task.task_id ?? 'empty'}-${demo?.task_id === currentSnapshot?.task.task_id ? 'trace' : 'saved'}-${demoRun.phase === 'requesting' ? 'requesting' : 'ready'}`}
              snapshot={demoRun.phase === 'requesting' ? null : currentSnapshot} demo={demo} runState={demoRun} overview={currentOverview} auditPrefix={auditPrefix.report} observedAt={snapshotObservedAt} onInspect={openEvidence} onHistory={() => setView('history')} /> : null}
            {view === 'records' ? <ExecutionRecords key={selectedTaskId} snapshot={currentSnapshot} onInspect={openEvidence} /> : null}
            {view === 'evidence' ? <>
              {authorizationReturnTaskId && authorizationReturnTaskId === selectedTaskId && evidenceTab === 'authorization' ? <Alert
                className="business-warning"
                type="info"
                showIcon
                message={`当前授权任务：工单 ${currentSnapshot?.task.ticket_id ?? '读取中'}`}
                description="这里处理的是当前工单的任务授权，不会执行退款。授权确认并刷新成功后，将返回同一工单。"
                action={<LiquidGlassButton size="small" icon={<ArrowLeft size={14} />} onClick={returnToCurrentTask}>返回当前工单</LiquidGlassButton>}
              /> : null}
              <Tabs className="evidence-page-tabs" activeKey={evidenceTab} onChange={setEvidenceTab} items={[
                { key: 'authorization', label: '授权凭证' }, { key: 'revocation', label: '撤销控制' }, { key: 'receipts', label: '执行回执' }, { key: 'audit', label: '审计记录' },
              ]} />
              {evidenceTab === 'authorization' ? <AuthorizationExplorer snapshot={currentSnapshot} observedAt={snapshotObservedAt} onInspect={openEvidence} onChanged={handleAuthorizationChanged} />
                : evidenceTab === 'revocation' ? <CredentialRevocationPanel snapshot={currentSnapshot} onRevoke={api.revokeCredential} onVerify={api.verifyRevokedCredential} onChanged={refresh} onInspect={openEvidence} />
                : <AuditEvidence section={evidenceTab === 'receipts' ? 'receipts' : 'audit'} overview={overview} snapshot={currentSnapshot} auditPrefix={auditPrefix.report} prefixError={auditPrefix.error} prefixObservedAt={auditPrefix.observedAt} overviewFresh={auditOverviewFresh} overviewLoading={auxiliaryLoading.overview} onInspect={openEvidence} />}
            </> : null}
            {view === 'history' ? (
              <HistoryView
                tasks={availableTasks}
                selectedTaskId={selectedTaskId}
                onSelect={selectTask}
              />
            ) : null}
            {view === 'security' ? (
              <SecurityLab
                matrix={matrix}
                matrixLoading={auxiliaryLoading.matrix}
                matrixError={auxiliaryErrors.matrix}
                snapshot={currentSnapshot}
                demo={demo}
                runState={demoRun}
                onDemo={handleDemo}
                onDemoStart={startDemo}
                onDemoError={cancelDemo}
                onInspect={openEvidence}
                onOpenRun={() => { setView('flow'); setWorkspaceTab('execution') }}
                onCloudReview={() => { setCloudReviewRequest((value) => value + 1); setView('flow'); setWorkspaceTab('business') }}
                onProofReady={async (taskId) => { await refresh(taskId) }}
              />
            ) : null}
            {view === 'benchmark' ? (
              <Benchmark benchmark={benchmark} matrix={matrix} overview={currentOverview}
                recordLoading={auxiliaryLoading.benchmark} recordError={auxiliaryErrors.benchmark} />
            ) : null}
          </div>
        </Content>
      </Layout>
      <EvidenceDrawer selection={selection} snapshot={currentSnapshot} overview={currentOverview} auditPrefix={auditPrefix.report} prefixError={auditPrefix.error} observedAt={snapshotObservedAt}
        onSelect={(next) => {
          if (selection) setSelectionStack((items) => [...items, selection])
          setSelection(scopeEvidenceSelection(next, selection?.taskId ?? selectedTaskId))
        }}
        onBack={selectionStack.length ? () => { setSelection(selectionStack[selectionStack.length - 1]); setSelectionStack((items) => items.slice(0, -1)) } : undefined}
        onClose={() => { setSelection(null); setSelectionStack([]) }} />
    </Layout></>
  )
}

export default App
