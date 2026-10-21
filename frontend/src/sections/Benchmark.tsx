import { fenToYuan } from '../money'
import { useEffect, useState } from 'react'
import { Alert, Descriptions, Empty, Table, Tag, Tooltip, Typography } from 'antd'
import { BarChart3, CircleHelp, Database, FlaskConical, Gauge, ShieldCheck } from 'lucide-react'
import { StatusTag } from '../components/Evidence'
import { MetricStrip } from '../components/MetricStrip'
import { SectionHeader } from '../components/SectionHeader'
import { aecLabel } from '../labels'
import { api } from '../api'
import type {
  BenchmarkAblation,
  BenchmarkLatencyStats,
  BenchmarkSummary,
  BenchmarkSystemMeasurement,
  Overview,
  SecurityMatrix,
  RuntimeProfiles,
} from '../types'

const { Text } = Typography

interface ComparisonRow {
  key: string
  system: string
  acceptanceRate: number
  completionRate: number
  unauthorizedSideEffects: number
  latency: BenchmarkLatencyStats
  throughput: number
  revocationMs: number
  budgetSafe: boolean
  allowed: number
  denied: number
}

interface CostRow {
  key: string
  profile: string
  credentialBytes: number | null
  storageBytes: number | null
}

interface ComponentRow {
  key: string
  component: string
  meanMs: number | null
  p95Ms: number | null
}

const systemLabels: Record<string, string> = {
  agentguard: 'AgentGuard',
  conventional_rbac: '常规智能体 RBAC',
  shared_static_credential: '共享静态凭据',
}

const ablationLabels: Record<string, { mechanism: string; result: string }> = {
  paired_multilevel_budget_reservation: {
    mechanism: '多层共享预算配对验证',
    result: '原子准入与先读后写的并发结果',
  },
  non_atomic_budget_admission: {
    mechanism: '非原子预算更新反例',
    result: '并发预算超额提交',
  },
  no_business_idempotency: {
    mechanism: '缺少业务幂等的反例',
    result: '同一逻辑操作产生重复副作用',
  },
  no_holder_proof: {
    mechanism: '共享凭据基线与错误持有者对照',
    result: '被窃凭据可由错误持有者使用',
  },
  no_signed_receipt_and_audit_evidence: {
    mechanism: '回执与审计记录的基线对照',
    result: '执行结果失去可交叉验证证据',
  },
}

function boolLabel(value: unknown) {
  return value === true ? '是' : value === false ? '否' : '未提供'
}

function formatPercent(value?: number) {
  return typeof value === 'number' ? `${(value * 100).toFixed(1)}%` : '—'
}

function formatMs(value?: number | null) {
  return typeof value === 'number' ? `${value.toFixed(2)} ms` : '—'
}

function formatRps(value?: number | null) {
  return typeof value === 'number' ? `${value.toFixed(2)} req/s` : '—'
}

function formatBytes(value?: number | null) {
  if (typeof value !== 'number') return '—'
  if (value < 1024) return `${value} B`
  return `${(value / 1024).toFixed(2)} KiB`
}

function formatDate(value?: string) {
  if (!value) return '—'
  return new Date(value).toLocaleString('zh-CN', { hour12: false })
}

function comparisonRow(measurement: BenchmarkSystemMeasurement): ComparisonRow {
  return {
    key: measurement.name,
    system: systemLabels[measurement.name] ?? measurement.name,
    acceptanceRate: measurement.legitimate_request_acceptance_rate,
    completionRate: measurement.normal_task_completion_rate,
    unauthorizedSideEffects: measurement.attack_outcome.unauthorized_side_effects,
    latency: measurement.latency_ms,
    throughput: measurement.throughput_rps,
    revocationMs: measurement.revocation.latency_ms,
    budgetSafe: measurement.concurrent_consistency.budget_safe,
    allowed: measurement.concurrent_consistency.allowed,
    denied: measurement.concurrent_consistency.denied,
  }
}

function ablationObservation(ablation: BenchmarkAblation) {
  switch (ablation.name) {
    case 'paired_multilevel_budget_reservation': {
      const atomic = ablation.atomic && typeof ablation.atomic === 'object' ? ablation.atomic as Record<string, unknown> : {}
      const race = ablation.read_check_write && typeof ablation.read_check_write === 'object' ? ablation.read_check_write as Record<string, unknown> : {}
      const count = (value: unknown) => typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 ? String(value) : '未提供'
      return `配对 ${count(ablation.trial_count)} 组；原子组预算违规 ${count(atomic.invariant_violation_trials)} 组；先读后写超额 ${count(race.overcommitted_trials)} 组`
    }
    case 'non_atomic_budget_admission':
      return `${String(ablation.decisions_allowed)} 次允许；提交 ${fenToYuan(Number(ablation.committed_fen))} / 上限 ${fenToYuan(Number(ablation.limit_fen))} 元`
    case 'no_business_idempotency':
      return `${String(ablation.committed_effects)} 个已提交副作用；重复副作用=${boolLabel(ablation.duplicate_effect_observed)}`
    case 'no_holder_proof':
      return `基线接受窃取凭据=${boolLabel(ablation.baseline_stolen_credential_accepted)}；AgentGuard 错误密钥拒绝=${boolLabel(ablation.agentguard_wrong_key_denied)}`
    case 'no_signed_receipt_and_audit_evidence':
      return `基线无强制回执执行 ${String(ablation.baseline_executions_without_required_receipt)} 次；AgentGuard 签名回执执行 ${String(ablation.agentguard_executions_with_signed_receipt)} 次`
    default:
      return ablationLabels[ablation.name]?.result ?? '已记录隔离实验结果'
  }
}

function latencyComponent(
  components: Record<string, unknown> | undefined,
  key: string,
): { mean: number | null; p95: number | null } {
  const value = components?.[key]
  if (!value || typeof value !== 'object') return { mean: null, p95: null }
  const record = value as Record<string, unknown>
  return {
    mean: typeof record.mean_ms === 'number' ? record.mean_ms : null,
    p95: typeof record.p95_ms === 'number' ? record.p95_ms : null,
  }
}

export function Benchmark({
  benchmark,
  matrix,
  recordLoading = false,
  recordError,
}: {
  benchmark: BenchmarkSummary | null
  matrix: SecurityMatrix | null
  overview: Overview | null
  recordLoading?: boolean
  recordError?: string | null
}) {
  const [profiles, setProfiles] = useState<RuntimeProfiles | null>(null)
  const [profileError, setProfileError] = useState(false)
  useEffect(() => {
    let current = true
    void api.runtimeProfiles().then((value) => { if (current) setProfiles(value) })
      .catch(() => { if (current) setProfileError(true) })
    return () => { current = false }
  }, [])
  const verified = benchmark?.status === 'VERIFIED' && benchmark.acceptance?.passed === true
  const provenance = benchmark?.source_provenance
  const sourceStatus = provenance?.status ?? 'UNVERIFIED'
  const recordLabel = sourceStatus === 'MATCH'
    ? null
    : sourceStatus === 'SOURCE_CHANGED' ? '历史评测记录' : '来源未核验'
  const metrics = verified ? benchmark.metrics : undefined
  const systems = verified
    ? [benchmark.agentguard, ...(benchmark.baselines ?? [])].filter(
        (item): item is BenchmarkSystemMeasurement => Boolean(item),
      )
    : []
  const comparisonRows = systems.map(comparisonRow)
  const credentialSizes = metrics?.credential_size_bytes
  const storage = metrics?.state_storage_bytes
  const chainSizes = credentialSizes?.agentguard_by_chain_length ?? {}
  const costRows: CostRow[] = verified
    ? [
        ...Object.entries(chainSizes).map(([depth, value]) => ({
          key: `agentguard-${depth}`,
          profile: `AgentGuard 链长 ${depth}`,
          credentialBytes: value.chain_bytes,
          storageBytes: depth === '3' ? storage?.agentguard?.logical_bytes ?? null : null,
        })),
        {
          key: 'conventional_rbac',
          profile: '常规智能体 RBAC',
          credentialBytes: credentialSizes?.conventional_rbac ?? null,
          storageBytes: storage?.conventional_rbac?.logical_bytes ?? null,
        },
        {
          key: 'shared_static_credential',
          profile: '共享静态凭据',
          credentialBytes: credentialSizes?.shared_static_credential ?? null,
          storageBytes: storage?.shared_static_credential?.logical_bytes ?? null,
        },
      ]
    : []
  const components = metrics?.component_latency_ms
  const crypto = latencyComponent(components, 'crypto_sign_and_verify_ms')
  const network = latencyComponent(components, 'network_gateway_health_ms')
  const persistence = latencyComponent(components, 'persistence_insert_delete_ms')
  const modelValue = components?.model_inference
  const model = modelValue && typeof modelValue === 'object'
    ? modelValue as Record<string, unknown>
    : undefined
  const modelStats = model?.latency_ms && typeof model.latency_ms === 'object'
    ? model.latency_ms as Record<string, unknown>
    : undefined
  const modelMean = [modelStats?.mean_ms, model?.mean_ms, model?.wall_ms].find(
    (value): value is number => typeof value === 'number' && Number.isFinite(value),
  )
  const modelP95 = [modelStats?.p95_ms, model?.p95_ms].find(
    (value): value is number => typeof value === 'number' && Number.isFinite(value),
  )
  const componentRows: ComponentRow[] = verified
    ? [
        { key: 'crypto', component: 'SM2 签名 + 验签', meanMs: crypto.mean, p95Ms: crypto.p95 },
        { key: 'network', component: '本机健康请求往返', meanMs: network.mean, p95Ms: network.p95 },
        { key: 'persistence', component: 'PG 连接与插入 / 删除事务', meanMs: persistence.mean, p95Ms: persistence.p95 },
        {
          key: 'model',
          component: '云端规划 HTTP 往返',
          meanMs: modelMean ?? null,
          p95Ms: modelP95 ?? null,
        },
      ]
    : []
  const aecRows = verified
    ? Object.entries(benchmark.aec ?? {}).map(([id, value]) => ({ id, ...value }))
    : []
  const ablationRows = verified ? benchmark.ablations ?? [] : []

  return (
    <section data-testid="benchmark">
      <SectionHeader
        title="系统评测"
        status={verified ? (recordLoading || recordError || recordLabel ? <Tag>{recordLoading ? '评测记录 · 正在刷新' : recordError ? '评测记录 · 读取失败' : recordLabel}</Tag> : null) : <StatusTag value={benchmark?.status ?? 'NOT_CHECKED'} />}
      />
      <MetricStrip
        items={[
          { label: '确定性安全场景', value: matrix?.scenario_count ?? '—' },
          { label: '合法请求接受率', value: formatPercent(metrics?.legitimate_request_acceptance_rate) },
          { label: '越权副作用', value: metrics?.unauthorized_side_effects ?? '—' },
          { label: 'AgentGuard P95 延迟', value: formatMs(metrics?.latency_p95_ms) },
        ]}
      />
      {!verified ? (
        <Alert
          type="info"
          showIcon
          icon={<CircleHelp size={18} />}
          message={!benchmark ? recordLoading ? '系统评测记录读取中' : recordError ? '系统评测记录读取失败' : '系统评测记录尚未读取' : '尚无已验收的评测记录'}
          description={!benchmark ? recordError ?? '尚无可展示的接口返回。' : '当前返回记录尚未通过评测验收，不展示指标。'}
          className="benchmark-pending"
        />
      ) : (
        <Alert
          type="info"
          showIcon
          icon={<ShieldCheck size={18} />}
          message={`评测批次 ${benchmark.run_id ?? '未知'}`}
          description={<>
            <div>评测日期 {formatDate(benchmark.generated_at)} · 运行耗时 {benchmark.duration_seconds?.toFixed(2) ?? '—'} 秒</div>
          </>}
          className="benchmark-verified"
        />
      )}

      {verified ? (
        <>
          <div className="work-panel benchmark-run-panel">
            <Descriptions size="small" column={{ xs: 1, sm: 2, lg: 4 }}>
              <Descriptions.Item label="延迟样本">{benchmark.protocol?.latency_samples ?? '—'}</Descriptions.Item>
              <Descriptions.Item label="正常任务样本">{benchmark.protocol?.normal_task_samples ?? '—'}</Descriptions.Item>
              <Descriptions.Item label="吞吐请求数">{benchmark.protocol?.throughput_requests ?? '—'}</Descriptions.Item>
              <Descriptions.Item label="并发数">{benchmark.protocol?.concurrency ?? '—'}</Descriptions.Item>
              <Descriptions.Item label="记录种子">{benchmark.protocol?.random_seed ?? '—'}</Descriptions.Item>
              <Descriptions.Item label="主延迟链长">{benchmark.protocol?.primary_chain_length ?? '未记录'}</Descriptions.Item>
              <Descriptions.Item label="评测部署">{benchmark.environment?.deployment === 'native_windows' ? 'Windows 本机服务' : '未记录'}</Descriptions.Item>
              <Descriptions.Item label="PostgreSQL 版本">{benchmark.environment?.postgresql?.main?.server_version ?? benchmark.environment?.postgresql?.server_version ?? '—'}</Descriptions.Item>
              <Descriptions.Item label="评测模型">{benchmark.environment?.model?.model_requested ?? benchmark.environment?.model?.requested ?? '未记录'}</Descriptions.Item>
              <Descriptions.Item label="记录源码摘要"><Text code title={provenance?.recorded_snapshot_sha256 ?? undefined}>{provenance?.recorded_snapshot_sha256?.slice(0, 12) ?? '未提供'}</Text></Descriptions.Item>
              <Descriptions.Item label="当前源码摘要"><Text code title={provenance?.current_snapshot_sha256 ?? undefined}>{provenance?.current_snapshot_sha256?.slice(0, 12) ?? '未核验'}</Text></Descriptions.Item>
              <Descriptions.Item label="当前规划服务">{profiles?.items.find((item) => item.mode === 'cloud')?.available ? '智能体审查 · 云端已配置' : profiles ? '确定性规则 · 云端不可用' : profileError ? '配置暂不可用' : '配置读取中'}</Descriptions.Item>
            </Descriptions>
            <Text type="secondary">指标适用范围为该批次的样本、环境和链长；不据此断言稳定尾延迟或跨设备表现。记录种子不控制 SM2 随机量或云端推理。</Text>
          </div>

          <div className="work-panel benchmark-comparison-panel">
            <div className="panel-title-row">
              <h2><BarChart3 size={17} /> 匹配业务条件的基线对照</h2>
              <Text type="secondary">同工具实现 / 同硬件 / SM2 与 SM3</Text>
            </div>
            <p>各系统使用按相同策略新建的业务记录。静态凭据与 RBAC 为较弱的对照，缺少持有者证明、逐级委托、任务绑定、多层共享预算和强制回执审计闭环；结果体现整体方案差异。</p>
            <Table<ComparisonRow>
              size="small"
              rowKey="key"
              dataSource={comparisonRows}
              pagination={false}
              scroll={{ x: 1080 }}
              columns={[
                { title: '系统', dataIndex: 'system', fixed: 'left', width: 160, render: (value: string) => <strong>{value}</strong> },
                { title: '合法接受', dataIndex: 'acceptanceRate', width: 100, render: (value: number) => formatPercent(value) },
                { title: '任务完成', dataIndex: 'completionRate', width: 100, render: (value: number) => formatPercent(value) },
                { title: '越权副作用', dataIndex: 'unauthorizedSideEffects', width: 110, render: (value: number) => <StatusTag value={value === 0 ? 'NONE' : String(value)} /> },
                { title: 'P50 延迟', dataIndex: ['latency', 'p50_ms'], width: 110, render: (value: number) => formatMs(value) },
                { title: 'P95 延迟', dataIndex: ['latency', 'p95_ms'], width: 110, render: (value: number) => formatMs(value) },
                { title: 'P99 延迟', dataIndex: ['latency', 'p99_ms'], width: 110, render: (value: number) => formatMs(value) },
                { title: '吞吐', dataIndex: 'throughput', width: 110, render: (value: number) => formatRps(value) },
                { title: '撤销延迟', dataIndex: 'revocationMs', width: 110, render: (value: number) => formatMs(value) },
                {
                  title: '并发预算',
                  width: 140,
                  render: (_, row) => (
                    <span>
                      <StatusTag value={row.budgetSafe ? 'VALID' : 'INVALID'} />
                      <span className="mono"> {row.allowed}A/{row.denied}D</span>
                    </span>
                  ),
                },
              ]}
            />
          </div>

          <div className="benchmark-grid">
            <div className="work-panel benchmark-panel benchmark-fill-panel">
              <div className="panel-title-row"><h2><ShieldCheck size={17} /> AEC 独立校验</h2><Text type="secondary">独立 SQL 检查</Text></div>
              <Table
                size="small"
                rowKey="id"
                dataSource={aecRows}
                pagination={false}
                columns={[
                  { title: '编号', dataIndex: 'id', width: 82, render: (value: string) => <span className="mono">{value}</span> },
                  { title: '不变量', dataIndex: 'name', render: (value: string) => <span title={value}>{aecLabel(value)}</span> },
                  {
                    title: '结果', dataIndex: 'passed', width: 88,
                    render: (value: boolean, row) => row.id === 'AEC-03' && value && row.checks?.unknown_execution_count === 0
                      ? <Tooltip title="本批次没有 UNKNOWN 执行；恢复行为见故障注入回归测试。"><Tag>无 UNKNOWN 样本</Tag></Tooltip>
                      : <StatusTag value={value ? 'VALID' : 'INVALID'} />,
                  },
                ]}
              />
              <div className="benchmark-panel-foot">审计事件 {benchmark.audit?.checked_events ?? '—'}；待写入 Outbox {benchmark.audit?.pending_outbox ?? '—'}；检查点 #{benchmark.audit?.checkpoint_sequence ?? '—'}</div>
            </div>

            <div className="work-panel benchmark-panel benchmark-fill-panel">
              <div className="panel-title-row"><h2><Database size={17} /> 凭证与存储开销</h2><Text type="secondary">逻辑字节数</Text></div>
              <Table<CostRow>
                size="small"
                rowKey="key"
                dataSource={costRows}
                pagination={false}
                columns={[
                  { title: '配置', dataIndex: 'profile' },
                  { title: '凭证', dataIndex: 'credentialBytes', width: 105, render: (value: number | null) => formatBytes(value) },
                  { title: '状态存储', dataIndex: 'storageBytes', width: 105, render: (value: number | null) => formatBytes(value) },
                ]}
              />
            </div>

            <div className="work-panel benchmark-panel">
              <div className="panel-title-row"><h2><Gauge size={17} /> 独立分项耗时</h2><Text type="secondary">不可直接相加</Text></div>
              <p>各行来自独立样本，不能相加为业务总耗时。密码项包含规范化、签名和验签；健康请求包含本机 HTTP 往返；数据库项包含连接、事务和关闭；云端项包含网络、服务排队与响应，不能当作纯模型计算耗时。</p>
              <Table<ComponentRow>
                size="small"
                rowKey="key"
                dataSource={componentRows}
                pagination={false}
                columns={[
                  { title: '组件', dataIndex: 'component' },
                  { title: '平均', dataIndex: 'meanMs', width: 96, render: (value: number | null) => formatMs(value) },
                  { title: 'P95', dataIndex: 'p95Ms', width: 96, render: (value: number | null) => formatMs(value) },
                ]}
              />
            </div>
          </div>

          <div className="work-panel benchmark-ablation-panel">
            <div className="panel-title-row"><h2><FlaskConical size={17} /> 弱基线对照与机制反例</h2><Text type="secondary">简化反例与多机制差异</Text></div>
            <p>预算与幂等项采用简化数据库反例；持有者证明及回执审计项对照同时缺少多项机制的基线，不能据此归因单一机制的独立效果。</p>
            {ablationRows.some((row) => row.name === 'paired_multilevel_budget_reservation') && <p>多层预算项比较同一共享链和金额下的准入机制，只验证测试表中的并发结果，不代表生产表完整路径或端到端性能对照。</p>}
            <Table<BenchmarkAblation>
              size="small"
              rowKey="name"
              dataSource={ablationRows}
              pagination={false}
              scroll={{ x: 760 }}
              columns={[
                { title: '对照或反例', dataIndex: 'name', width: 260, render: (value: string) => ablationLabels[value]?.mechanism ?? value },
                { title: '隔离标记', dataIndex: 'isolated', width: 86, render: (value: boolean) => <Tag color={value ? 'green' : 'red'}>{value ? '是' : '否'}</Tag> },
                { title: '实测观察', render: (_, row) => ablationObservation(row) },
              ]}
            />
          </div>

        </>
      ) : (
        <div className="work-panel benchmark-panel benchmark-empty-panel">
          <Empty description={!benchmark ? recordLoading ? '评测记录读取中' : recordError ? '未获得可用评测记录' : '评测记录未读取' : '当前返回记录暂无可引用实测结果'} />
        </div>
      )}
    </section>
  )
}
