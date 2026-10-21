import { render, screen, within } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../api'
import type { BenchmarkSummary, BenchmarkSystemMeasurement } from '../types'
import { Benchmark } from './Benchmark'

function measurement(name: string, budgetSafe: boolean): BenchmarkSystemMeasurement {
  return {
    name,
    legitimate_accepted: 3,
    legitimate_attempts: 3,
    legitimate_request_acceptance_rate: 1,
    normal_task_attempts: 1,
    normal_tasks_completed: 1,
    normal_task_completion_rate: 1,
    latency_ms: {
      count: 3,
      min_ms: 10,
      max_ms: 20,
      mean_ms: 15,
      p50_ms: 15,
      p95_ms: 19,
      p99_ms: 20,
    },
    throughput_rps: 12,
    attack_outcome: {
      attack: 'test',
      decision: name === 'agentguard' ? 'DENY' : 'ALLOW',
      http_status: 200,
      reason_code: 'TEST',
      unauthorized_side_effects: name === 'agentguard' ? 0 : 1,
    },
    revocation: { denied: true, latency_ms: 25, reason_code: 'REVOKED' },
    concurrent_consistency: {
      allowed: budgetSafe ? 1 : 2,
      denied: budgetSafe ? 1 : 0,
      budget_safe: budgetSafe,
      committed_refund_fen: budgetSafe ? 6000 : 12000,
      configured_limit_fen: 10000,
    },
    state_storage: { logical_bytes: 4096, tables: {} },
  }
}

const verifiedBenchmark: BenchmarkSummary = {
  status: 'VERIFIED',
  run_id: 'formal-run-01',
  generated_at: '2026-09-30T00:00:00Z',
  duration_seconds: 12,
  source_provenance: {
    status: 'SOURCE_CHANGED',
    recorded_snapshot_sha256: '1'.repeat(64),
    current_snapshot_sha256: '2'.repeat(64),
  },
  acceptance: { passed: true, checks: { aec_01: true } },
  protocol: { latency_samples: 3, normal_task_samples: 1, throughput_requests: 4, concurrency: 2, primary_chain_length: 3, random_seed: 42 },
  environment: {
    deployment: 'native_windows',
    postgresql: { main: { server_version: '16.15' } },
    model: { provider: 'DeepSeek', model_requested: 'deepseek-flash' },
  },
  metrics: {
    legitimate_request_acceptance_rate: 1,
    normal_task_completion_rate: 1,
    unauthorized_side_effects: 0,
    latency_p95_ms: 19,
    credential_size_bytes: {
      agentguard_by_chain_length: { '1': { chain_bytes: 1500, credential_bytes: [1500] } },
      conventional_rbac: 36,
      shared_static_credential: 38,
    },
    state_storage_bytes: {
      agentguard: { logical_bytes: 4096, tables: {} },
      conventional_rbac: { logical_bytes: 2048, tables: {} },
      shared_static_credential: { logical_bytes: 2048, tables: {} },
    },
    component_latency_ms: {
      crypto_sign_and_verify_ms: { mean_ms: 3, p95_ms: 4 },
      network_gateway_health_ms: { mean_ms: 1, p95_ms: 2 },
      persistence_insert_delete_ms: { mean_ms: 4, p95_ms: 5 },
      model_inference: { model: 'deepseek-flash', wall_ms: 600 },
    },
  },
  agentguard: measurement('agentguard', true),
  baselines: [
    measurement('shared_static_credential', false),
    measurement('conventional_rbac', false),
  ],
  aec: {
    'AEC-01': { name: 'authorization-to-effect unique mapping', passed: true, checks: {} },
  },
  audit: { valid: true, checked_events: 20, pending_outbox: 0, checkpoint_sequence: 20 },
  ablations: [
    {
      name: 'non_atomic_budget_admission',
      isolated: true,
      decisions_allowed: 2,
      committed_fen: 12000,
      limit_fen: 10000,
    },
  ],
}

describe('Benchmark', () => {
  beforeEach(() => {
    vi.spyOn(api, 'runtimeProfiles').mockResolvedValue({ workflow_enabled: true, items: [
      { mode: 'cloud', label: '智能体审查', provider: 'deepseek', model: 'deepseek-flash', available: true,
        verification: 'configured_not_invoked', message: '已配置' },
    ] })
  })
  afterEach(() => vi.restoreAllMocks())
  it('never presents placeholder metrics as measured Phase 17 evidence', () => {
    render(
      <Benchmark
        benchmark={{ status: 'PENDING_PHASE_17', message: 'pending' }}
        matrix={null}
        overview={null}
      />,
    )
    expect(screen.getByText('尚无已验收的评测记录')).toBeInTheDocument()
    expect(screen.getByText('当前返回记录暂无可引用实测结果')).toBeInTheDocument()
    expect(screen.queryByText('0 ms')).not.toBeInTheDocument()
  })

  it('renders only structured metrics from a verified accepted summary', () => {
    render(
      <Benchmark
        benchmark={verifiedBenchmark}
        matrix={{ scenario_count: 36 } as never}
        overview={null}
      />,
    )

    expect(screen.getByText('评测批次 formal-run-01')).toBeInTheDocument()
    expect(screen.getAllByText('AgentGuard').length).toBeGreaterThan(0)
    expect(screen.getAllByText('100.0%').length).toBeGreaterThan(0)
    expect(screen.getByText('AEC-01')).toBeInTheDocument()
    expect(screen.getByText('授权到业务效果的唯一映射')).toHaveAttribute('title', 'authorization-to-effect unique mapping')
    expect(screen.getByText('非原子预算更新反例')).toBeInTheDocument()
    expect(screen.getByText('历史评测记录')).toBeInTheDocument()
    expect(screen.queryByTestId('benchmark-source-boundary')).not.toBeInTheDocument()
    expect(screen.queryByText('当前批次')).not.toBeInTheDocument()
    expect(screen.queryByText(/"latency_ms"/)).not.toBeInTheDocument()
  })

  it('shows paired budget trial counts and its limited mechanism scope', () => {
    render(<Benchmark benchmark={{ ...verifiedBenchmark, ablations: [{
      name: 'paired_multilevel_budget_reservation', isolated: true, trial_count: 30,
      atomic: { invariant_violation_trials: 0 }, read_check_write: { overcommitted_trials: 30 },
    }] }} matrix={null} overview={null} />)
    expect(screen.getByText('多层共享预算配对验证')).toBeInTheDocument()
    expect(screen.getByText('配对 30 组；原子组预算违规 0 组；先读后写超额 30 组')).toBeInTheDocument()
    expect(screen.getByText(/只验证测试表中的并发结果/)).toHaveTextContent('不代表生产表完整路径或端到端性能对照')
  })

  it('does not turn absent paired budget observations into zero violations', () => {
    render(<Benchmark benchmark={{ ...verifiedBenchmark, ablations: [{
      name: 'paired_multilevel_budget_reservation', isolated: true, trial_count: 30,
    }] }} matrix={null} overview={null} />)
    expect(screen.getByText('配对 30 组；原子组预算违规 未提供 组；先读后写超额 未提供 组')).toBeInTheDocument()
    expect(screen.queryByText(/原子组预算违规 0 组/)).not.toBeInTheDocument()
  })

  it('separates the archived planning sample from the current cloud service without renaming measurements', async () => {
    render(<Benchmark benchmark={verifiedBenchmark} matrix={null} overview={null} />)
    expect(await screen.findByText('智能体审查 · 云端已配置')).toBeInTheDocument()
    expect(screen.getByText('评测模型')).toBeInTheDocument()
    expect(screen.getByText('deepseek-flash')).toBeInTheDocument()
    expect(screen.getByText('历史评测记录')).toBeInTheDocument()
    expect(screen.queryByText('评测规划配置')).not.toBeInTheDocument()
    expect(screen.queryByText('本地 AI 样本（归档）')).not.toBeInTheDocument()
    expect(screen.queryByText(/qwen2\.5|本地模型|Ollama|不代表当前 Windows|安全边界|创新表述/)).not.toBeInTheDocument()
    expect(verifiedBenchmark.environment?.model?.model_requested).toBe('deepseek-flash')
  })

  it('does not infer a deployment or planning engine from missing archived configuration', async () => {
    render(<Benchmark benchmark={{ ...verifiedBenchmark, environment: undefined }} matrix={null} overview={null} />)
    expect(await screen.findByText('智能体审查 · 云端已配置')).toBeInTheDocument()
    expect(screen.getAllByText('未记录')).toHaveLength(2)
    expect(screen.queryByText('本机部署')).not.toBeInTheDocument()
    expect(screen.queryByText('确定性规则')).not.toBeInTheDocument()
  })

  it('does not present accepted metrics with missing provenance as current evidence', () => {
    render(<Benchmark benchmark={{ ...verifiedBenchmark, source_provenance: undefined }} matrix={null} overview={null} />)
    expect(screen.getByText('来源未核验')).toBeInTheDocument()
    expect(screen.queryByTestId('benchmark-source-boundary')).not.toBeInTheDocument()
    expect(screen.getByText('评测批次 formal-run-01')).toBeInTheDocument()
    expect(screen.queryByText('当前批次')).not.toBeInTheDocument()
  })

  it('omits the matching-source heading tag without declaring a new performance run', () => {
    render(<Benchmark benchmark={{ ...verifiedBenchmark, source_provenance: {
      status: 'MATCH', recorded_snapshot_sha256: '2'.repeat(64), current_snapshot_sha256: '2'.repeat(64),
    } }} matrix={null} overview={null} />)
    expect(screen.queryByText('源码一致的评测记录')).not.toBeInTheDocument()
    expect(screen.queryByTestId('benchmark-source-boundary')).not.toBeInTheDocument()
    expect(screen.queryByText('当前批次')).not.toBeInTheDocument()
  })

  it('discloses weak baseline and simplified counterexample differences without single-factor claims', () => {
    render(<Benchmark benchmark={verifiedBenchmark} matrix={null} overview={null} />)
    expect(screen.getByText('匹配业务条件的基线对照')).toBeInTheDocument()
    expect(screen.getByText('弱基线对照与机制反例')).toBeInTheDocument()
    expect(screen.getByText(/预算与幂等项采用简化数据库反例/)).toHaveTextContent('不能据此归因单一机制的独立效果')
    expect(screen.getByText(/各系统使用按相同策略新建的业务记录/)).toHaveTextContent('结果体现整体方案差异')
    expect(screen.queryByText('每次仅移除一个机制')).not.toBeInTheDocument()
    expect(screen.queryByText('相同记录 / 工具 / 硬件 / 密码算法')).not.toBeInTheDocument()
  })

  it('renders imported model latency statistics before legacy flat values', async () => {
    render(<Benchmark benchmark={{ ...verifiedBenchmark, metrics: {
      ...verifiedBenchmark.metrics,
      component_latency_ms: {
        ...verifiedBenchmark.metrics?.component_latency_ms,
        model_inference: {
          status: 'IMPORTED', sample_count: 12,
          latency_ms: { count: 12, mean_ms: 2070.75, p95_ms: 2532.2 },
          mean_ms: 1, wall_ms: 2, p95_ms: 3,
        },
      },
    } }} matrix={null} overview={null} />)
    expect(await screen.findByText('智能体审查 · 云端已配置')).toBeInTheDocument()
    const row = screen.getByText('云端规划 HTTP 往返').closest('tr')!
    expect(within(row).getAllByRole('cell').map((cell) => cell.textContent)).toEqual([
      '云端规划 HTTP 往返', '2070.75 ms', '2532.20 ms',
    ])
  })

  it('keeps legacy model latency fallbacks and never substitutes zero for missing statistics', async () => {
    const { rerender } = render(<Benchmark benchmark={verifiedBenchmark} matrix={null} overview={null} />)
    expect(await screen.findByText('智能体审查 · 云端已配置')).toBeInTheDocument()
    const cases = [
      { model: { mean_ms: 640, wall_ms: 600, p95_ms: 750 }, cells: ['640.00 ms', '750.00 ms'] },
      { model: { wall_ms: 600 }, cells: ['600.00 ms', '—'] },
      { model: { status: 'IMPORTED', sample_count: 12 }, cells: ['—', '—'] },
      { model: { latency_ms: { mean_ms: 'invalid', p95_ms: Infinity }, mean_ms: 640, p95_ms: 750 }, cells: ['640.00 ms', '750.00 ms'] },
    ]
    for (const { model, cells } of cases) {
      rerender(<Benchmark benchmark={{ ...verifiedBenchmark, metrics: {
        ...verifiedBenchmark.metrics,
        component_latency_ms: { ...verifiedBenchmark.metrics?.component_latency_ms, model_inference: model },
      } }} matrix={null} overview={null} />)
      const row = screen.getByText('云端规划 HTTP 往返').closest('tr')!
      expect(within(row).getAllByRole('cell').slice(1).map((cell) => cell.textContent)).toEqual(cells)
    }
  })

  it('marks an accepted AEC-03 with zero UNKNOWN executions as an empty sample and preserves other verdicts', async () => {
    const { rerender } = render(<Benchmark benchmark={verifiedBenchmark} matrix={null} overview={null} />)
    expect(await screen.findByText('智能体审查 · 云端已配置')).toBeInTheDocument()
    const cases = [
      { count: 0, passed: true, label: '无 UNKNOWN 样本' },
      { count: 2, passed: true, label: '有效' },
      { count: undefined, passed: true, label: '有效' },
      { count: 0, passed: false, label: '无效' },
      { count: 2, passed: false, label: '无效' },
    ]
    for (const { count, passed, label } of cases) {
      rerender(<Benchmark benchmark={{ ...verifiedBenchmark, aec: {
        ...verifiedBenchmark.aec,
        'AEC-03': { name: 'unknown-result safety', passed,
          checks: count === undefined ? {} : { unknown_execution_count: count } },
      } }} matrix={null} overview={null} />)
      const row = screen.getByText('AEC-03').closest('tr')!
      const result = within(row).getByText(label)
      if (count === 0 && passed) {
        expect(result).not.toHaveClass('ant-tag-green')
        expect(within(row).queryByText('有效')).not.toBeInTheDocument()
      } else {
        expect(result).toHaveAttribute('title', passed ? 'VALID' : 'INVALID')
      }
      const knownSampleRow = screen.getByText('AEC-01').closest('tr')!
      expect(within(knownSampleRow).getByText('有效')).toHaveAttribute('title', 'VALID')
    }
  })
})
