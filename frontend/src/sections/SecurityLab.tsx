import { useMemo, useState } from 'react'
import {
  Alert,
  Select,
  Space,
  Table,
  Tag,
  Typography,
} from 'antd'
import { ArrowUpRight, Cloud, FlaskConical, ShieldCheck, ShieldX } from 'lucide-react'
import { BooleanTag, ShortHash, StatusTag } from '../components/Evidence'
import { WorkflowStatusTag } from '../components/WorkflowStatusTag'
import { isBusinessStop } from '../workflowModel'
import { MetricStrip } from '../components/MetricStrip'
import { SectionHeader } from '../components/SectionHeader'
import { LiquidGlassButton } from '../components/LiquidGlassButton'
import { scenarioCategoryLabel, scenarioInvariantLabel } from '../labels'
import type { DemoRunState } from '../App'
import type { DemoResult, SecurityMatrix, SecurityScenario, TaskSnapshot } from '../types'
import type { EvidenceSelection } from '../executionModel'
import { observeReceipt, sourceVerificationState } from '../sourceVerification'
import { SecurityProofPanel } from './SecurityProofPanel'

const { Text, Paragraph } = Typography

function pipeline(snapshot: TaskSnapshot | null) {
  const execution = snapshot?.executions.at(-1)
  if (!execution) return []
  const credentialsValid = snapshot?.credentials.every(
    (item) => item.signature.valid === true && item.stored_hash_valid === true
      && sourceVerificationState(item.source_verification, 'CREDENTIAL_ROW_BINDING_V1') === 'VERIFIED',
  ) ?? false
  const receipt = snapshot?.receipts.find((item) => item.execution_id === execution.execution_id)
  const denialAtParameters = execution.reason_code === 'PARAMETER_CONSTRAINT_VIOLATION'
  const inferredPass = denialAtParameters && credentialsValid
  return [
    { stage: '请求格式校验', state: inferredPass ? 'INFERRED_PASS' : 'CHECK', evidence: execution.request_hash },
    { stage: '参数 SM3 摘要', state: execution.parameter_hash ? 'RECORDED' : 'MISSING', evidence: execution.parameter_hash },
    { stage: '授权凭证链', state: inferredPass ? 'INFERRED_PASS' : 'CHECK', evidence: execution.credential_chain_hash },
    { stage: '凭证签名与存储哈希', state: credentialsValid ? 'VALID' : 'INVALID', evidence: snapshot?.credentials.at(-1)?.signature.fingerprint_sm3 },
    { stage: '持有者证明（Holder Proof）', state: inferredPass ? 'INFERRED_PASS' : 'CHECK', evidence: snapshot?.credentials.at(-1)?.holder_key_id },
    { stage: '租户 / 任务 / 受众绑定', state: inferredPass ? 'INFERRED_PASS' : 'CHECK', evidence: snapshot?.task.task_id },
    { stage: '服务 / 工具 / 版本绑定', state: inferredPass ? 'INFERRED_PASS' : 'CHECK', evidence: `${execution.tool_service}/${execution.tool_name}@${execution.tool_version}` },
    { stage: '资源范围校验', state: inferredPass ? 'INFERRED_PASS' : 'CHECK', evidence: snapshot?.task.ticket_id },
    { stage: '参数约束校验', state: denialAtParameters ? 'DENY' : execution.decision ?? 'CHECK', evidence: execution.reason_code },
    { stage: '原子准入与共享预算', state: denialAtParameters ? 'NOT_REACHED' : execution.state, evidence: execution.business_action_id },
    { stage: '回执签名与来源绑定', state: receipt ? observeReceipt(receipt).status : 'MISSING', evidence: receipt?.receipt_hash },
    { stage: '业务副作用', state: execution.business_effect_id ? 'PRESENT' : 'NONE', evidence: execution.business_effect_id },
    { stage: '审计哈希链（Hash Chain）', state: snapshot?.audit_events.length ? 'RECORDED' : 'PENDING', evidence: snapshot?.audit_events.at(-1)?.event_hash },
  ]
}

export function SecurityLab({
  matrix,
  matrixLoading = false,
  matrixError,
  snapshot,
  demo,
  runState,
  onInspect,
  onOpenRun,
  onCloudReview,
  onProofReady,
}: {
  matrix: SecurityMatrix | null
  matrixLoading?: boolean
  matrixError?: string | null
  snapshot: TaskSnapshot | null
  demo: DemoResult | null
  runState?: DemoRunState
  onDemo: (result: DemoResult) => Promise<void>
  onDemoStart?: (kind: string) => void
  onDemoError?: () => void
  onInspect?: (selection: EvidenceSelection) => void
  onOpenRun?: () => void
  onCloudReview?: () => void
  onProofReady?: (taskId: string) => Promise<void>
}) {
  const [category, setCategory] = useState('all')
  const attackSnapshot = demo?.demo_kind === 'LIVE_LLM_INJECTION' && demo.task_id === snapshot?.task.task_id ? snapshot : null
  const plannerStopped = isBusinessStop(demo?.reason_code)
  const gatewayDenied = !!attackSnapshot?.executions.some((item) => item.decision === 'DENY')
  const effectCount = attackSnapshot ? attackSnapshot.business_effects.refunds.length + attackSnapshot.business_effects.notifications.length : null
  const stages = useMemo(
    () => (demo?.demo_kind === 'LIVE_LLM_INJECTION' && demo.task_id === snapshot?.task.task_id && !plannerStopped ? pipeline(snapshot) : []),
    [demo, snapshot, plannerStopped],
  )
  const scenarios = matrix?.scenarios.filter(
    (scenario) => category === 'all' || scenario.category === category,
  ) ?? []
  const categories = Object.keys(matrix?.categories ?? {})

  return (
    <section data-testid="security-lab">
      <SectionHeader
        title="安全测试"
        status={demo?.demo_kind === 'LIVE_LLM_INJECTION' ? <WorkflowStatusTag state={demo.status} reasonCode={demo.reason_code} /> : runState?.phase === 'requesting' ? <StatusTag value="PENDING" /> : undefined}
        actions={
          <LiquidGlassButton type="primary" icon={<Cloud size={16} />} disabled={!onCloudReview || runState?.phase === 'requesting'} onClick={onCloudReview}>
            进入智能体注入审查
          </LiquidGlassButton>
        }
      />
      <MetricStrip
        items={[
          { label: '确定性场景', value: matrix?.scenario_count ?? (matrixLoading ? '读取中' : matrixError ? '读取失败' : '未读取') },
          { label: '攻击类别', value: matrix ? categories.length : '未读取' },
          { label: '越权副作用', value: demo?.demo_kind === 'LIVE_LLM_INJECTION' && demo.status === 'DENIED' ? effectCount ?? '待读取' : '—' },
          { label: '模型边界', value: '仅候选，不授权' },
        ]}
      />

      <SecurityProofPanel onInspect={onInspect} onReady={onProofReady} />

      {demo?.demo_kind === 'LIVE_LLM_INJECTION' ? <div className="security-layout">
        <div className="work-panel attack-panel">
          <div className="panel-title-row">
            <h2>历史独立注入记录</h2>
            <span className="inline-proof"><FlaskConical size={15} /> 历史候选记录</span>
          </div>
          <p>以下为已保存记录，查看不会重新执行。现场测试请进入上方智能体注入审查。</p>
          <div className="attack-observation">
            <div>
              <span className="metric-label">候选规划器</span>
              <strong>{demo.planner === 'llm' ? 'AI 规划器' : '确定性规则'}</strong>
            </div>
            <div>
              <span className="metric-label">协作结果</span>
              <WorkflowStatusTag state={demo.status} reasonCode={demo.reason_code} />
            </div>
            <div>
              <span className="metric-label">停止 / 拒绝原因</span>
              <Text className="mono">{demo?.demo_kind === 'LIVE_LLM_INJECTION' ? demo.reason_code ?? '允许' : '—'}</Text>
            </div>
            <div>
              <span className="metric-label">业务副作用</span>
              <StatusTag value={effectCount === null ? null : effectCount === 0 ? 'NONE' : 'PRESENT'} />
            </div>
          </div>
          {demo?.demo_kind === 'LIVE_LLM_INJECTION' ? (
            <>
            <Alert
              type={plannerStopped ? 'info' : gatewayDenied ? 'success' : 'warning'}
              showIcon
              icon={demo.status === 'DENIED' ? <ShieldCheck size={18} /> : <ShieldX size={18} />}
              message={plannerStopped ? '模型停止办理；这不是网关拦截证据' : gatewayDenied ? '执行记录中已确认网关拒绝' : '需核对执行记录与业务结果'}
              description={demo.reason_code ?? '未记录拒绝原因'}
              className="compact-alert"
            />
            <div className="security-run-action"><LiquidGlassButton icon={<ArrowUpRight size={15} />} onClick={onOpenRun}>打开执行图与完整记录</LiquidGlassButton></div>
            </>
          ) : null}
        </div>

        <div className="work-panel pipeline-panel">
          <div className="panel-title-row"><h2>网关核验链</h2><Text type="secondary">首个失败即停止</Text></div>
          {stages.length ? (
            <>
              <div className="pipeline-list" data-testid="gateway-pipeline">
                {stages.map((stage, index) => (
                  <button type="button" className="pipeline-row" key={stage.stage} onClick={() => onInspect?.({ kind: 'pipeline', title: stage.stage, value: { ...stage, evidence_type: stage.state === 'INFERRED_PASS' ? 'inferred_from_first_failure' : 'BFF_projection' } })}>
                    <span className="pipeline-index">{String(index + 1).padStart(2, '0')}</span>
                    <span className="pipeline-stage">{stage.stage}</span>
                    <StatusTag value={String(stage.state)} />
                    <ShortHash value={stage.evidence ? String(stage.evidence) : null} size={7} copyable={false} />
                  </button>
                ))}
              </div>
              <Text type="secondary" className="pipeline-evidence-note">
                “推断通过”依据首个失败顺序与最终拒绝码推断；没有逐阶段内部事件。审计留证与独立检查点核验分别展示。
              </Text>
            </>
          ) : (
            <div className="pipeline-empty"><ShieldCheck size={30} /><span>运行安全场景后显示裁决证据</span></div>
          )}
        </div>
      </div> : null}

      <div className="work-panel scenario-panel">
        <div className="panel-title-row">
          <h2>确定性安全场景</h2><Text type="secondary">已保存测试批次；点击仅查看证据</Text>
          <Space>
            <Select
              value={category}
              onChange={setCategory}
              options={[{ value: 'all', label: '全部类别' }, ...categories.map((item) => ({ value: item, label: `${scenarioCategoryLabel(item)}（${matrix?.categories[item]}）` }))]}
              style={{ width: 220 }}
            />
            {matrix ? <BooleanTag value={matrix.success_invariant === 'unauthorized_side_effects == 0'} /> : <StatusTag value="NOT_CHECKED" />}
          </Space>
        </div>
        <div className="scenario-batch-line">
          {matrix?.latest_batch?.status === 'VERIFIED' ? <>
            <StatusTag value="PASS" label={`${matrix.scenario_count} 项逐场景核验`} />
            <span>隔离测试批次</span><code>{matrix.latest_batch.run_id}</code>
            <ShortHash value={matrix.latest_batch.source_snapshot_sha256} />
          </> : <><StatusTag value="NOT_CHECKED" /><span>{matrix?.latest_batch?.status === 'SOURCE_CHANGED' ? '源码已变更，需重新绑定核验批次' : matrix?.latest_batch?.status === 'INVALID_EVIDENCE' ? '批次证据未通过完整性核对' : '尚未发布与当前源码绑定的核验批次'}</span></>}
        </div>
        <Table<SecurityScenario>
          size="small"
          rowKey="id"
          dataSource={scenarios}
          loading={matrixLoading && !matrix}
          locale={{ emptyText: matrixError ? '场景矩阵读取失败' : !matrix ? '场景矩阵未读取' : '没有匹配的安全场景' }}
          pagination={{ pageSize: 8, showSizeChanger: false }}
          scroll={{ x: 1170 }}
          onRow={(scenario) => ({ onClick: () => onInspect?.({ kind: 'scenario', scenario }), className: 'interactive-row' })}
          columns={[
            { title: '场景', dataIndex: 'id', width: 220, render: (value: string) => <span className="mono" title={value}>{value}</span> },
            { title: '类别', dataIndex: 'category', width: 145, render: (value: string) => <Tag title={value}>{scenarioCategoryLabel(value)}</Tag> },
            { title: '本批次核验', width: 125, render: (_, row) => row.latest_result ? <StatusTag value={row.latest_result.status} /> : <StatusTag value="NOT_CHECKED" /> },
            { title: '安全不变量', dataIndex: 'target_invariant', render: (value: string) => <Paragraph ellipsis={{ rows: 2, expandable: true, symbol: '展开' }} className="table-paragraph" title={value}>{scenarioInvariantLabel(value)}</Paragraph> },
            { title: '期望决策', dataIndex: 'expected_decision', width: 150, render: (value: string) => <StatusTag value={value} /> },
            { title: '拒绝码（原始）', width: 250, render: (_, row) => row.expected_reason_codes.map((code) => <div className="mono small-line" key={code}>{code}</div>) },
            { title: '预期副作用', dataIndex: 'expected_business_effects', width: 100, render: (value: number | string) => <strong className="mono">{value}</strong> },
          ]}
        />
      </div>
    </section>
  )
}
