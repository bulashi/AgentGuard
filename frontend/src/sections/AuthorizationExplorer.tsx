import { fenToYuan } from '../money'
import { useMemo } from 'react'
import { Empty, Progress, Table, Typography } from 'antd'
import { Background, Controls, MarkerType, ReactFlow, type Edge, type Node } from '@xyflow/react'
import { KeyRound, Link2, ShieldCheck } from 'lucide-react'
import { BooleanTag, ShortHash, TimeValue } from '../components/Evidence'
import { CredentialObservationTag } from '../components/CredentialObservationTag'
import { observeCredential } from '../credentialObservation'
import { MetricStrip } from '../components/MetricStrip'
import { SectionHeader } from '../components/SectionHeader'
import { CoauthorizationStatusDialog } from '../components/CoauthorizationStatusDialog'
import { CoauthorizationTaskDialog } from '../components/CoauthorizationTaskDialog'
import { RootAuthorizationButton } from '../components/RootAuthorizationButton'
import { agentLabel, credentialTypeLabel, quotaLabel, statusLabel } from '../labels'
import type { BudgetState, CredentialView, TaskSnapshot } from '../types'
import type { EvidenceSelection } from '../executionModel'
import { credentialLevel } from '../executionModel'

const { Text } = Typography

function isMonotonic(credential: CredentialView, credentials: CredentialView[]) {
  if (!credential.parent_credential_id) return true
  const parent = credentials.find((item) => item.credential_id === credential.parent_credential_id)
  if (!parent) return false
  const parentTools = new Set(parent.capabilities.map((item) => item.tool))
  const childTools = credential.capabilities.map((item) => item.tool)
  const toolsNarrow = childTools.every((tool) => parentTools.has(tool))
  const depthNarrow = credential.delegation_depth < parent.delegation_depth
  const timeNarrow = credential.not_before >= parent.not_before && credential.expires_at <= parent.expires_at
  return toolsNarrow && depthNarrow && timeNarrow
}

function credentialGraph(credentials: CredentialView[], observedAt: number): { nodes: Node[]; edges: Edge[] } {
  const byDepth = new Map<number, number>()
  const nodes: Node[] = credentials.map((credential) => {
    const level = credentialLevel(credential, credentials) ?? 0
    const index = byDepth.get(level) ?? 0
    const observation = observeCredential(credential, credentials, observedAt)
    byDepth.set(level, index + 1)
    return {
      id: credential.credential_id,
      position: { x: level * 320 + 30, y: index * 180 + 30 },
      draggable: false,
      className: ['REVOKED', 'ANCESTOR_REVOKED', 'EXPIRED'].includes(observation.code) ? 'credential-node revoked' : 'credential-node',
      data: {
        label: (
          <div className="credential-node-content">
            <div className="credential-node-title"><KeyRound size={15} />{credentialTypeLabel(credential.credential_type)}</div>
            <strong>{agentLabel(credential.holder_agent_id)}</strong>
            <span>可再委托 {credential.delegation_depth} 级 · {credential.capabilities.length} 项能力</span>
            <div><CredentialObservationTag observation={observation} /></div>
          </div>
        ),
      },
    }
  })
  const edges: Edge[] = credentials
    .filter((credential) => credential.parent_credential_id)
    .map((credential) => ({
      id: `parent-${credential.credential_id}`,
      source: credential.parent_credential_id!,
      target: credential.credential_id,
      label: isMonotonic(credential, credentials) ? '可见字段收窄' : statusLabel('INVALID'),
      markerEnd: { type: MarkerType.ArrowClosed },
      style: { stroke: isMonotonic(credential, credentials) ? 'var(--success)' : 'var(--danger)' },
    }))
  return { nodes, edges }
}

function BudgetCell({ budget }: { budget: BudgetState }) {
  const consumed = budget.reserved + budget.committed
  const unit = budget.quota_type === 'refund_total_fen' ? '元' : '次'
  const format = budget.quota_type === 'refund_total_fen' ? fenToYuan : String
  const percent = budget.limit === 0 ? 0 : Math.round((consumed / budget.limit) * 100)
  return (
    <div className="budget-cell">
      <div className="budget-row"><span>{quotaLabel(budget.quota_type)}</span><span className="mono">已占用 {format(consumed)} / {format(budget.limit)} {unit}</span></div>
      <Progress percent={percent} size="small" showInfo format={(value) => `${value}%`} strokeColor="var(--success)" />
      <div className="budget-caption"><span>剩余 {format(budget.remaining)} {unit}</span> · <span>预留 {format(budget.reserved)} {unit}</span> · <span>已提交 {format(budget.committed)} {unit}</span></div>
    </div>
  )
}

export function AuthorizationExplorer({ snapshot, onInspect, onChanged, observedAt = Date.now() / 1000 }: {
  snapshot: TaskSnapshot | null
  observedAt?: number
  onInspect?: (selection: EvidenceSelection) => void
  onChanged?: (taskId: string) => Promise<void>
}) {
  const graph = useMemo(() => credentialGraph(snapshot?.credentials ?? [], observedAt), [observedAt, snapshot])
  const credentials = snapshot?.credentials ?? []
  const monotonic = credentials.every((item) => isMonotonic(item, credentials))
  const validSignatures = credentials.filter((item) => item.signature.valid === true && item.stored_hash_valid === true).length
  const revoked = credentials.filter((item) => typeof item.revoked_at === 'number' && Number.isFinite(item.revoked_at)).length

  return (
    <section data-testid="authorization-explorer">
      <SectionHeader
        title="授权浏览器"
        actions={<div className="coauth-entry-actions"><RootAuthorizationButton
          key={`root-${snapshot?.task.task_id ?? 'no-task'}`} task={snapshot?.task ?? null} onChanged={onChanged} />
        </div>}
        status={credentials.length ? <span className="table-secondary">本机快照观测 <TimeValue value={observedAt} /></span> : undefined}
      />
      <details className="advanced-authorization">
        <summary>高级授权</summary>
        <div className="coauth-entry-actions">
          <CoauthorizationStatusDialog />
          <CoauthorizationTaskDialog key={snapshot?.task.task_id ?? 'no-task'}
            taskId={snapshot?.task.task_id ?? null} taskStatus={snapshot?.task.status ?? null} onChanged={onChanged} />
        </div>
      </details>
      <MetricStrip
        items={[
          { label: '凭证链', value: credentials.length },
          { label: '签名有效', value: validSignatures },
          { label: '投影收窄检查', value: credentials.length ? monotonic ? '一致' : '不一致' : '未记录' },
          { label: '已撤销', value: revoked },
        ]}
      />
      {!snapshot ? (
        <div className="empty-band"><Empty description="选择已授权任务" /></div>
      ) : (
        <div className="authorization-layout">
          <div className="work-panel credential-flow-panel">
            <div className="panel-title-row">
              <h2>根授权 → 中间委托 → 叶子委托</h2>
              <span className="inline-proof"><ShieldCheck size={15} /> SM2 + SM3</span>
            </div>
            <div className="credential-flow" data-testid="credential-flow">
              <ReactFlow
                nodes={graph.nodes}
                edges={graph.edges}
                fitView
                fitViewOptions={{ padding: 0.2 }}
                nodesConnectable={false}
                elementsSelectable={false}
                onNodeClick={(_, node) => {
                  const credential = credentials.find((item) => item.credential_id === node.id)
                  if (credential) onInspect?.({ kind: 'credential', credential })
                }}
                minZoom={0.5}
                maxZoom={1.15}
                ariaLabelConfig={{
                  'controls.zoomIn.ariaLabel': '放大授权图',
                  'controls.zoomOut.ariaLabel': '缩小授权图',
                  'controls.fitView.ariaLabel': '适应全部授权节点',
                }}
              >
                <Background color="var(--line)" gap={22} size={1} />
                <Controls showInteractive={false} />
              </ReactFlow>
            </div>
          </div>

          <div className="work-panel credential-table-panel">
            <div className="panel-title-row">
              <h2>凭证与共享预算</h2>
              <Text type="secondary">权限只能收窄</Text>
            </div>
            <Table<CredentialView>
              size="small"
              rowKey="credential_id"
              dataSource={credentials}
              pagination={false}
              scroll={{ x: 1260 }}
              onRow={(credential) => ({ onClick: () => onInspect?.({ kind: 'credential', credential }), className: 'interactive-row' })}
              columns={[
                {
                  title: '持有者',
                  width: 160,
                  fixed: 'left',
                  render: (_, row) => (
                    <div>
                      <strong>{agentLabel(row.holder_agent_id)}</strong>
                      <div className="table-secondary">{credentialTypeLabel(row.credential_type)} / 可再委托 {row.delegation_depth} 级</div>
                    </div>
                  ),
                },
                { title: '签发者', dataIndex: 'issuer_subject_id', width: 170 },
                {
                  title: '能力',
                  width: 230,
                  render: (_, row) => row.capabilities.map((item) => <div className="mono small-line" key={item.tool}>{item.tool}@{item.version}</div>),
                },
                {
                  title: '共享预算',
                  width: 270,
                  render: (_, row) => <div className="budget-stack">{row.budgets.map((budget) => <BudgetCell budget={budget} key={budget.quota_type} />)}</div>,
                },
                {
                  title: '父授权绑定',
                  width: 190,
                  render: (_, row) => row.parent_credential_hash ? <ShortHash value={row.parent_credential_hash} size={7} /> : <Text type="secondary">根授权</Text>,
                },
                {
                  title: '签名 / 存储哈希',
                  width: 170,
                  render: (_, row) => (
                    <div className="verification-stack">
                      <span><BooleanTag value={row.signature.valid} /> {row.signature.algorithm}</span>
                      <span><BooleanTag value={row.stored_hash_valid} /> SM3</span>
                      <ShortHash value={row.signature.fingerprint_sm3} size={6} />
                    </div>
                  ),
                },
                {
                  title: '投影收窄',
                  width: 110,
                  render: (_, row) => <BooleanTag value={isMonotonic(row, credentials)} />,
                },
                {
                  title: '有效时间',
                  width: 180,
                  render: (_, row) => <div><TimeValue value={row.issued_at} /><div className="table-secondary"><TimeValue value={row.expires_at} /></div></div>,
                },
                {
                  title: '快照观测状态',
                  width: 150,
                  fixed: 'right',
                  render: (_, row) => <CredentialObservationTag observation={observeCredential(row, credentials, observedAt)} />,
                },
              ]}
            />
            <div className="evidence-footer">
              <Link2 size={15} />
              <span>父授权哈希、持有者、能力集合、有效期、委托深度与共享预算均来自持久化签名对象和原子预算状态。</span>
            </div>
          </div>
        </div>
      )}
    </section>
  )
}
