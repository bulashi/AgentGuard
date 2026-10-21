import { useMemo, useState } from 'react'
import { Alert, Descriptions, Empty, Segmented, Table, Typography } from 'antd'
import { Anchor, CheckCircle2, FileCheck2, ShieldAlert } from 'lucide-react'
import { BooleanTag, ShortHash, StatusTag, TimeValue } from '../components/Evidence'
import { MetricStrip } from '../components/MetricStrip'
import { SectionHeader } from '../components/SectionHeader'
import { eventLabel, statusLabel } from '../labels'
import type { AuditEventView, Overview, ReceiptView, TaskSnapshot } from '../types'
import type { EvidenceSelection } from '../executionModel'
import { auditChainIsConsistent, coauthorizationBindingStatus, isCoauthorizationAuditEvent, taskAuditNeedsRefresh } from '../executionModel'
import { observeReceipt } from '../sourceVerification'
import { auditPrefixObservation, auditPrefixSummary, coauthorizationRevocationBindingStatus, coauthorizationRevocationProjection, type AuditPrefixReport } from '../auditPrefixBinding'

const { Text } = Typography

type EvidenceFilter = 'all' | 'rejected' | 'denied' | 'successful'

export function AuditEvidence({
  overview,
  snapshot,
  auditPrefix = null,
  prefixError,
  prefixObservedAt,
  overviewFresh = true,
  overviewLoading = false,
  onInspect,
  section = 'all',
}: {
  overview: Overview | null
  snapshot: TaskSnapshot | null
  auditPrefix?: AuditPrefixReport | null
  prefixError?: string | null
  prefixObservedAt?: number
  overviewFresh?: boolean
  overviewLoading?: boolean
  onInspect?: (selection: EvidenceSelection) => void
  section?: 'all' | 'audit' | 'receipts'
}) {
  const [filter, setFilter] = useState<EvidenceFilter>('all')
  const executions = snapshot?.executions
  const receipts = snapshot?.receipts ?? []
  const events = snapshot?.audit_events ?? []
  const filtered = useMemo(
    () =>
      (executions ?? []).filter((execution) => {
        if (filter === 'rejected') return execution.state === 'DENIED' && execution.reason_code === 'REQUEST_SCHEMA_INVALID'
        if (filter === 'denied') return execution.decision === 'DENY'
        if (filter === 'successful') return execution.state === 'COMMITTED'
        return true
      }),
    [executions, filter],
  )
  const verification = overview?.audit.verification
  const checkpoint = overview?.audit.checkpoint.checkpoint
  const chainChecked = auditChainIsConsistent(overview)
  const pendingAppend = (overview?.audit.pending_outbox ?? 0) > 0
  const pendingVerification = !overviewFresh || overviewLoading || pendingAppend || taskAuditNeedsRefresh(snapshot, overview)
  const prefix = auditPrefixSummary(snapshot?.task.task_id ?? '', events, auditPrefix)
  const scopedPrefix = auditPrefix?.task_id === snapshot?.task.task_id ? auditPrefix : null
  const verifiedCheckpoint = scopedPrefix?.checkpoint?.signed_checkpoint

  return (
    <section data-testid="audit-evidence">
      <SectionHeader
        title={section === 'receipts' ? '签名执行回执' : '审计与证据'}
        status={verification ? <StatusTag value={pendingVerification ? 'NOT_CHECKED' : chainChecked ? 'VALID' : 'INVALID'} /> : undefined}
      />
      {section !== 'receipts' ? <MetricStrip
        items={[
          { label: '链上事件', value: overview?.audit.latest_event_sequence ?? '未读取' },
          { label: '待追加', value: overview?.audit.pending_outbox ?? '未读取' },
          { label: '另读最新检查点', value: checkpoint?.payload.checkpoint_sequence ?? '—' },
          { label: '回滚', value: verification?.rollback_detected === true ? '是' : verification?.rollback_detected === false ? '否' : '待核验' },
        ]}
      /> : null}
      <div className="audit-layout" hidden={section === 'receipts'}>
        <div className="work-panel audit-summary-panel">
          <div className="panel-title-row"><h2>独立审计验证</h2><Anchor size={17} /></div>
          {verification ? (
            <>
              <Alert
                type={!overviewFresh || overviewLoading ? 'warning' : !chainChecked ? 'error' : pendingVerification ? 'warning' : 'success'}
                showIcon
                icon={overviewFresh && !overviewLoading && chainChecked ? <CheckCircle2 size={18} /> : <ShieldAlert size={18} />}
                message={overviewLoading ? '正在读取最新审计概览；以下为上次成功读取记录' : !overviewFresh ? '最新审计概览读取失败；以下报告为上次成功读取记录' : !chainChecked ? '审计核对失败或结果不完整' : pendingAppend ? '已有报告自洽；仍有审计事件待追加、待核验' : pendingVerification ? '已有报告自洽；当前任务新事件待核验' : '审计哈希链（Hash Chain）报告自洽'}
                description={`已检查 ${verification.checked_events} 个事件 · 核对末事件序号 ${verification.latest_event_sequence}`}
                className="compact-alert"
              />
              <Descriptions column={1} size="small" className="audit-descriptions">
                <Descriptions.Item label="最新事件哈希"><ShortHash value={overview?.audit.latest_event_hash} size={12} /></Descriptions.Item>
                <Descriptions.Item label="另读检查点哈希"><ShortHash value={checkpoint?.payload.latest_event_hash} size={12} /></Descriptions.Item>
                <Descriptions.Item label="另读检查点末序号">{checkpoint?.payload.latest_event_sequence ?? '未返回'}</Descriptions.Item>
                <Descriptions.Item label="另读检查点签发者">{checkpoint?.signature.key_id ?? '—'}</Descriptions.Item>
                <Descriptions.Item label="首个无效序号">{verification.first_invalid_sequence ?? '无'}</Descriptions.Item>
                <Descriptions.Item label="检查点时间"><TimeValue value={checkpoint?.payload.timestamp} /></Descriptions.Item>
              </Descriptions>
            </>
          ) : <Empty description={overviewLoading ? '审计概览读取中' : !overviewFresh ? '未获得可用审计概览' : '等待审计服务返回验证结果'} />}
          <h3 className="detail-heading">当前任务逐事件核验</h3>
          {prefixError ? <Alert type="warning" showIcon message={prefixError} className="compact-alert" /> : null}
          <Descriptions column={1} size="small" className="audit-descriptions">
            <Descriptions.Item label="精确前缀覆盖"><StatusTag value={prefix.status} label={prefix.label} /> {prefix.anchored}/{prefix.total}</Descriptions.Item>
            <Descriptions.Item label="本次实际检查点">{verifiedCheckpoint?.payload.checkpoint_sequence ?? '未核验'}</Descriptions.Item>
            <Descriptions.Item label="本次检查点末序号">{verifiedCheckpoint?.payload.latest_event_sequence ?? '未核验'}</Descriptions.Item>
            <Descriptions.Item label="完整检查点摘要"><ShortHash value={scopedPrefix?.checkpoint?.signed_object_hash} size={12} /></Descriptions.Item>
            <Descriptions.Item label="报告读取时间"><TimeValue value={prefixObservedAt} /></Descriptions.Item>
          </Descriptions>
        </div>

        <div className="work-panel evidence-classification-panel" hidden={section !== 'all'}>
          <div className="panel-title-row">
            <h2>执行证据分类</h2>
            <Segmented<EvidenceFilter>
              value={filter}
              onChange={setFilter}
              options={[
                { label: '全部', value: 'all' },
                { label: '原始格式拒绝', value: 'rejected' },
                { label: '授权拒绝', value: 'denied' },
                { label: '成功执行', value: 'successful' },
              ]}
            />
          </div>
          <Table
            size="small"
            rowKey="execution_id"
            dataSource={filtered}
            pagination={{ pageSize: 6, showSizeChanger: false }}
            scroll={{ x: 1100 }}
            onRow={(execution) => ({ onClick: () => onInspect?.({ kind: 'execution', execution }), className: 'interactive-row' })}
            locale={{ emptyText: '当前任务暂无匹配执行证据' }}
            columns={[
              { title: '执行编号', dataIndex: 'execution_id', width: 170, render: (value: string) => <ShortHash value={value} size={8} /> },
              { title: '工具', dataIndex: 'tool_name', width: 190, render: (value: string) => <span className="mono">{value}</span> },
              { title: '网关裁决', dataIndex: 'decision', width: 105, render: (value: string | null) => <StatusTag value={value} /> },
              { title: '拒绝码', dataIndex: 'reason_code', width: 240, render: (value: string | null) => <span className="mono" title={value ?? 'ALLOW'}>{value ?? '无'}</span> },
              { title: '业务副作用', dataIndex: 'business_effect_id', width: 190, render: (value: string | null) => <span className="mono" title={value ?? 'NONE'}>{value ?? '无'}</span> },
              { title: '执行回执', dataIndex: 'receipt_status', width: 110, render: (value: string) => <StatusTag value={value} /> },
              { title: '执行状态', dataIndex: 'state', width: 120, render: (value: string) => <StatusTag value={value} /> },
            ]}
          />
          <div className="evidence-footer"><FileCheck2 size={15} /><span>拒绝回执、成功回执、业务副作用和审计哈希链（Hash Chain）是不同证据对象，不以单一状态替代。</span></div>
        </div>
      </div>

      <div className="work-panel audit-events-panel" hidden={section === 'receipts'}>
        <div className="panel-title-row"><h2>审计哈希链（Hash Chain）事件链</h2><Text type="secondary">当前任务投影</Text></div>
        <Table
          size="small"
          rowKey="event_sequence"
          dataSource={events}
          pagination={{ pageSize: 8, showSizeChanger: false }}
          scroll={{ x: 1100 }}
          onRow={(event) => ({ onClick: () => onInspect?.({ kind: 'audit', event }), className: 'interactive-row' })}
          locale={{ emptyText: '选择已执行任务后显示事件链' }}
          columns={[
            { title: '#', dataIndex: 'event_sequence', width: 60 },
            { title: '事件类型', dataIndex: 'event_type', width: 220, render: (value: string, event: AuditEventView) => {
              if (event.event_type === 'COAUTH_REVOCATION_APPLIED' || event.schema_version === '3.0') {
                const binding = coauthorizationRevocationBindingStatus(event)
                const projection = coauthorizationRevocationProjection(event)
                const taskRoots = projection && snapshot && projection.evidence.tenant_id === snapshot.task.tenant_id
                  ? projection.roots.filter((root) => root.task_id === snapshot.task.task_id) : []
                const created = taskRoots.filter((root) => root.root_revocation_created === true).length
                return <div title={`${value} · 服务端原文 / 摘要 / 元数据绑定：${statusLabel(binding)} · ${auditPrefixObservation(snapshot?.task.task_id ?? '', event, auditPrefix).label}`}>
                  <span>{eventLabel(value)}</span>
                  <div><StatusTag value={binding} label={binding === 'BINDING_CHECKED' ? '绑定已核对' : binding === 'INVALID' ? '绑定未通过' : '绑定待核对'} /></div>
                  <Text type="secondary">{projection
                    ? `第 ${projection.evidence.page_number}/${projection.evidence.page_count} 页 · 本任务 ${taskRoots.length} 根，本次新撤销 ${created} 根`
                    : '撤销投影缺失或不符合契约'}</Text>
                </div>
              }
              return <span title={isCoauthorizationAuditEvent(event) ? `${value} · 结构与摘要绑定核对：${statusLabel(coauthorizationBindingStatus(event))} · ${auditPrefixObservation(snapshot?.task.task_id ?? '', event, auditPrefix).label}` : value}>{eventLabel(value)}</span>
            } },
            { title: '精确前缀覆盖', width: 220, render: (_, event: AuditEventView) => {
              const observation = auditPrefixObservation(snapshot?.task.task_id ?? '', event, auditPrefix)
              return <StatusTag value={observation.status} label={observation.label} />
            } },
            { title: '执行编号', dataIndex: 'execution_id', width: 180, render: (value: string | null) => value === null ? <Text type="secondary">无执行关联</Text> : <ShortHash value={value} size={8} /> },
            { title: '证据引用', dataIndex: 'evidence_reference', width: 180, render: (value: string) => <ShortHash value={value} size={8} /> },
            { title: '前一事件哈希', dataIndex: 'previous_event_hash', width: 210, render: (value: string) => <ShortHash value={value} size={9} /> },
            { title: '当前事件哈希', dataIndex: 'event_hash', width: 210, render: (value: string) => <ShortHash value={value} size={9} /> },
            { title: '时间', dataIndex: 'timestamp', width: 180, render: (value: number) => <TimeValue value={value} /> },
          ]}
        />
      </div>

      <div className="work-panel receipt-panel" hidden={section === 'audit'}>
        <div className="panel-title-row"><h2>签名执行回执</h2><Text type="secondary">签名原文不下发到浏览器</Text></div>
        <Table
          size="small"
          rowKey="receipt_id"
          dataSource={receipts}
          pagination={false}
          scroll={{ x: 1100 }}
          onRow={(receipt) => ({ onClick: () => onInspect?.({ kind: 'receipt', receipt }), className: 'interactive-row' })}
          locale={{ emptyText: '暂无签名回执' }}
          columns={[
            { title: '回执编号', dataIndex: 'receipt_id', width: 180, render: (value: string) => <ShortHash value={value} size={8} /> },
            { title: '回执类型', dataIndex: 'receipt_type', width: 220, render: (value: string) => <span className="mono">{value}</span> },
            { title: '裁决', dataIndex: 'decision', width: 110, render: (value: string) => <StatusTag value={value} /> },
            { title: '原因码', dataIndex: 'reason_code', width: 260, render: (value: string) => <span className="mono">{value}</span> },
            { title: '签名', width: 270, render: (_, row) => <span><BooleanTag value={row.signature.valid} /> {row.signature.key_id} · <ShortHash value={row.signature.fingerprint_sm3} size={6} /></span> },
            { title: '签名与来源绑定', width: 180, render: (_, row: ReceiptView) => <StatusTag value={observeReceipt(row).status} label={observeReceipt(row).label} /> },
            { title: '回执哈希', dataIndex: 'receipt_hash', width: 230, render: (value: string) => <ShortHash value={value} size={9} /> },
          ]}
        />
      </div>
    </section>
  )
}
