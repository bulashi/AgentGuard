import { CustomerName } from '../components/CustomerName'
import { useEffect, useState } from 'react'
import { Alert, App, Modal, Select, Tag } from 'antd'
import { ArrowUpRight, FileJson, History, Play, ShieldCheck } from 'lucide-react'
import { api } from '../api'
import { LiquidGlassButton } from '../components/LiquidGlassButton'
import { Fen, ShortHash, StatusTag } from '../components/Evidence'
import type { EvidenceSelection } from '../executionModel'
import type { SecurityProofReport } from '../types'

export function SecurityProofPanel({ onInspect, onReady }: {
  onInspect?: (selection: EvidenceSelection) => void
  onReady?: (taskId: string) => Promise<void>
}) {
  const { message } = App.useApp()
  const [kind, setKind] = useState<SecurityProofReport['kind']>('wrong_customer')
  const [running, setRunning] = useState(false)
  const [confirmation, setConfirmation] = useState(false)
  const [report, setReport] = useState<SecurityProofReport | null>(null)
  const [origin, setOrigin] = useState<'saved' | 'current'>('saved')
  const [history, setHistory] = useState<SecurityProofReport[]>([])
  const [historyError, setHistoryError] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let mounted = true
    async function load() {
      try {
        const value = await api.securityProofs()
        if (mounted) setHistory(value.items)
      } catch {
        if (mounted) setHistoryError(true)
      }
    }
    void load()
    return () => { mounted = false }
  }, [])

  async function select(saved: SecurityProofReport, source: 'saved' | 'current' = 'saved') {
    setReport(saved)
    setOrigin(source)
    setError(null)
    try { await onReady?.(saved.task_id) } catch { setError('任务详情暂未读取成功，验证原始记录仍已保存。') }
  }

  async function run() {
    setConfirmation(false)
    setRunning(true)
    setError(null)
    setReport(null)
    try {
      const result = await api.securityProof(kind)
      setHistory((items) => [result, ...items.filter((item) => item.proof_id !== result.proof_id)].slice(0, 20))
      setHistoryError(false)
      await select(result, 'current')
      if (result.status === 'FAIL') void message.error('验证未通过，请检查实际裁决和业务记录。')
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : '验证请求失败，不能确认业务结果。')
    } finally { setRunning(false) }
  }

  function inspect(title: string, value: unknown) {
    if (report) onInspect?.({ kind: 'pipeline', title, value, taskId: report.task_id })
  }

  const attack = report?.attack
  const control = report?.control
  const checks = report && attack ? [
    { title: '根授权及两级委托', ok: attack.chain_valid, value: { credential_ids: attack.request.credential_ids, chain_hash: attack.request.credential_chain_hash }, source: '凭证验签与数据库绑定' },
    { title: '受限代理持有者签名', ok: attack.holder_proof_valid, value: attack.request.holder_signature, source: 'BFF 独立 SM2 验签' },
    { title: '真实网关裁决', ok: attack.gateway.decision === 'DENY', value: attack.gateway, source: attack.gateway.reason_code ?? '未确认拒绝原因' },
    { title: '签名回执与请求关联', ok: attack.receipt_valid && attack.record_binding_valid, value: { receipt_projection: attack.gateway.receipt, request_id: attack.request.request_id }, source: '回执验签与记录绑定' },
    { title: '全链共享预算', ok: attack.budget_unchanged, value: { before: attack.before.budgets, after: attack.after.budgets }, source: '拒绝前后保持不变' },
    { title: '越权请求业务变化', ok: attack.refund_delta === 0 && attack.notification_delta === 0, value: { before: attack.before, after: attack.after }, source: `${attack.refund_delta} 笔退款 · ${attack.notification_delta} 条通知` },
    { title: '合法请求对照', ok: report.checks.legal_control_committed, value: control, source: control ? `${control.refund_delta} 笔退款 · ${control.gateway.state}` : '未执行' },
  ] : []

  return <div className="security-proof-section" data-testid="security-proof">
    <div className="panel-title-row">
      <h2><ShieldCheck size={18} /> 有效签名不等于有效授权</h2>
      {report ? <StatusTag value={report.status} /> : <Tag>确定性验证</Tag>}
    </div>
    <div className="security-proof-toolbar">
      <Select aria-label="越权验证类型" value={kind} disabled={running}
        onChange={setKind} options={[{ value: 'wrong_customer', label: '更换未授权客户' }, { value: 'over_amount', label: '超过授权金额' }]} />
      <LiquidGlassButton type="primary" icon={<Play size={16} />} loading={running} disabled={running}
        onClick={() => setConfirmation(true)}>验证拒绝与合法对照</LiquidGlassButton>
      <Select aria-label="历史验证记录" placeholder={historyError ? '历史记录读取失败' : '历史验证记录'}
        disabled={running || !history.length} value={report?.proof_id}
        suffixIcon={<History size={15} />} onChange={(id) => { const saved = history.find((item) => item.proof_id === id); if (saved) void select(saved) }}
        options={history.map((item) => ({ value: item.proof_id, label: `${new Date(item.created_at_ms).toLocaleString()} · ${item.kind === 'wrong_customer' ? '客户越界' : '金额越界'} · ${item.status}` }))} />
    </div>
    {error ? <Alert type="error" showIcon message={error} /> : null}
    {running ? <div className="proof-running" role="status">正在签发授权、两级委托并核对真实业务结果</div> : null}
    {report && attack ? <>
      <div className="proof-reference"><Tag>{origin === 'current' ? '本次执行' : '已保存验证记录'}</Tag><span>{new Date(report.created_at_ms).toLocaleString()}</span><ShortHash value={report.proof_id} /> <span>{report.ticket_id} / <CustomerName id={report.customer_id} /></span><span>构造攻击候选 · 不调用大模型</span></div>
      <div className="security-proof-grid">
        <div className="proof-request-column">
          <h3>授权范围与越权候选</h3>
          <dl className="proof-scope">
            <dt>指定客户</dt><dd><CustomerName id={report.customer_id} /></dd>
            <dt>授权金额</dt><dd><Fen value={report.refund_limit_fen} /></dd>
            <dt>候选请求</dt><dd><pre>{JSON.stringify(attack.request.canonical_parameters, null, 2)}</pre></dd>
            <dt>网关拒绝码</dt><dd className="mono proof-reason">{attack.gateway.reason_code ?? '未确认'}</dd>
          </dl>
          <div className="proof-inline-actions">
            <LiquidGlassButton icon={<FileJson size={15} />} onClick={() => inspect('越权请求与签名核验信息', { source_kind: 'BFF_public_projection', ...attack.request })}>请求与签名</LiquidGlassButton>
            <LiquidGlassButton icon={<ArrowUpRight size={15} />} onClick={() => inspect('确定性安全验证完整记录', report)}>完整记录</LiquidGlassButton>
          </div>
          <div className="proof-control-result">
            <span>拒绝阶段</span><strong>{attack.refund_delta} 笔退款</strong>
            <span>合法对照</span><strong>{control ? `${control.refund_delta} 笔退款` : '未执行'}</strong>
          </div>
        </div>
        <div className="proof-verdict-column">
          <h3>{origin === 'current' ? '本次核验证据' : '已保存核验证据'}</h3>
          {checks.map((check, index) => <button className="proof-check-row" key={check.title}
            onClick={() => inspect(check.title, { evidence_type: 'direct_verification_or_observed_database_state', ...check })}>
            <span className="pipeline-index">{index + 1}</span><span><strong>{check.title}</strong><small>{check.source}</small></span>
            <StatusTag value={check.ok ? 'PASS' : 'FAIL'} /><ArrowUpRight size={14} />
          </button>)}
        </div>
      </div>
    </> : null}
    <Modal title="开始独立安全验证" open={confirmation} okText="确认验证" cancelText="取消"
      onCancel={() => setConfirmation(false)} onOk={() => void run()}>
      <p>本次创建独立任务。先提交越权请求，确认被拒绝且账本未变化后，再办理一笔授权范围内的退款对照。合法对照会写入业务账本。</p>
    </Modal>
  </div>
}
