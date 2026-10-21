import { useEffect, useRef, useState } from 'react'
import { Descriptions, Modal, Tag, Tooltip } from 'antd'
import { ArrowDown, Building2, CircleAlert, RefreshCw, ShieldCheck, UsersRound, Wallet } from 'lucide-react'
import { api } from '../api'
import type { CoauthorizationStatus } from '../types'
import { LiquidGlassButton } from './LiquidGlassButton'
import '../coauthorization.css'

export function CoauthorizationStatusDialog() {
  const [open, setOpen] = useState(false)
  const [status, setStatus] = useState<CoauthorizationStatus | null>(null)
  const [busy, setBusy] = useState(false)
  const [failed, setFailed] = useState(false)
  const sequence = useRef(0)

  useEffect(() => () => { sequence.current += 1 }, [])

  const read = async () => {
    const request = ++sequence.current
    setBusy(true)
    setStatus(null)
    setFailed(false)
    try {
      const result = await api.coauthorizationStatus()
      if (sequence.current === request) setStatus(result)
    } catch {
      if (sequence.current === request) setFailed(true)
    } finally {
      if (sequence.current === request) setBusy(false)
    }
  }

  const close = () => {
    sequence.current += 1
    setOpen(false)
    setBusy(false)
    setStatus(null)
    setFailed(false)
  }

  return <>
    <LiquidGlassButton icon={<UsersRound size={15} />} onClick={() => { setOpen(true); void read() }}>
      共同授权状态
    </LiquidGlassButton>
    <Modal open={open} onCancel={close} title={<span className="coauth-dialog-title"><UsersRound size={17} />独立主体共同授权</span>}
      width={640} className="coauth-status-dialog" destroyOnHidden
      footer={<LiquidGlassButton aria-label="关闭" onClick={close}>关闭</LiquidGlassButton>}>
      <div className="coauth-config-heading">
        <span>Authority 当前配置</span>
        <Tag color={failed ? 'red' : status?.enabled ? 'orange' : 'default'}>
          {busy ? '读取中' : failed ? '无法读取' : status ? status.enabled ? '要求两方审批' : '未启用' : '未读取'}
        </Tag>
        <Tooltip title="重新读取 Authority 配置">
          <LiquidGlassButton icon={<RefreshCw size={14} />} aria-label="刷新共同授权状态"
            onClick={() => void read()} loading={busy} />
        </Tooltip>
      </div>
      {failed ? <div role="alert" className="coauth-read-error"><CircleAlert size={16} />配置读取失败，未判定为关闭或已审批。</div> : null}
      <div className="coauth-role-map" aria-label="共同授权职责关系">
        <div className="coauth-role-pair">
          <div><Building2 size={21} /><strong>企业审批</strong><span>外部独立签名主体</span></div>
          <div><Wallet size={21} /><strong>财务审批</strong><span>外部独立签名主体</span></div>
        </div>
        <div className="coauth-map-junction"><ArrowDown size={17} /><span>同一任务约束摘要</span></div>
        <div className="coauth-authority"><ShieldCheck size={20} /><strong>授权签发方</strong><span>校验两方证据后签发根授权</span></div>
      </div>
      <Descriptions size="small" column={1} className="coauth-config-details" items={[
        { key: 'switch', label: '旧单签入口', children: status ? status.enabled ? '强制拒绝' : '保留基础模式' : '未读取' },
        { key: 'keys', label: '公钥来源', children: status ? '服务端受信登记' : '未读取' },
        { key: 'signers', label: '签名位置', children: status ? '企业与财务各自在服务外签名' : '未读取' },
        { key: 'approval', label: '当前任务审批', children: '本入口未查询审批记录' },
        { key: 'identity', label: '独立身份与托管', children: '未在本入口验证' },
      ]} />
      <div className="coauth-config-boundary"><CircleAlert size={14} /><span>配置状态不是审批结果；当前入口不签名、不授权、不运行任务。</span></div>
    </Modal>
  </>
}
