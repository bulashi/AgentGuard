import { Tag, Tooltip, Typography } from 'antd'
import { fenToYuan } from '../money'
import { statusLabel } from '../labels'

const { Text } = Typography

export function StatusTag({ value, label }: { value: string | null | undefined; label?: string }) {
  const raw = value ?? 'NONE'
  const text = label ?? statusLabel(raw)
  const color =
    raw === 'ALLOW' || raw === 'COMPLETED' || raw === 'COMMITTED' || raw === 'VALID' || raw === 'VERIFIED' || raw === 'PASS' || raw === 'ANCHORED'
      ? 'green'
      : raw === 'DENY' || raw === 'DENIED' || raw === 'INVALID' || raw === 'FAILED' || raw === 'FAIL' || raw === 'MISSING' || raw === 'INTERRUPTED'
        || raw === 'SIGNATURE_INVALID' || raw === 'SOURCE_BINDING_INVALID' || raw === 'PARENT_LINK_INVALID'
        ? 'red'
      : raw === 'AUTHORIZED' || raw === 'SIGNED' || raw === 'AVAILABLE' || raw === 'RUNNING' || raw === 'WINDOW_OPEN'
          ? 'blue'
      : raw === 'INFERRED_PASS' || raw === 'CHECK' || raw === 'NOT_REACHED' || raw === 'PENDING_PHASE_17'
        || raw === 'EXPIRED' || raw === 'NOT_YET_VALID' || raw === 'REVOKED' || raw === 'ANCESTOR_REVOKED' || raw === 'INCOMPLETE'
        || raw === 'BUSINESS_STOPPED' || raw === 'STOPPED' || raw === 'UNKNOWN' || raw === 'RECONCILING' || raw === 'RECOVERY_FAILED_FINAL'
            ? 'orange'
            : 'default'
  return <Tag color={color} title={raw} aria-label={`${text}（${raw}）`}>{text}</Tag>
}

export function BooleanTag({ value }: { value: boolean }) {
  return <StatusTag value={value === true ? 'VALID' : 'INVALID'} />
}

export function ShortHash({ value, size = 12, copyable = true }: { value?: string | null; size?: number; copyable?: boolean }) {
  if (!value) return <Text type="secondary">无</Text>
  const short = value.length <= size * 2 + 1 ? value : `${value.slice(0, size)}…${value.slice(-size)}`
  return (
    <Tooltip title={value} placement="topLeft">
      <Text
        aria-label={value}
        className="mono hash-value"
        copyable={copyable ? { text: value } : false}
        title={value}
      >
        {short}
      </Text>
    </Tooltip>
  )
}

export function Fen({ value }: { value: number }) {
  return <span className="mono">¥ {fenToYuan(value)} 元</span>
}

export function TimeValue({ value }: { value?: number | null }) {
  if (value === null || value === undefined || !Number.isFinite(value)) return <Text type="secondary">无</Text>
  return <span className="mono">{new Date(value * 1000).toLocaleString('zh-CN', { hour12: false })}</span>
}
