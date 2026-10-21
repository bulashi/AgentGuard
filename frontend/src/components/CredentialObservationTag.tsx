import { Tooltip } from 'antd'
import type { observeCredential } from '../credentialObservation'
import { StatusTag } from './Evidence'

export function CredentialObservationTag({ observation }: {
  observation: ReturnType<typeof observeCredential>
}) {
  return <Tooltip title={`${observation.detail}；基于最近读取的凭证投影和本机观测时间，不是网关准入结论`}>
    <span className="credential-observation-tag"><StatusTag value={observation.code} label={observation.label} /></span>
  </Tooltip>
}
