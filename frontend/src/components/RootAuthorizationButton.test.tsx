import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { api, ApiError } from '../api'
import type { CoauthorizationStatus, TaskSummary } from '../types'
import { RootAuthorizationButton } from './RootAuthorizationButton'

const task: TaskSummary = {
  task_id: 'TASK-root-ui', tenant_id: '验收企业', ticket_id: 'T-ui-root', customer_id: '张三',
  refund_total_fen: 7000, max_tool_calls: 4, expires_at: 2_000_000_000,
  status: 'PENDING_AUTHORIZATION', created_at: 1, updated_at: 1, credential_count: 0, execution_count: 0,
}
const policy: CoauthorizationStatus = {
  schema_version: '1.0', enabled: false, policy_source: 'SERVER_REGISTERED_PUBLIC_KEYS', signing: 'EXTERNAL_APPROVERS_ONLY',
}
async function open() {
  fireEvent.click(screen.getByRole('button', { name: '查看并授权当前任务' }))
  await waitFor(() => expect(screen.queryByText('正在核对服务端授权策略')).not.toBeInTheDocument())
}

describe('RootAuthorizationButton', () => {
  it('confirms exact task without running tools or accepting implicit confirmation', async () => {
    const status = vi.spyOn(api, 'coauthorizationStatus').mockResolvedValue(policy)
    const authorize = vi.spyOn(api, 'authorizeTask').mockResolvedValue({ credential_id: 'ROOT-test' })
    const changed = vi.fn().mockResolvedValue(undefined)
    try {
      render(<RootAuthorizationButton task={task} onChanged={changed} />)
      await open()
      expect(screen.getByText('验收企业')).toBeInTheDocument()
      expect(screen.getByText('张三')).toBeInTheDocument()
      expect(screen.getByRole('button', { name: '确认签发根授权' })).toBeDisabled()
      fireEvent.click(screen.getByRole('checkbox'))
      fireEvent.click(screen.getByRole('button', { name: '确认签发根授权' }))
      await waitFor(() => expect(changed).toHaveBeenCalledWith(task.task_id))
      expect(authorize).toHaveBeenCalledExactlyOnceWith(task.task_id, {
        confirmed: true, confirmer_id: 'policy-refund-v1', holder_agent_id: 'agent-coordinator',
        holder_key_id: 'agent-coordinator-key-01', delegation_depth: 2,
      })
    } finally { status.mockRestore(); authorize.mockRestore() }
  })
  it('cannot bypass required joint approval', async () => {
    const status = vi.spyOn(api, 'coauthorizationStatus').mockResolvedValue({ ...policy, enabled: true })
    const authorize = vi.spyOn(api, 'authorizeTask')
    try {
      render(<RootAuthorizationButton task={task} onChanged={vi.fn()} />)
      await open()
      expect(screen.getByText('本任务要求企业与财务共同授权')).toBeInTheDocument()
      expect(screen.getByRole('checkbox')).toBeDisabled()
      expect(screen.getByRole('button', { name: '确认签发根授权' })).toBeDisabled()
      expect(authorize).not.toHaveBeenCalled()
    } finally { status.mockRestore(); authorize.mockRestore() }
  })
  it.each(['failed', 'malformed'])('fails closed for %s policy', async (condition) => {
    const status = vi.spyOn(api, 'coauthorizationStatus')
    if (condition === 'failed') status.mockRejectedValue(new Error('transport'))
    else status.mockResolvedValue({ ...policy, enabled: undefined } as unknown as CoauthorizationStatus)
    try {
      render(<RootAuthorizationButton task={task} onChanged={vi.fn()} />)
      await open()
      expect(screen.getByText('授权策略读取失败，不能签发；请刷新重试。')).toBeInTheDocument()
      expect(screen.getByRole('checkbox')).toBeDisabled()
    } finally { status.mockRestore() }
  })
  it('does not issue on cancel', async () => {
    const status = vi.spyOn(api, 'coauthorizationStatus').mockResolvedValue(policy)
    const authorize = vi.spyOn(api, 'authorizeTask')
    try {
      render(<RootAuthorizationButton task={task} onChanged={vi.fn()} />)
      await open()
      fireEvent.click(screen.getByRole('button', { name: '取消' }))
      expect(authorize).not.toHaveBeenCalled()
    } finally { status.mockRestore(); authorize.mockRestore() }
  })
  it.each(['expired', 'authorized', 'no-refresh'])('prevents %s task signing', async (condition) => {
    const status = vi.spyOn(api, 'coauthorizationStatus').mockResolvedValue(policy)
    try {
      render(<RootAuthorizationButton task={{ ...task, ...(condition === 'expired' ? { expires_at: 1 }
        : condition === 'authorized' ? { status: 'AUTHORIZED' } : {}) }} onChanged={condition === 'no-refresh' ? undefined : vi.fn()} />)
      if (condition === 'expired') {
        await open()
        expect(screen.getByRole('checkbox')).toBeDisabled()
      } else expect(screen.getByRole('button', { name: '查看并授权当前任务' })).toBeDisabled()
    } finally { status.mockRestore() }
  })
  it('does not repeat an uncertain signing request', async () => {
    const status = vi.spyOn(api, 'coauthorizationStatus').mockResolvedValue(policy)
    const authorize = vi.spyOn(api, 'authorizeTask').mockRejectedValue(new ApiError(503, 'HTTP_ERROR', 'unavailable'))
    try {
      render(<RootAuthorizationButton task={task} onChanged={vi.fn()} />)
      await open()
      fireEvent.click(screen.getByRole('checkbox'))
      fireEvent.click(screen.getByRole('button', { name: '确认签发根授权' }))
      expect(await screen.findByText('签发结果未确认；请刷新任务核对，不自动重试。')).toBeInTheDocument()
      expect(screen.getByRole('checkbox')).toBeDisabled()
      expect(authorize).toHaveBeenCalledOnce()
    } finally { status.mockRestore(); authorize.mockRestore() }
  })
})
