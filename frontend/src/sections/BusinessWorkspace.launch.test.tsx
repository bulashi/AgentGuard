import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { App } from 'antd'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../api'
import type { RuntimeProfiles } from '../types'
import { BusinessWorkspace } from './BusinessWorkspace'

function profiles(cloudAvailable: boolean): RuntimeProfiles {
  return { workflow_enabled: true, items: [
    { mode: 'deterministic', label: '确定性规则', provider: 'rules', model: null,
      available: true, verification: 'local_rules', message: '不调用大模型' },
    { mode: 'cloud', label: '智能体审查', provider: 'deepseek', model: 'deepseek-flash',
      available: cloudAvailable, verification: cloudAvailable ? 'configured_not_invoked' : 'unavailable',
      message: cloudAvailable ? '配置满足' : '云端未配置' },
  ] }
}

function workspace() {
  render(<App><BusinessWorkspace snapshot={null} onInspect={vi.fn()}
    onStarted={vi.fn().mockResolvedValue(undefined)} onHistory={vi.fn()} /></App>)
}

beforeEach(() => {
  vi.spyOn(api, 'runtimeProfiles').mockResolvedValue(profiles(false))
  vi.spyOn(api, 'coauthorizationStatus').mockResolvedValue({ schema_version: '1.0', enabled: false,
    policy_source: 'SERVER_REGISTERED_PUBLIC_KEYS', signing: 'EXTERNAL_APPROVERS_ONLY' })
  vi.spyOn(api, 'startWorkflow')
})
afterEach(() => vi.restoreAllMocks())

describe('one-click launch planning selection', () => {
  it('selects deterministic rules on an unconfigured first launch without starting a task', async () => {
    workspace()
    await waitFor(() => expect(screen.getByRole('radio', { name: '确定性规则' })).toBeChecked())
    expect(screen.getByRole('radio', { name: '智能体审查' })).toBeDisabled()
    expect(screen.getByTestId('start-business-workflow')).toBeEnabled()
    expect(api.startWorkflow).not.toHaveBeenCalled()
  })

  it('selects cloud only when configuration is available and still waits for explicit execution', async () => {
    vi.mocked(api.runtimeProfiles).mockResolvedValue(profiles(true))
    workspace()
    await waitFor(() => expect(screen.getByRole('radio', { name: '智能体审查' })).toBeEnabled())
    expect(screen.getByRole('radio', { name: '智能体审查' })).toBeChecked()
    expect(api.startWorkflow).not.toHaveBeenCalled()
  })

  it('preserves the user selection after a configuration refresh', async () => {
    vi.mocked(api.runtimeProfiles).mockResolvedValue(profiles(true))
    workspace()
    await waitFor(() => expect(screen.getByRole('radio', { name: '确定性规则' })).toBeEnabled())
    fireEvent.click(screen.getByRole('radio', { name: '确定性规则' }))
    fireEvent.click(screen.getByRole('button', { name: '刷新运行与授权配置' }))
    await waitFor(() => expect(api.runtimeProfiles).toHaveBeenCalledTimes(2))
    expect(screen.getByRole('radio', { name: '确定性规则' })).toBeChecked()
    expect(api.startWorkflow).not.toHaveBeenCalled()
  })
})
