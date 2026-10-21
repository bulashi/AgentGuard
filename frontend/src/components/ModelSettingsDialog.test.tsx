import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { App } from 'antd'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { api, ApiError } from '../api'
import { runtimeProfiles } from '../test/fixtures'
import type { ModelConfiguration, ModelConfigurations } from '../types'
import { ModelSettingsDialog } from './ModelSettingsDialog'

const primary: ModelConfiguration = { id: 'primary', name: '企业服务 A', provider_id: 'provider-a', base_url: 'https://a.example.com/v1',
  api_mode: 'chat_completions', model: 'model-a', timeout_seconds: 120, enabled: true, has_key: true, is_default: true }
const secondary: ModelConfiguration = { ...primary, id: 'secondary', name: '企业服务 B', provider_id: 'provider-b',
  base_url: 'https://b.example.com/v1', model: 'model-b', is_default: false }
let current: ModelConfigurations

function dialog(props: Partial<Parameters<typeof ModelSettingsDialog>[0]> = {}) {
  const onRefresh = vi.fn(), onClose = vi.fn()
  const base = { open: true, initialMode: 'cloud' as const, profiles: runtimeProfiles, error: null, refreshing: false, onRefresh, onClose }
  const view = render(<App><ModelSettingsDialog {...base} {...props} /></App>)
  return { onRefresh, onClose, change: (next: Partial<typeof base>) => view.rerender(<App><ModelSettingsDialog {...base} {...props} {...next} /></App>) }
}

async function loaded() {
  await screen.findByDisplayValue(primary.name)
  await waitFor(() => expect(screen.getByRole('button', { name: '保存配置' })).toBeEnabled())
}

async function confirmation(title: string) {
  // rc-dialog's test environment reuses a title id; locate the actual dialog by its title.
  const heading = await screen.findByText(title, { exact: true })
  const element = heading.closest('[role="dialog"], [role="alertdialog"]')
  if (!(element instanceof HTMLElement)) throw new Error('Confirmation is not a dialog')
  return within(element)
}

beforeEach(() => {
  current = { items: [structuredClone(primary), structuredClone(secondary)], default_id: primary.id, supported_api_modes: ['chat_completions'] }
  vi.spyOn(api, 'modelConfigurations').mockImplementation(async () => structuredClone(current))
  vi.spyOn(api, 'saveModelConfiguration').mockImplementation(async (id, body) => {
    const old = current.items.find((item) => item.id === id)
    if (body.set_default || current.default_id === null) current.default_id = id
    const stored: ModelConfiguration = { id, name: body.name, provider_id: body.provider_id, base_url: body.base_url, api_mode: body.api_mode,
      model: body.model, timeout_seconds: body.timeout_seconds, enabled: body.enabled, has_key: Boolean(body.api_key || old?.has_key), is_default: id === current.default_id }
    current.items = [...current.items.filter((item) => item.id !== id), stored].map((item) => ({ ...item, is_default: item.id === current.default_id }))
    return stored
  })
  vi.spyOn(api, 'setDefaultModelConfiguration').mockImplementation(async (id) => {
    current.default_id = id
    current.items = current.items.map((item) => ({ ...item, is_default: item.id === id }))
    return { id }
  })
  vi.spyOn(api, 'deleteModelConfiguration').mockImplementation(async (id) => {
    current.items = current.items.filter((item) => item.id !== id)
    return { deleted: true, id }
  })
  vi.spyOn(api, 'testModelConfiguration').mockImplementation(async (id) => ({ status: 'PASS',
    model_requested: current.items.find((item) => item.id === id)!.model, model_returned: 'reported-model', duration_ms: 42 }))
})
afterEach(() => vi.restoreAllMocks())

describe('multi-provider configuration actions', () => {
  it('reads only when opened and does not infer connection verification from saved settings', async () => {
    const view = dialog({ open: false })
    expect(api.modelConfigurations).not.toHaveBeenCalled()
    view.change({ open: true })
    await loaded()
    expect(screen.getByLabelText('API 密钥')).toHaveValue('')
    expect(screen.queryByText('连接测试通过')).not.toBeInTheDocument()
    expect(api.testModelConfiguration).not.toHaveBeenCalled()
    expect(screen.getByRole('button', { name: '删除服务配置' })).toBeDisabled()
  })

  it('uses the supplied form layout but does not enable protocols without adapters', async () => {
    dialog()
    await loaded()
    for (const name of ['名称', '提供商 ID', '端点 URL', '模型 ID', '请求超时（秒）', 'API 密钥']) expect(screen.getByLabelText(name)).toBeInTheDocument()
    expect(screen.getByRole('radio', { name: 'Chat Completions' })).toBeEnabled()
    expect(screen.getByRole('radio', { name: 'Responses API · 未适配' })).toBeDisabled()
    expect(screen.getByRole('radio', { name: 'Anthropic Messages · 未适配' })).toBeDisabled()
    expect(screen.queryByText('自动检测')).not.toBeInTheDocument()
  })

  it('saves edited public fields while omitting an empty key and does not start a model call', async () => {
    const view = dialog()
    await loaded()
    fireEvent.change(screen.getByLabelText('名称'), { target: { value: '更新后的服务' } })
    fireEvent.click(screen.getByRole('button', { name: '保存配置' }))
    await waitFor(() => expect(api.saveModelConfiguration).toHaveBeenCalledWith(primary.id, {
      name: '更新后的服务', provider_id: primary.provider_id, base_url: primary.base_url, api_mode: primary.api_mode,
      model: primary.model, timeout_seconds: 120, enabled: true,
    }))
    expect(await screen.findByText(/配置已保存，尚未测试连接/)).toBeInTheDocument()
    expect(view.onRefresh).toHaveBeenCalledOnce()
    expect(api.testModelConfiguration).not.toHaveBeenCalled()
    expect(screen.getByLabelText('API 密钥')).toHaveValue('')
  })

  it('clears a submitted key immediately and never writes browser storage', async () => {
    const local = vi.spyOn(Storage.prototype, 'setItem')
    let finish!: (value: ModelConfiguration) => void
    vi.mocked(api.saveModelConfiguration).mockReturnValue(new Promise((resolve) => { finish = resolve }))
    dialog()
    await loaded()
    const secret = 'TEST_ONLY_NEW_KEY'
    fireEvent.change(screen.getByLabelText('API 密钥'), { target: { value: secret } })
    fireEvent.click(screen.getByRole('button', { name: '保存配置' }))
    await waitFor(() => expect(api.saveModelConfiguration).toHaveBeenCalledOnce())
    expect(screen.getByLabelText('API 密钥')).toHaveValue('')
    expect(document.body.textContent).not.toContain(secret)
    expect(local).not.toHaveBeenCalled()
    expect(screen.getByRole('button', { name: '关闭' })).toBeDisabled()
    await act(async () => finish(primary))
  })

  it('requires a fresh key before changing an endpoint or provider', async () => {
    dialog()
    await loaded()
    fireEvent.change(screen.getByLabelText('端点 URL'), { target: { value: 'https://new.example.com/v1' } })
    fireEvent.click(screen.getByRole('button', { name: '保存配置' }))
    expect(await screen.findByText('更换端点或提供商后请重新填写密钥')).toBeInTheDocument()
    expect(api.saveModelConfiguration).not.toHaveBeenCalled()
    expect(screen.getByRole('button', { name: '测试连接' })).toBeDisabled()
  })

  it('rejects nonpublic or credential-bearing endpoints before submitting', async () => {
    dialog()
    await loaded()
    fireEvent.change(screen.getByLabelText('端点 URL'), { target: { value: 'https://127.0.0.1/v1' } })
    fireEvent.change(screen.getByLabelText('API 密钥'), { target: { value: 'TEST_ONLY_KEY' } })
    fireEvent.click(screen.getByRole('button', { name: '保存配置' }))
    expect(await screen.findByText('使用公开 HTTPS 地址，不含凭据、查询参数、片段或本机地址')).toBeInTheDocument()
    expect(api.saveModelConfiguration).not.toHaveBeenCalled()
  })

  it('creates a new named provider using a separate configuration identity', async () => {
    dialog()
    await loaded()
    fireEvent.click(screen.getByRole('button', { name: '新增服务配置' }))
    fireEvent.change(screen.getByLabelText('名称'), { target: { value: '新增企业服务' } })
    fireEvent.change(screen.getByLabelText('提供商 ID'), { target: { value: 'enterprise.ai' } })
    fireEvent.change(screen.getByLabelText('端点 URL'), { target: { value: 'https://c.example.com/v1' } })
    fireEvent.change(screen.getByLabelText('模型 ID'), { target: { value: 'vendor/model-v2' } })
    fireEvent.change(screen.getByLabelText('API 密钥'), { target: { value: 'TEST_ONLY_NEW_KEY' } })
    fireEvent.click(screen.getByRole('button', { name: '保存配置' }))
    await waitFor(() => expect(api.saveModelConfiguration).toHaveBeenCalledOnce())
    const [id, body] = vi.mocked(api.saveModelConfiguration).mock.calls[0]
    expect(id).not.toBe(primary.id)
    expect(body).toMatchObject({ provider_id: 'enterprise.ai', model: 'vendor/model-v2', api_key: 'TEST_ONLY_NEW_KEY' })
    expect(await screen.findByDisplayValue('新增企业服务')).toBeInTheDocument()
    expect(screen.getByLabelText('API 密钥')).toHaveValue('')
  })

  it('supports a disabled draft with no API key without claiming it is runnable', async () => {
    dialog()
    await loaded()
    fireEvent.click(screen.getByRole('button', { name: '新增服务配置' }))
    fireEvent.change(screen.getByLabelText('名称'), { target: { value: '待启用服务' } })
    fireEvent.change(screen.getByLabelText('提供商 ID'), { target: { value: 'draft-provider' } })
    fireEvent.change(screen.getByLabelText('端点 URL'), { target: { value: 'https://draft.example.com/v1' } })
    fireEvent.change(screen.getByLabelText('模型 ID'), { target: { value: 'model-draft' } })
    fireEvent.click(screen.getByRole('checkbox', { name: '启用服务' }))
    fireEvent.click(screen.getByRole('button', { name: '保存配置' }))
    await waitFor(() => expect(api.saveModelConfiguration).toHaveBeenCalledOnce())
    expect(vi.mocked(api.saveModelConfiguration).mock.calls[0][1]).toMatchObject({ enabled: false })
    expect(vi.mocked(api.saveModelConfiguration).mock.calls[0][1]).not.toHaveProperty('api_key')
    expect(screen.getByRole('button', { name: '测试连接' })).toBeDisabled()
  })

  it('requires separate cost confirmation for a connection test', async () => {
    dialog()
    await loaded()
    fireEvent.click(screen.getByRole('button', { name: '测试连接' }))
    const confirm = await confirmation('确认连接测试')
    expect(confirm.getByRole('button', { name: '确认并测试' })).toBeDisabled()
    expect(api.testModelConfiguration).not.toHaveBeenCalled()
    fireEvent.click(confirm.getByRole('checkbox'))
    fireEvent.click(confirm.getByRole('button', { name: '确认并测试' }))
    expect(await screen.findByText('连接测试通过')).toBeInTheDocument()
    expect(screen.getByRole('region', { name: '连接测试结果' })).toHaveTextContent('model-a')
    expect(screen.getByRole('region', { name: '连接测试结果' })).toHaveTextContent('reported-model')
    expect(api.testModelConfiguration).toHaveBeenCalledExactlyOnceWith(primary.id)
    expect(api.saveModelConfiguration).not.toHaveBeenCalled()
  })

  it('canceling a connection test neither calls a provider nor saves a configuration', async () => {
    dialog()
    await loaded()
    fireEvent.click(screen.getByRole('button', { name: '测试连接' }))
    fireEvent.click((await confirmation('确认连接测试')).getByRole('button', { name: /^取\s*消$/ }))
    expect(api.testModelConfiguration).not.toHaveBeenCalled()
    expect(api.saveModelConfiguration).not.toHaveBeenCalled()
  })

  it('displays typed nullable PASS and FAIL test results without inventing model metadata', async () => {
    vi.mocked(api.testModelConfiguration).mockResolvedValueOnce({ status: 'PASS', model_requested: primary.model,
      model_returned: null, duration_ms: 4, reason_code: null, message: null })
      .mockResolvedValueOnce({ status: 'FAIL', model_requested: null, model_returned: null,
        duration_ms: 0, reason_code: 'MODEL_MODE_UNAVAILABLE', message: null })
    dialog()
    await loaded()
    for (const status of ['连接测试通过', '连接测试未通过']) {
      fireEvent.click(screen.getByRole('button', { name: '测试连接' }))
      const confirm = await confirmation('确认连接测试')
      fireEvent.click(confirm.getByRole('checkbox'))
      fireEvent.click(confirm.getByRole('button', { name: '确认并测试' }))
      expect(await screen.findByText(status)).toBeInTheDocument()
      await waitFor(() => expect(screen.getByRole('button', { name: '测试连接' })).toBeEnabled())
    }
    expect(screen.getByRole('region', { name: '连接测试结果' })).toHaveTextContent('未返回请求型号')
    expect(screen.queryByText(/连接测试结果未确认/)).not.toBeInTheDocument()
  })

  it('clears old test results when fields change and does not test unsaved fields', async () => {
    dialog()
    await loaded()
    fireEvent.click(screen.getByRole('button', { name: '测试连接' }))
    const confirm = await confirmation('确认连接测试')
    fireEvent.click(confirm.getByRole('checkbox'))
    fireEvent.click(confirm.getByRole('button', { name: '确认并测试' }))
    await screen.findByText('连接测试通过')
    fireEvent.change(screen.getByLabelText('模型 ID'), { target: { value: 'different-model' } })
    expect(screen.queryByText('连接测试通过')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: '测试连接' })).toBeDisabled()
  })

  it('changes the default only through the dedicated mutation and server readback', async () => {
    dialog()
    await loaded()
    fireEvent.click(screen.getByRole('button', { name: /企业服务 B.*model-b/ }))
    fireEvent.click(screen.getByRole('button', { name: '设为默认' }))
    expect(await screen.findByText('默认服务已更新，仅作用于后续任务。')).toBeInTheDocument()
    expect(api.setDefaultModelConfiguration).toHaveBeenCalledExactlyOnceWith(secondary.id)
    expect(api.testModelConfiguration).not.toHaveBeenCalled()
    expect(screen.getByRole('button', { name: '删除服务配置' })).toBeDisabled()
  })

  it('does not report a default change as verified when readback fails', async () => {
    vi.mocked(api.modelConfigurations).mockResolvedValueOnce(current).mockRejectedValueOnce(new Error('read failed'))
    dialog()
    await loaded()
    fireEvent.click(screen.getByRole('button', { name: /企业服务 B.*model-b/ }))
    fireEvent.click(screen.getByRole('button', { name: '设为默认' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('配置读取失败')
    expect(screen.queryByText('默认服务已更新，仅作用于后续任务。')).not.toBeInTheDocument()
  })

  it('locks writes while a known task is in flight and keeps the current task untouched', async () => {
    dialog({ workInFlight: true })
    await screen.findByDisplayValue(primary.name)
    fireEvent.click(screen.getByRole('button', { name: /企业服务 B.*model-b/ }))
    expect(screen.getByRole('button', { name: '保存配置' })).toBeDisabled()
    expect(screen.getByRole('button', { name: '设为默认' })).toBeDisabled()
    expect(screen.getByRole('button', { name: '删除服务配置' })).toBeDisabled()
    expect(screen.getByRole('status')).toHaveTextContent('有任务尚未终结')
    expect(api.saveModelConfiguration).not.toHaveBeenCalled()
  })

  it('shows safe backend failures and requires refreshing before another mutation', async () => {
    vi.mocked(api.saveModelConfiguration).mockRejectedValueOnce(new ApiError(409, 'MODEL_CONFIGURATION_BUSY', 'TEST_ONLY_SECRET'))
    dialog()
    await loaded()
    fireEvent.click(screen.getByRole('button', { name: '保存配置' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('尚有任务未终结')
    expect(document.body.textContent).not.toContain('TEST_ONLY_SECRET')
    expect(screen.getByRole('button', { name: '保存配置' })).toBeDisabled()
    expect(screen.getByRole('button', { name: '刷新配置' })).toBeEnabled()
    fireEvent.click(screen.getByRole('button', { name: '刷新配置' }))
    await loaded()
    expect(api.saveModelConfiguration).toHaveBeenCalledOnce()
  })

  it('deletes only a non-default configuration after explicit confirmation', async () => {
    dialog()
    await loaded()
    fireEvent.click(screen.getByRole('button', { name: /企业服务 B.*model-b/ }))
    fireEvent.click(screen.getByRole('button', { name: '删除服务配置' }))
    expect(api.deleteModelConfiguration).not.toHaveBeenCalled()
    const confirm = await confirmation('删除配置“企业服务 B”？')
    fireEvent.click(confirm.getByRole('button', { name: '删除配置' }))
    expect(await screen.findByText('配置已删除，已有任务记录不变。')).toBeInTheDocument()
    expect(api.deleteModelConfiguration).toHaveBeenCalledExactlyOnceWith(secondary.id)
  })

  it('clears key input on close and on a confirmed profile switch', async () => {
    const view = dialog()
    await loaded()
    fireEvent.change(screen.getByLabelText('API 密钥'), { target: { value: 'TEST_ONLY_SECRET' } })
    fireEvent.click(screen.getByRole('button', { name: /企业服务 B.*model-b/ }))
    const confirm = await confirmation('放弃未保存的配置？')
    fireEvent.click(confirm.getByRole('button', { name: '放弃并切换' }))
    expect(await screen.findByDisplayValue(secondary.name)).toBeInTheDocument()
    expect(screen.getByLabelText('API 密钥')).toHaveValue('')
    fireEvent.change(screen.getByLabelText('API 密钥'), { target: { value: 'TEST_ONLY_SECRET' } })
    fireEvent.click(screen.getByRole('button', { name: '关闭' }))
    expect(view.onClose).toHaveBeenCalledOnce()
    expect(screen.getByLabelText('API 密钥')).toHaveValue('')
  })

  it('does not preserve a stale successful list after a failed refresh', async () => {
    vi.mocked(api.modelConfigurations).mockResolvedValueOnce(current).mockRejectedValueOnce(new Error('unavailable'))
    dialog()
    await loaded()
    fireEvent.click(screen.getByRole('button', { name: '刷新配置' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('配置读取失败')
    expect(screen.queryByText('密钥已保存')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: '保存配置' })).toBeDisabled()
    expect(screen.queryByText('尚无模型服务')).not.toBeInTheDocument()
  })

  it('ignores earlier read responses after closing and reopening', async () => {
    let finish!: (value: ModelConfigurations) => void
    const pending = new Promise<ModelConfigurations>((resolve) => { finish = resolve })
    vi.mocked(api.modelConfigurations).mockReturnValueOnce(pending).mockResolvedValueOnce({ ...current, items: [secondary], default_id: null })
    const view = dialog()
    await waitFor(() => expect(api.modelConfigurations).toHaveBeenCalledOnce())
    view.change({ open: false })
    view.change({ open: true })
    await screen.findByDisplayValue(secondary.name)
    await act(async () => { finish(current); await pending })
    expect(screen.queryByDisplayValue(primary.name)).not.toBeInTheDocument()
  })
})
