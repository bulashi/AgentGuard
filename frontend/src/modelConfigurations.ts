import { ApiError } from './api'
import type { ModelConfiguration, ModelConfigurations, ModelConnectionTest } from './types'

function record(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid configuration response')
  return value as Record<string, unknown>
}

function requiredText(value: unknown): string {
  if (typeof value !== 'string' || !value.trim()) throw new Error('Invalid configuration response')
  return value
}

export function publicModelConfiguration(value: unknown): ModelConfiguration {
  const row = record(value)
  if (!['chat_completions', 'responses', 'anthropic_messages'].includes(String(row.api_mode))
    || !Number.isSafeInteger(row.timeout_seconds) || Number(row.timeout_seconds) <= 0
    || typeof row.enabled !== 'boolean' || typeof row.has_key !== 'boolean' || typeof row.is_default !== 'boolean') {
    throw new Error('Invalid configuration response')
  }
  // Keep only public fields, even if a server accidentally returns extra values.
  return {
    id: requiredText(row.id), name: requiredText(row.name), provider_id: requiredText(row.provider_id),
    base_url: requiredText(row.base_url), api_mode: row.api_mode as ModelConfiguration['api_mode'],
    model: requiredText(row.model), timeout_seconds: Number(row.timeout_seconds), enabled: row.enabled,
    has_key: row.has_key, is_default: row.is_default,
  }
}

export function publicModelConfigurations(value: unknown): ModelConfigurations {
  const data = record(value)
  if (!Array.isArray(data.items) || !Array.isArray(data.supported_api_modes)
    || data.default_id !== null && typeof data.default_id !== 'string') throw new Error('Invalid configuration response')
  const items = data.items.map(publicModelConfiguration)
  if (new Set(items.map((item) => item.id)).size !== items.length
    || items.some((item) => item.is_default !== (item.id === data.default_id))
    || data.default_id !== null && !items.some((item) => item.id === data.default_id)) {
    throw new Error('Invalid configuration response')
  }
  return {
    items, default_id: data.default_id as string | null,
    supported_api_modes: data.supported_api_modes.filter((mode): mode is ModelConfiguration['api_mode'] =>
      typeof mode === 'string' && ['chat_completions', 'responses', 'anthropic_messages'].includes(mode)),
  }
}

export function validModelEndpoint(value: string): boolean {
  try {
    const url = new URL(value)
    const host = url.hostname.toLowerCase()
    const octets = /^\d+\.\d+\.\d+\.\d+$/.test(host) ? host.split('.').map(Number) : null
    const privateHost = host === 'localhost' || /\.(localhost|local|internal)$/.test(host)
      || host.startsWith('[') || octets && (octets[0] === 0 || octets[0] === 10 || octets[0] === 127 || octets[0] >= 224
        || octets[0] === 169 && octets[1] === 254 || octets[0] === 192 && octets[1] === 168
        || octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31 || octets[0] === 100 && octets[1] >= 64 && octets[1] <= 127)
    return url.protocol === 'https:' && !privateHost && host.includes('.') && /^[a-z0-9.-]+$/.test(host)
      && !url.username && !url.password && !url.search && !url.hash && !/[\s\\]/.test(value)
      && !/%|(?:^|\/)\.\.(?:\/|$)/.test(value.slice(value.indexOf('://') + 3))
  } catch { return false }
}

export function publicModelConnectionTest(value: unknown): ModelConnectionTest {
  const row = record(value)
  if (!['PASS', 'FAIL'].includes(String(row.status))
    || row.model_requested !== null && (typeof row.model_requested !== 'string' || !row.model_requested.trim())
    || row.duration_ms !== undefined && row.duration_ms !== null && (typeof row.duration_ms !== 'number' || !Number.isFinite(row.duration_ms) || row.duration_ms < 0)) {
    throw new Error('Invalid test response')
  }
  return {
    status: row.status as ModelConnectionTest['status'], model_requested: row.model_requested as string | null,
    ...(typeof row.model_returned === 'string' ? { model_returned: row.model_returned } : {}),
    ...(typeof row.duration_ms === 'number' ? { duration_ms: row.duration_ms } : {}),
    ...(typeof row.reason_code === 'string' && /^[A-Z0-9_]{1,80}$/.test(row.reason_code) ? { reason_code: row.reason_code } : {}),
  }
}

export function modelConfigurationError(error: unknown, fallback: string): string {
  // Provider and transport errors can contain credential-bearing request data.
  if (!(error instanceof ApiError)) return fallback
  const messages: Record<string, string> = {
    MODEL_CONFIGURATION_IN_USE: '有任务正在使用模型配置，不能切换或删除；请等待任务结束。',
    WORKFLOW_IN_PROGRESS: '有任务正在执行，当前默认服务保持不变。',
    DEFAULT_CONFIGURATION_IN_USE: '默认配置不能删除，请先切换默认服务。',
    MODEL_CONFIGURATION_NOT_FOUND: '该配置已不存在，请刷新配置列表。',
    MODEL_API_MODE_UNSUPPORTED: '当前版本没有此 API 协议的适配器。',
    MODEL_CONFIG_API_MODE_UNSUPPORTED: '当前版本没有此 API 协议的适配器。',
    MODEL_KEY_REQUIRED: '请为此配置填写 API 密钥。',
    MODEL_CONFIGURATION_DISABLED: '该服务尚未启用。',
    MODEL_TEST_FAILED: '连接测试未通过，请核对端点、型号和密钥。',
    MODEL_CONFIGURATIONS_UNAVAILABLE: '模型配置服务暂不可用。',
    MODEL_CONFIGURATION_UNAVAILABLE: '当前启动环境未启用模型配置管理，请检查服务版本。',
    MODEL_CONFIGURATION_BUSY: '尚有任务未终结，配置未修改；请等待任务完成或对账结束。',
    MODEL_CONFIGURATION_IS_DEFAULT: '默认配置不能删除，请先切换默认服务。',
    MODEL_CREDENTIAL_REQUIRED: '启用服务前请填写 API 密钥。',
    MODEL_CREDENTIAL_CONFIRMATION_REQUIRED: '更换端点或提供商后须重新填写密钥；旧密钥不会转发。',
    MODEL_MODE_UNAVAILABLE: '该服务尚未启用，或密钥尚未配置。',
    MODEL_CONFIGURATION_LIMIT: '最多保存 32 个服务配置，请先删除不再使用的配置。',
    MODEL_ENDPOINT_INVALID: '使用公开 HTTPS 服务地址，不得包含凭据、查询参数或本机地址。',
    MODEL_ENDPOINT_UNREACHABLE: '端点未解析为公开网络地址，请检查域名与网络。',
    MODEL_CONFIGURATION_ORIGIN_DENIED: '配置变更必须从本机控制台的同源页面提交。',
    CLOUD_CONFIRMATION_REQUIRED: '请先确认本次连接测试及可能产生的费用。',
  }
  return messages[error.reasonCode] ?? (error.status === 409 ? '服务端拒绝了此配置变更；请刷新并检查在途任务。'
    : error.status === 404 ? '当前服务未提供该配置接口，请检查服务版本。'
      : error.status === 422 ? '配置字段未通过校验，请核对端点、型号及超时设置。' : fallback)
}
