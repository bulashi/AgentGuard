import { describe, expect, it } from 'vitest'
import { ApiError } from './api'
import { modelConfigurationError, publicModelConfiguration, publicModelConfigurations, publicModelConnectionTest, validModelEndpoint } from './modelConfigurations'

const profile = { id: 'primary', name: '企业智能体', provider_id: 'provider', base_url: 'https://api.example.com/v1',
  api_mode: 'chat_completions', model: 'model-1', timeout_seconds: 120, enabled: true, has_key: true, is_default: true }

describe('public model configuration boundary', () => {
  it('keeps only public fields and never retains returned credentials', () => {
    expect(publicModelConfiguration({ ...profile, api_key: 'TEST_ONLY_SECRET', credential: 'TEST_ONLY_CIPHERTEXT' })).toEqual(profile)
    const result = publicModelConfigurations({ items: [{ ...profile, api_key: 'TEST_ONLY_SECRET' }], default_id: 'primary', supported_api_modes: ['chat_completions'] })
    expect(JSON.stringify(result)).not.toContain('TEST_ONLY_SECRET')
  })
  it.each([null, [], {}, { ...profile, has_key: 'true' }, { ...profile, timeout_seconds: true }, { ...profile, enabled: 1 }, { ...profile, model: '' }])(
    'rejects an invalid public configuration: %j', (value) => expect(() => publicModelConfiguration(value)).toThrow(),
  )
  it.each([
    { items: [profile, profile], default_id: 'primary', supported_api_modes: ['chat_completions'] },
    { items: [profile], default_id: 'missing', supported_api_modes: ['chat_completions'] },
    { items: [profile], default_id: null, supported_api_modes: ['chat_completions'] },
    { items: [], default_id: 'primary', supported_api_modes: ['chat_completions'] },
  ])('does not infer a valid default from an ambiguous list: %j', (value) => expect(() => publicModelConfigurations(value)).toThrow())
  it('accepts a genuinely empty public configuration list', () => {
    expect(publicModelConfigurations({ items: [], default_id: null, supported_api_modes: ['chat_completions'] }).items).toEqual([])
  })
  it('drops unrecognized protocols without claiming an adapter exists', () => {
    expect(publicModelConfigurations({ items: [profile], default_id: 'primary', supported_api_modes: ['chat_completions', 'unrecognized'] }).supported_api_modes).toEqual(['chat_completions'])
  })
  it.each(['https://api.example.com', 'https://api.example.com/v1', 'https://gateway.example.com:8443/v1'])('accepts public HTTPS syntax: %s', (url) => {
    expect(validModelEndpoint(url)).toBe(true)
  })
  it.each(['not-a-url', 'http://api.example.com/v1', 'https://user:password@api.example.com', 'https://api.example.com?api_key=TEST_ONLY',
    'https://api.example.com/#secret', 'http://127.0.0.1:1234/v1', 'https://localhost/v1', 'https://127.0.0.1/v1',
    'https://10.0.0.1/v1', 'https://192.168.1.1/v1', 'https://service.internal/v1', 'https://api.example.com/../v1', 'https://api.example.com/%2e%2e/v1'])('rejects unsafe endpoint syntax: %s', (url) => {
    expect(validModelEndpoint(url)).toBe(false)
  })
  it('does not surface transport or provider error messages containing request secrets', () => {
    const secret = 'TEST_ONLY_SECRET'
    expect(modelConfigurationError(new ApiError(500, 'UNEXPECTED_PROVIDER_ERROR', secret), '安全错误提示')).toBe('安全错误提示')
    expect(modelConfigurationError(new Error(secret), '安全错误提示')).toBe('安全错误提示')
  })
  it('localizes backend busy and credential-change rules', () => {
    expect(modelConfigurationError(new ApiError(409, 'MODEL_CONFIGURATION_BUSY', ''), '')).toContain('尚有任务未终结')
    expect(modelConfigurationError(new ApiError(400, 'MODEL_CREDENTIAL_CONFIRMATION_REQUIRED', ''), '')).toContain('旧密钥不会转发')
  })
  it('retains measured test metadata, not arbitrary response messages or credentials', () => {
    expect(publicModelConnectionTest({ status: 'PASS', model_requested: 'model-1', model_returned: 'model-1.1', duration_ms: 41,
      message: 'TEST_ONLY_SECRET', api_key: 'TEST_ONLY_SECRET' })).toEqual({ status: 'PASS', model_requested: 'model-1', model_returned: 'model-1.1', duration_ms: 41 })
  })
  it('accepts nullable typed response fields without turning a PASS into a failure', () => {
    expect(publicModelConnectionTest({ status: 'PASS', model_requested: 'model-1', model_returned: null,
      duration_ms: 10, reason_code: null, message: null })).toEqual({ status: 'PASS', model_requested: 'model-1', duration_ms: 10 })
    expect(publicModelConnectionTest({ status: 'FAIL', model_requested: null, model_returned: null,
      duration_ms: 0, reason_code: 'MODEL_MODE_UNAVAILABLE', message: null })).toEqual({
      status: 'FAIL', model_requested: null, duration_ms: 0, reason_code: 'MODEL_MODE_UNAVAILABLE',
    })
  })
  it.each([{ status: 'PASS', model_requested: 'model-1', duration_ms: -1 }, { status: 'PASS', model_requested: 'model-1', duration_ms: NaN },
    { status: 'UNKNOWN', model_requested: 'model-1' }, { status: 'PASS', model_requested: '' }])('rejects unverified connection results: %j', (value) => {
    expect(() => publicModelConnectionTest(value)).toThrow()
  })
})
