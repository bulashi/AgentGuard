async (page) => {
  const origin = new URL(page.url()).origin
  const checks = [], errors = [], cleanupFailures = []
  const assert = (condition, name) => { checks.push({ name, passed: Boolean(condition) }); if (!condition) throw new Error(name) }
  page.setDefaultTimeout(20000)
  page.on('pageerror', error => errors.push(error.message))
  const initial = await (await page.request.get(`${origin}/api/model-configurations`)).json()
  const primary = initial.items.find(item => item.id === initial.default_id)
  const catalog = await (await page.request.get(`${origin}/api/business/tickets`)).json()
  const business = catalog.items.find(item => item.tenant_id === '验收企业' && item.customer_id === '张三' && item.can_refund)
  let failure = null, taskId = null, addedId = null, restorePrimary = false
  const configHeader = { 'X-AgentGuard-Configuration': '1' }
  const bodyFor = item => ({ name: item.name, provider_id: item.provider_id, base_url: item.base_url,
    api_mode: item.api_mode, model: item.model, timeout_seconds: item.timeout_seconds, enabled: item.enabled })
  const latestConfigurations = async () => (await (await page.request.get(`${origin}/api/model-configurations`)).json())
  const waitConfigurations = async predicate => {
    const deadline = Date.now() + 20000
    while (Date.now() < deadline) {
      const value = await latestConfigurations()
      if (predicate(value)) return value
      await page.waitForTimeout(200)
    }
    throw new Error('model configuration state did not settle')
  }
  const saveConfiguration = async models => {
    const response = page.waitForResponse(item => item.request().method() === 'PUT' && new URL(item.url()).pathname.startsWith('/api/model-configurations/'))
    await models.getByRole('button', { name: '保存配置', exact: true }).click()
    const stored = await response
    assert(stored.ok(), `model configuration save HTTP ${stored.status()}`)
    await models.getByText('配置已保存，尚未测试连接；实际调用结果以运行记录为准。', { exact: true }).waitFor()
    await models.getByRole('button', { name: '新增服务配置', exact: true }).waitFor({ state: 'visible' })
    return await stored.json()
  }
  try {
    assert(Boolean(primary?.has_key), 'existing primary configuration has a protected key')
    assert(Boolean(business), 'fresh Chinese trusted business case exists')
    await page.goto(`${origin}/${new URL(page.url()).search}#overview`)
    await page.getByTestId('task-overview').waitFor()
    await page.setViewportSize({ width: 1440, height: 1000 })
    await page.getByRole('button', { name: '配置模型服务', exact: true }).click()
    const models = page.getByRole('dialog', { name: '智能体运行配置' })
    await models.getByRole('tab', { name: '智能体审查' }).click()
    const name = models.getByLabel('名称', { exact: true })
    await name.fill(primary.name + ' · 验收')
    assert(await models.getByLabel('API 密钥', { exact: true }).inputValue() === '', 'blank key is not read back')
    restorePrimary = true
    await saveConfiguration(models)
    const saved = (await latestConfigurations()).items.find(item => item.id === primary.id)
    assert(saved.has_key && saved.name.endsWith(' · 验收'), 'blank-key save retains configured key')
    await name.fill(primary.name)
    await saveConfiguration(models)
    await waitConfigurations(value => !value.items.some(item => item.name.endsWith(' · 验收')))
    restorePrimary = false
    await models.getByRole('button', { name: '新增服务配置', exact: true }).click()
    await name.fill('验收接口（停用）')
    await models.getByLabel('提供商 ID', { exact: true }).fill('acceptance-disabled')
    await models.getByLabel('端点 URL', { exact: true }).fill('https://example.com/v1')
    await models.getByLabel('模型 ID', { exact: true }).fill('acceptance-model')
    await models.getByRole('checkbox', { name: '启用服务', exact: true }).uncheck()
    const stored = await saveConfiguration(models)
    const added = (await waitConfigurations(value => value.items.some(item => item.id === stored.id))).items.find(item => item.id === stored.id)
    addedId = added.id
    assert(added.enabled === false && added.has_key === false, 'disabled provider can be saved without a key or network call')
    assert(await models.getByRole('button', { name: '设为默认', exact: true }).isDisabled(), 'disabled provider cannot become default')
    assert(await models.getByRole('button', { name: '测试连接', exact: true }).isDisabled(), 'disabled provider cannot send a model request')
    await page.screenshot({ path: 'F:/AgentGuardCompetition/AgentGuard/output/playwright/formal-studio/model-configurations.png', fullPage: true })
    await models.getByRole('button', { name: '删除服务配置', exact: true }).click()
    await page.getByRole('button', { name: '删除配置', exact: true }).click()
    await waitConfigurations(value => !value.items.some(item => item.id === addedId))
    assert(!(await latestConfigurations()).items.some(item => item.id === addedId), 'non-default profile is actually deleted')
    addedId = null
    await models.getByRole('button', { name: '关闭', exact: true }).click()
    await models.waitFor({ state: 'hidden' })
    await page.getByTestId('nav-overview').click()
    await page.getByRole('button', { name: '新建任务', exact: true }).click()
    const create = page.getByRole('dialog', { name: '新建业务任务' })
    await create.getByLabel('租户', { exact: true }).fill(business.tenant_id)
    await create.getByLabel('工单编号', { exact: true }).fill(business.ticket_id)
    await create.getByLabel('客户', { exact: true }).fill(business.customer_id)
    const created = page.waitForResponse(response => response.request().method() === 'POST' && new URL(response.url()).pathname === '/api/tasks')
    await create.getByRole('button', { name: '创建待授权任务', exact: true }).click()
    const response = await created
    assert(response.status() === 201, 'Chinese task is created through the actual form')
    taskId = (await response.json()).task_id
    await create.waitFor({ state: 'hidden' })
    await page.waitForURL(url => url.searchParams.get('task') === taskId)
    await page.getByRole('button', { name: '打开当前任务授权', exact: true }).click()
    await page.getByTestId('authorization-explorer').waitFor()
    await page.getByRole('button', { name: '查看并授权当前任务', exact: true }).click()
    const authorization = page.getByRole('dialog', { name: '确认任务授权' })
    const confirm = authorization.getByRole('checkbox', { name: '我确认本次工单、客户和授权额度', exact: true })
    await confirm.waitFor()
    await confirm.check()
    const signed = page.waitForResponse(response => response.request().method() === 'POST' && new URL(response.url()).pathname === `/api/tasks/${taskId}/authorize`)
    await authorization.getByRole('button', { name: '确认签发根授权', exact: true }).click()
    assert((await signed).status() === 201, 'explicit root confirmation actually signs selected task')
    await authorization.waitFor({ state: 'hidden' })
    const before = await (await page.request.get(`${origin}/api/tasks/${taskId}`)).json()
    assert(before.task.status === 'AUTHORIZED' && before.credentials.length === 1, 'root stored before tools or delegation')
    assert(before.executions.length === 0 && before.business_effects.refunds.length === 0, 'authorization itself creates no refund')
    await page.getByTestId('nav-overview').click()
    await page.getByRole('button', { name: '运行与配置', exact: true }).click()
    await page.getByRole('radiogroup', { name: '智能体规划方式' }).getByText('确定性规则', { exact: true }).click()
    const started = page.waitForResponse(response => response.request().method() === 'POST' && new URL(response.url()).pathname === `/api/tasks/${taskId}/workflow`)
    await page.getByTestId('start-business-workflow').click()
    const queued = await started
    assert(queued.status() === 202 && (await queued.json()).task_id === taskId, 'UI starts original authorized task, not another task')
    const workflowDeadline = Date.now() + 120000
    let terminal = false
    while (Date.now() < workflowDeadline) {
      const value = await (await page.request.get(`${origin}/api/tasks/${taskId}`)).json()
      const state = value.workflow_runs?.[0]?.state
      if (state === 'COMPLETED') { terminal = true; break }
      if (['FAILED', 'DENIED', 'STOPPED', 'EXPIRED'].includes(state)) throw new Error(`workflow terminated ${state}`)
      await page.waitForTimeout(500)
    }
    assert(terminal, 'selected workflow reaches actual completion within its deadline')
    const result = await (await page.request.get(`${origin}/api/tasks/${taskId}`)).json()
    const refunds = result.business_effects.refunds, notices = result.business_effects.notifications
    const refundResult = result.workflow_runs[0].events.find(item => item.action === 'call_tool' && item.details.tool === 'refund.create')?.details.output
    assert(refunds.length === 1 && refunds[0].amount_fen === 7000 && refundResult?.customer_id === '张三'
      && refundResult.tenant_id === business.tenant_id && refundResult.ticket_id === business.ticket_id
      && refundResult.refund_id === refunds[0].refund_id && refundResult.execution_id === refunds[0].execution_id,
    'actual refund service result binds one authorized Chinese-customer ledger effect')
    assert(notices.length === 1 && notices[0].template_id === 'REFUND_SUCCESS' && notices[0].content.includes('70.00') && notices[0].content.includes('张三'), 'fixed template body is stored for the original customer')
    assert(result.credentials.some(item => item.delegation_depth === 0), 'two-level delegation reaches zero remaining depth')
    assert(result.executions.length === 4 && result.executions.every(item => item.state === 'COMMITTED'), 'all four tools genuinely commit')
    assert(result.receipts.length === 4 && result.receipts.every(item => item.signature.valid), 'all four receipts have actual valid signatures')
    await page.getByTestId('nav-overview').click()
    await page.getByTestId('task-overview').waitFor()
    await page.getByRole('button', { name: '刷新运行状态', exact: true }).click()
    await page.getByRole('region', { name: '客户通知', exact: true }).getByText(notices[0].content, { exact: true }).waitFor()
    await page.screenshot({ path: 'F:/AgentGuardCompetition/AgentGuard/output/playwright/formal-studio/chinese-business-completed.png', fullPage: true })
    await page.getByRole('button', { name: '查看通知记录', exact: true }).click()
    await page.getByTestId('evidence-detail').getByRole('tab', { name: '投影 JSON', exact: true }).click()
    assert((await page.getByTestId('evidence-json').innerText()).includes(notices[0].notification_id), 'notification detail maps to the exact saved record')
    await page.keyboard.press('Escape')
    assert(!errors.length, 'no page runtime errors during real UI writes')
  } catch (error) {
    failure = String(error.message)
    await page.screenshot({ path: 'F:/AgentGuardCompetition/AgentGuard/output/playwright/formal-studio/failed-native-write.png', fullPage: true })
  } finally {
    try {
      if (restorePrimary && primary) {
        const restored = await page.request.put(`${origin}/api/model-configurations/${primary.id}`, { headers: configHeader, data: bodyFor(primary) })
        if (!restored.ok()) cleanupFailures.push(`primary restore HTTP ${restored.status()}`)
      }
      const current = await latestConfigurations()
      const initialIds = new Set(initial.items.map(item => item.id))
      for (const item of current.items) {
        if (!initialIds.has(item.id) && item.provider_id === 'acceptance-disabled') {
          const removed = await page.request.delete(`${origin}/api/model-configurations/${item.id}`, { headers: configHeader })
          if (!removed.ok()) cleanupFailures.push(`test profile removal HTTP ${removed.status()}`)
        }
      }
    } catch (error) { cleanupFailures.push(String(error.message)) }
  }
  const final = await latestConfigurations()
  const restored = final.default_id === initial.default_id && final.items.length === initial.items.length
  checks.push({ name: 'primary configuration and profile count are restored', passed: restored })
  if (!restored) cleanupFailures.push('configuration identity or profile count changed')
  return { status: failure || cleanupFailures.length ? 'FAIL' : 'PASS', scope: 'formal_native_ui_writes_no_model_calls', checks, task_id: taskId, errors, failure, cleanup_failures: cleanupFailures }
}
