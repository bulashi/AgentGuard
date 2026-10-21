async (page) => {
  const origin = new URL(page.url()).origin
  const requests = []
  const badResponses = []
  const consoleProblems = []
  const assert = (condition, message) => { if (!condition) throw new Error(message) }
  const health = await (await page.request.get(`${origin}/healthz`)).json()
  assert(health.runtime === 'native-development', 'not the native Windows frontend')
  const artifactRoot = 'F:/AgentGuardCompetition/AgentGuard/output/playwright/light-workbench'
  page.on('request', (request) => requests.push(request.url()))
  page.on('response', (response) => {
    if (response.status() >= 400) badResponses.push(`${response.status()} ${response.url()}`)
  })
  page.on('console', (message) => {
    if (['warning', 'error'].includes(message.type())) consoleProblems.push(message.text())
  })
  page.on('pageerror', (error) => consoleProblems.push(error.message))
  const screenshot = (name, fullPage = true) => page.screenshot({ path: `${artifactRoot}/${name}.png`, fullPage })
  const closeDetail = async () => {
    await page.keyboard.press('Escape')
    await page.getByTestId('evidence-detail').waitFor({ state: 'hidden' })
  }
  const projection = async () => {
    await page.getByTestId('evidence-detail').getByRole('tab', { name: '投影 JSON' }).click()
    return JSON.parse(await page.getByTestId('evidence-json').innerText())
  }
  const taskSnapshot = async (id) => (await page.request.get(`${origin}/api/tasks/${id}`)).json()
  const waitForTask = async (id) => {
    await page.waitForURL((url) => url.searchParams.get('task') === id)
    await page.getByTestId('live-execution').waitFor()
    await page.getByRole('button', { name: '任务详情', exact: true }).waitFor()
  }
  const layout = () => page.evaluate(() => ({
    documentWidth: document.documentElement.scrollWidth, viewportWidth: window.innerWidth,
    siderWidth: document.querySelector('.app-sider').getBoundingClientRect().width,
  }))
  const assertGraph = async (vertical) => {
    const bounds = await page.getByTestId('execution-flow').evaluate((graph) => {
      const outer = graph.getBoundingClientRect()
      return [...graph.querySelectorAll('.stage-button')].map((button) => {
        const rect = button.getBoundingClientRect()
        return { id: button.dataset.testid, width: rect.width, height: rect.height,
          inside: rect.left >= outer.left && rect.right <= outer.right && rect.top >= outer.top && rect.bottom <= outer.bottom }
      })
    })
    assert(bounds.length === 6 && bounds.every((item) => item.inside), `graph not fully framed: ${JSON.stringify(bounds)}`)
    assert(bounds.every((item) => item.width >= (vertical ? 185 : 130)), `graph nodes too small: ${JSON.stringify(bounds)}`)
    return bounds
  }

  await page.setViewportSize({ width: 1440, height: 1000 })
  await page.goto(origin, { waitUntil: 'networkidle' })
  await page.getByTestId('task-center').waitFor({ timeout: 30_000 })
  assert(await page.locator('[data-testid^="nav-"]').count() === 4, 'expected four main regions')
  const normalResponse = page.waitForResponse((response) => response.url().endsWith('/api/demos/normal') && response.request().method() === 'POST', { timeout: 120_000 })
  await page.getByRole('button', { name: '运行标准演示' }).click()
  const normal = await (await normalResponse).json()
  assert(normal.status === 'COMPLETED', `normal demo failed: ${JSON.stringify(normal)}`)
  await waitForTask(normal.task_id)
  await page.waitForFunction((length) => document.querySelector('[data-testid="replay-position"]')?.textContent === `${length} / ${length}`, normal.trace.length, { timeout: 30_000 })
  await page.getByTestId('execution-decision').getByText('已提交', { exact: true }).waitFor({ timeout: 30_000 })
  const successful = await taskSnapshot(normal.task_id)
  assert(successful.credentials.length === 4 && new Set(successful.credentials.map((item) => item.holder_agent_id)).size === 4, 'normal demo did not record four holders')
  assert(successful.executions.length === 4 && successful.receipts.length === 4 && successful.receipts.every((item) => item.signature.valid), 'normal executions or signatures missing')
  assert(successful.business_effects.refunds.reduce((sum, item) => sum + item.amount_fen, 0) === 7000 && successful.business_effects.notifications.length === 1, 'normal business state mismatch')
  assert((await page.getByTestId('stage-agents').innerText()).includes('2 级委托'), 'actual two-level delegation not displayed')
  assert((await page.getByTestId('stage-gateway').getAttribute('class')).includes('stage-complete'), 'gateway stayed pending after allow')
  const desktopGraph = await assertGraph(false)
  await screenshot('desktop-normal', false)

  await page.getByRole('button', { name: '重放', exact: true }).click()
  await page.waitForFunction(() => parseInt(document.querySelector('[data-testid="replay-position"]')?.textContent ?? '0') >= 1)
  const animation = await page.getByTestId('execution-flow').evaluate((graph) => ({
    active_nodes: graph.querySelectorAll('.stage-active').length,
    moving_edges: graph.querySelectorAll('.run-edge-active').length,
    edge_animation: graph.querySelector('.run-edge-active .react-flow__edge-path') ? getComputedStyle(graph.querySelector('.run-edge-active .react-flow__edge-path')).animationName : null,
  }))
  assert(animation.active_nodes > 0 && animation.moving_edges > 0 && /edge-travel|dashdraw/.test(animation.edge_animation), `replay did not animate: ${JSON.stringify(animation)}`)
  await screenshot('desktop-replaying', false)
  await page.getByRole('button', { name: '暂停回放', exact: true }).click()
  const paused = await page.getByTestId('replay-position').innerText()
  await page.waitForTimeout(900)
  assert(await page.getByTestId('replay-position').innerText() === paused, 'paused replay advanced')
  await page.getByRole('button', { name: '下一步', exact: true }).click()
  assert(parseInt(await page.getByTestId('replay-position').innerText()) === parseInt(paused) + 1, 'next replay step failed')
  await page.getByRole('button', { name: '上一步', exact: true }).click()
  assert(await page.getByTestId('replay-position').innerText() === paused, 'previous replay step failed')
  await page.getByRole('slider', { name: '回放进度' }).focus()
  await page.keyboard.press('End')
  assert(parseInt(await page.getByTestId('replay-position').innerText()) === normal.trace.length, 'replay seek did not reach end')

  for (const stage of ['request', 'authorization', 'agents', 'gateway', 'tools', 'evidence']) {
    await page.getByTestId(`stage-${stage}`).click()
    await page.getByTestId('evidence-detail').waitFor()
    assert((await page.getByTestId('evidence-detail').innerText()).length > 30, `empty detail for ${stage}`)
    await projection()
    await closeDetail()
  }
  const toolStepIndex = normal.trace.findIndex((step) => step.action === 'call_tool' && step.details.execution_id)
  assert(toolStepIndex >= 0, 'no exact execution link in service trace')
  await page.getByTestId(`run-step-${toolStepIndex + 1}`).click()
  const traceProjection = await projection()
  assert(traceProjection.details.execution_id === normal.trace[toolStepIndex].details.execution_id, 'wrong trace detail')
  await page.getByTestId('evidence-detail').getByRole('tab', { name: '关联记录' }).click()
  await page.getByTestId('evidence-detail').locator('.record-link').first().click()
  const executionProjection = await projection()
  assert(executionProjection.execution_id === traceProjection.details.execution_id && executionProjection.parameter_hash.length === 64, 'execution detail lost full identifiers')
  await page.getByTestId('evidence-detail').getByRole('tab', { name: '关联记录' }).click()
  await page.getByTestId('evidence-detail').locator('.record-link').first().click()
  const receiptProjection = await projection()
  assert(receiptProjection.execution_id === executionProjection.execution_id && receiptProjection.signature.valid, 'related signed receipt mismatch')
  await page.getByRole('button', { name: '返回上一条记录' }).click()
  assert((await projection()).execution_id === executionProjection.execution_id, 'drawer back did not restore execution')
  await screenshot('desktop-execution-detail', false)
  await closeDetail()

  await page.getByRole('tab', { name: '授权与预算', exact: true }).click()
  await page.getByTestId('credential-flow').locator('.react-flow__node').first().click()
  const credentialProjection = await projection()
  assert(credentialProjection.credential_id && credentialProjection.budgets.length && credentialProjection.signature.valid, 'credential drawer omitted budget or signature')
  await closeDetail()
  await page.getByRole('tab', { name: '回执与审计', exact: true }).click()
  await page.locator('.audit-events-panel .ant-table-row').first().click()
  const auditProjection = await projection()
  assert(auditProjection.event_hash.length === 64 && auditProjection.previous_event_hash.length === 64, 'audit drawer omitted full chain hashes')
  await closeDetail()

  await page.getByTestId('nav-history').click()
  await page.getByTestId('history-view').waitFor()
  await page.waitForFunction(() => document.querySelector('.history-count')?.textContent.includes('40'))
  await page.getByRole('button', { name: '加载更早记录' }).waitFor({ state: 'visible' })
  await page.getByRole('button', { name: '加载更早记录' }).click()
  await page.waitForFunction(() => parseInt(document.querySelector('.history-count')?.textContent.match(/\d+/)?.[0] ?? '0') > 40)
  const older = (await (await page.request.get(`${origin}/api/tasks?limit=1&offset=40`)).json()).items[0]
  assert(older, 'database has no older history for pagination test')
  await page.getByRole('textbox', { name: '搜索历史记录' }).fill(older.task_id)
  await page.getByTestId(`history-task-${older.task_id}`).waitFor()
  await page.waitForFunction(() => document.querySelector('.history-count')?.textContent.includes('1 条'))
  await screenshot('desktop-history', false)
  await page.getByTestId(`history-task-${older.task_id}`).click()
  await waitForTask(older.task_id)
  await page.getByRole('button', { name: '任务详情', exact: true }).click()
  assert((await projection()).task_id === older.task_id, 'history opened a different task')
  await closeDetail()
  await page.reload({ waitUntil: 'networkidle' })
  await waitForTask(older.task_id)
  assert((await page.getByTestId('live-execution').innerText()).includes('持久化事件回放'), 'refresh invented unavailable historic Agent trace')
  await page.getByRole('button', { name: '任务详情', exact: true }).click()
  assert((await projection()).task_id === older.task_id, 'URL refresh lost older selected task')
  await closeDetail()

  await page.getByRole('button', { name: '新建任务', exact: true }).click()
  await page.getByRole('dialog').waitFor()
  const createResponse = page.waitForResponse((response) => response.url().endsWith('/api/tasks') && response.request().method() === 'POST')
  await page.getByRole('button', { name: '创建待授权任务', exact: true }).click()
  const created = await (await createResponse).json()
  await waitForTask(created.task_id)
  await page.getByRole('button', { name: '确认当前任务授权', exact: true }).click()
  const authorizeResponse = page.waitForResponse((response) => response.url().endsWith(`/api/tasks/${created.task_id}/authorize`))
  await page.getByRole('dialog').getByRole('button', { name: '确认签发根授权', exact: true }).click()
  assert((await authorizeResponse).ok(), 'explicit root authorization failed')
  await page.getByRole('button', { name: '运行当前任务', exact: true }).waitFor()
  const manualResponse = page.waitForResponse((response) => response.url().endsWith(`/api/tasks/${created.task_id}/run`), { timeout: 120_000 })
  await page.getByRole('button', { name: '运行当前任务', exact: true }).click()
  const manual = await (await manualResponse).json()
  assert(manual.status === 'COMPLETED' && manual.task_id === created.task_id, 'manual create/authorize/run failed')
  await page.getByTestId('execution-decision').getByText('已提交', { exact: true }).waitFor({ timeout: 30_000 })

  await page.getByTestId('nav-security').click()
  const injectionResponse = page.waitForResponse((response) => response.url().endsWith('/api/demos/prompt-injection'), { timeout: 180_000 })
  await page.getByRole('button', { name: '运行注入演示' }).click()
  const injection = await (await injectionResponse).json()
  assert(injection.planner === 'llm' && injection.status === 'DENIED' && injection.reason_code === 'PARAMETER_CONSTRAINT_VIOLATION', `real injection did not match criteria: ${JSON.stringify(injection)}`)
  await page.getByTestId('gateway-pipeline').waitFor({ timeout: 30_000 })
  await page.waitForFunction(() => !document.querySelector('[data-testid="security-lab"] .ant-btn-loading'))
  const rejected = await taskSnapshot(injection.task_id)
  assert(!rejected.business_effects.refunds.length && !rejected.business_effects.notifications.length, 'rejected candidate produced business effects')
  assert(rejected.receipts.length && rejected.receipts.every((item) => item.signature.valid && item.decision === 'DENY'), 'signed denial receipt missing')
  assert((await page.getByTestId('gateway-pipeline').innerText()).includes('推断通过'), 'inferred stages were presented as internal event proof')
  await screenshot('desktop-injection', false)
  await page.getByRole('button', { name: '打开执行图与完整记录' }).click()
  await page.waitForFunction(() => Number(document.querySelector('.run-facts > button:last-child strong')?.textContent) >= 2)
  await page.waitForFunction(() => [...document.querySelectorAll('.result-row')].some((item) => item.textContent.includes('独立审计核验') && item.textContent.includes('有效')), undefined, { timeout: 30_000 })
  await page.getByRole('button', { name: '定位失败步骤' }).click()
  await page.getByTestId('evidence-detail').waitFor()
  await closeDetail()
  assert((await page.getByTestId('stage-gateway').getAttribute('class')).includes('stage-denied'), 'denial not highlighted at gateway')
  assert((await page.getByTestId('stage-tools').innerText()).includes('未分发'), 'blocked request was presented as tool execution')
  await screenshot('desktop-denied-flow', false)

  await page.setViewportSize({ width: 1920, height: 1080 })
  await page.getByRole('button', { name: '适应全部执行节点' }).click()
  const wideGraph = await assertGraph(false)
  await screenshot('wide-desktop', false)
  await page.setViewportSize({ width: 390, height: 844 })
  await page.waitForFunction(() => document.querySelector('[data-testid="execution-flow"]')?.classList.contains('vertical'))
  await page.waitForFunction(() => {
    const node = document.querySelector('[data-testid="stage-request"]')
    const sider = document.querySelector('.app-sider')
    return node?.getBoundingClientRect().width >= 185 && Math.abs(sider?.getBoundingClientRect().width - 56) <= 0.5
      && document.documentElement.scrollWidth <= window.innerWidth
  })
  const mobileGraph = await assertGraph(true)
  const mobileLayout = await layout()
  assert(mobileLayout.documentWidth <= mobileLayout.viewportWidth && Math.abs(mobileLayout.siderWidth - 56) <= 0.5, `mobile workbench overflow or uncollapsed sidebar: ${JSON.stringify(mobileLayout)}`)
  await page.waitForFunction(() => !document.querySelector('.ant-message-notice'))
  await page.evaluate(() => window.scrollTo(0, 0))
  await screenshot('mobile-workbench', false)
  await screenshot('mobile-workbench-full')
  await page.getByTestId('stage-gateway').click()
  await page.getByTestId('evidence-detail').locator('.record-link').first().click()
  const mobileExecution = await projection()
  assert(mobileExecution.reason_code === 'PARAMETER_CONSTRAINT_VIOLATION', 'mobile drawer opened wrong record')
  await page.getByTestId('evidence-detail').getByRole('tab', { name: '详情', exact: true }).click()
  const drawerWidth = await page.locator('.ant-drawer-content-wrapper').evaluate((drawer) => drawer.getBoundingClientRect().width)
  assert(drawerWidth <= 390, 'mobile detail drawer overflow')
  await screenshot('mobile-detail', false)
  await closeDetail()
  const mobileViews = {}
  for (const view of ['history', 'security', 'benchmark']) {
    await page.getByTestId(`nav-${view}`).click()
    await page.getByTestId(view === 'history' ? 'history-view' : view === 'security' ? 'security-lab' : 'benchmark').waitFor()
    await page.evaluate(() => window.scrollTo(0, 0))
    mobileViews[view] = await layout()
    assert(mobileViews[view].documentWidth <= mobileViews[view].viewportWidth, `mobile ${view} overflows`)
    await screenshot(`mobile-${view}`, false)
  }
  assert((await page.getByTestId('benchmark').innerText()).includes('已验证运行'), 'recorded Compose benchmark unavailable')
  await page.setViewportSize({ width: 1440, height: 1000 })
  await page.getByTestId('nav-workbench').click()
  await page.getByRole('tab', { name: '执行图', exact: true }).click()

  const origins = [...new Set(requests.map((url) => new URL(url).origin))]
  assert(origins.length === 1 && origins[0] === origin, 'browser crossed same-origin BFF')
  assert(!badResponses.length, `HTTP errors: ${badResponses.join('; ')}`)
  assert(!consoleProblems.length, `console errors: ${consoleProblems.join('; ')}`)
  return JSON.stringify({ status: 'PASS', runtime: 'windows-native', origin, generated_at: new Date().toISOString(),
    normal_task_id: normal.task_id, manual_task_id: created.task_id, injection_task_id: injection.task_id, history_task_id: older.task_id,
    normal: '4_HOLDERS_4_TOOLS_2_DELEGATION_LEVELS_REFUND_7000_NOTIFICATION_1',
    manual_workflow: 'CREATE_EXPLICIT_AUTHORIZE_EXECUTE', injection: 'REAL_LLM_DENIED_NO_BUSINESS_EFFECT_VALID_DENIAL_RECEIPT',
    replay_controls: 'PLAY_ANIMATION_PAUSE_PREVIOUS_NEXT_SEEK_FAILURE_LOCATION', animation, detail_navigation: '6_NODES_TRACE_EXECUTION_RECEIPT_CREDENTIAL_AUDIT_JSON_BACK',
    history: 'OFFSET_40_DATABASE_SEARCH_OPEN_AND_URL_REFRESH_NO_INVENTED_AGENT_TRACE',
    desktop_graph: desktopGraph, wide_graph: wideGraph, mobile_graph: mobileGraph, mobile_layout: mobileLayout, mobile_views: mobileViews,
    console_problems: consoleProblems.length, bad_responses: badResponses.length, request_origins: origins, request_count: requests.length,
    benchmark_provenance: 'recorded_compose_result_not_native_performance_claim', artifacts: artifactRoot })
}
