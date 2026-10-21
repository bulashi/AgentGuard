async (page) => {
  const initial = new URL(page.url())
  const origin = initial.origin
  const selectedTask = initial.searchParams.get('task')
  page.setDefaultTimeout(15000)
  const directory = 'F:/AgentGuardCompetition/AgentGuard/output/playwright/formal-studio'
  const checks = [], errors = [], badResponses = [], requests = []
  const assert = (condition, name) => { checks.push({ name, passed: Boolean(condition) }); if (!condition) throw new Error(name) }
  page.on('pageerror', (error) => errors.push(error.message))
  page.on('console', (event) => { if (event.type() === 'error' || event.type() === 'warning') errors.push(event.text()) })
  page.on('request', (request) => requests.push({ method: request.method(), origin: new URL(request.url()).origin, path: new URL(request.url()).pathname }))
  page.on('response', (response) => { if (response.status() >= 400) badResponses.push({ status: response.status(), path: new URL(response.url()).pathname }) })
  const screenshot = (name) => page.screenshot({ path: `${directory}/${name}.png`, fullPage: true })
  const close = async () => { await page.keyboard.press('Escape'); await page.getByTestId('evidence-detail').waitFor({ state: 'hidden' }) }
  const projection = async () => {
    await page.getByTestId('evidence-detail').waitFor()
    await page.getByTestId('evidence-detail').getByRole('tab', { name: '投影 JSON' }).click()
    return JSON.parse(await page.getByTestId('evidence-json').innerText())
  }
  const navigate = async (name) => {
    await page.waitForFunction(() => {
      const label = document.querySelector('.nav-toggle')?.getAttribute('aria-label')
      return window.matchMedia('(max-width: 1000px)').matches
        ? label === '打开导航' || label === '关闭导航'
        : label === '展开导航' || label === '收起导航'
    })
    const toggle = page.getByRole('button', { name: '打开导航', exact: true })
    if (await toggle.isVisible()) await toggle.click()
    await page.waitForFunction(() => {
      const sidebar = document.querySelector('.app-sider')
      return sidebar && !sidebar.hasAttribute('inert') && sidebar.getBoundingClientRect().left >= 0
    })
    await page.getByTestId(`nav-${name}`).click()
    await page.waitForURL((url) => url.hash === `#${name}`)
  }
  const noOverflow = async (name) => {
    const size = await page.evaluate(() => ({ width: innerWidth, content: document.documentElement.scrollWidth }))
    assert(size.content <= size.width + 1, `${name}: page width ${size.content} <= ${size.width}`)
  }
  let failure = null
  try {
    await page.setViewportSize({ width: 1440, height: 1000 })
    const target = new URL(origin)
    if (selectedTask) target.searchParams.set('task', selectedTask)
    await page.goto(target.href, { waitUntil: 'domcontentloaded' })
    await page.getByTestId('task-overview').waitFor({ timeout: 30000 })
    const taskId = new URL(page.url()).searchParams.get('task')
    const response = await page.request.get(`${origin}/api/tasks/${taskId}`)
    assert(response.ok(), 'native BFF task read')
    const snapshot = await response.json()
    assert(await page.locator('[data-testid^="nav-"]').count() === 7, 'all seven formal navigation entries retained')
    assert(await page.locator('.studio-process-stage').count() === 4, 'four main stages: authorization, roles, gateway and business results')
    assert(await page.locator('.studio-agent-roster button').count() === 4, 'four actual role detail entries')
    assert((await page.getByTestId('task-overview').innerText()).includes(snapshot.task.customer_id), 'homepage bound to selected task')
    await noOverflow('desktop overview')
    await screenshot('desktop-overview')
    await page.getByRole('button', { name: '运行与配置', exact: true }).click()
    assert(await page.getByTestId('start-business-workflow').isVisible(), 'real execution controls available inline')
    const controlsBeforePath = await page.evaluate(() => document.querySelector('.studio-inline-controls').getBoundingClientRect().top < document.querySelector('.studio-process-path').getBoundingClientRect().top)
    assert(controlsBeforePath, 'run controls appear adjacent to heading, not after page results')
    await page.getByRole('button', { name: '查看模型配置' }).click()
    const model = page.getByRole('dialog')
    await model.getByText('智能体运行配置', { exact: true }).waitFor()
    await model.getByRole('tab', { name: '智能体审查' }).click()
    await model.getByLabel('端点 URL', { exact: true }).waitFor()
    assert(await model.getByLabel('API 密钥', { exact: true }).inputValue() === '', 'stored API key is never read back into the form')
    assert(await model.getByRole('radio', { name: 'Responses API · 未适配', exact: true }).isDisabled(), 'unsupported Responses protocol is not advertised as usable')
    assert(await model.getByRole('radio', { name: 'Anthropic Messages · 未适配', exact: true }).isDisabled(), 'unsupported Anthropic protocol is not advertised as usable')
    await model.getByRole('tab', { name: '确定性规则' }).click()
    assert((await model.innerText()).includes('规则规划不调用大模型'), 'deterministic independent model configuration')
    await model.getByRole('button', { name: '关闭', exact: true }).click()
    await model.waitFor({ state: 'hidden' })
    await page.getByRole('button', { name: '运行与配置', exact: true }).click()
    await page.getByRole('button', { name: '新建任务', exact: true }).click()
    const create = page.getByRole('dialog')
    await create.getByRole('spinbutton').last().waitFor()
    assert(await create.getByRole('spinbutton').count() === 3, 'task form preserves amount, call count and validity constraints')
    await create.getByRole('button', { name: '取消', exact: true }).click()
    await create.waitFor({ state: 'hidden' })
    for (const name of ['工单详情', '关联知识', '查看业务效果', '安全网关', '回执留证']) {
      await page.getByTestId('task-overview').getByRole('button', { name: new RegExp(`^${name}`) }).click()
      assert(Boolean(await projection()), `${name}: inspectable JSON`)
      await close()
    }
    for (const name of ['协调智能体', '知识智能体', '工单智能体', '退款智能体']) {
      await page.locator('.studio-agent-roster').getByRole('button', { name: new RegExp(name) }).click()
      const value = await projection()
      assert(JSON.stringify(value).includes('agent-'), `${name}: persisted role projection`)
      await close()
    }
    if (snapshot.workflow_runs?.[0]?.events.length) {
      const position = page.locator('.studio-replay-count')
      const taskResult = await page.locator('.studio-result-amount').innerText()
      await page.getByRole('button', { name: '回放过程', exact: true }).click()
      await page.waitForFunction(() => Number(document.querySelector('.studio-replay-count').textContent.split('/')[0]) > 0, undefined, { timeout: 10000 })
      await page.getByRole('button', { name: '暂停回放', exact: true }).click()
      const paused = await position.innerText()
      await page.waitForTimeout(1400)
      assert(await position.innerText() === paused, 'paused homepage playback does not advance')
      assert(await page.locator('.studio-result-amount').innerText() === taskResult, 'observation playback does not alter cumulative business facts')
      await page.getByRole('button', { name: '查看事件', exact: true }).click()
      assert((await projection()).sequence > 0, 'playback opens exact saved event')
      await close()
      await page.getByRole('slider', { name: '首页回放进度' }).focus()
      await page.keyboard.press('End')
      assert((await position.innerText()).startsWith(String(snapshot.workflow_runs[0].events.length)), 'keyboard seek reaches final saved event')
    }
    if (snapshot.executions.length) {
      await page.locator('.studio-tool-row').first().click()
      const execution = (await projection()).execution
      assert(snapshot.executions.some((item) => item.execution_id === execution.execution_id), 'homepage tool row opens exact persisted execution')
      await page.getByTestId('evidence-detail').getByRole('tab', { name: '关联记录' }).click()
      assert(await page.getByTestId('evidence-detail').locator('.record-link').count() > 0, 'execution links actual related evidence')
      await page.getByTestId('evidence-detail').locator('.record-link').first().click()
      assert(Boolean(await projection()), 'related evidence can be inspected')
      await page.getByRole('button', { name: '返回上一条记录' }).click()
      assert((await projection()).execution.execution_id === execution.execution_id, 'drawer back restores exact execution')
      await screenshot('desktop-execution-detail')
      await close()
    }
    await navigate('flow')
    await page.getByTestId('business-graph').waitFor()
    assert(await page.getByTestId('business-graph').getByRole('button', { name: /^查看/ }).count() === 9, 'four roles, gateway and four tools preserved')
    for (const name of ['查看协调智能体', '查看知识智能体', '查看工单智能体', '查看退款智能体', '查看安全网关', '查看查询关联知识', '查看读取工单', '查看创建退款', '查看发送退款通知']) {
      await page.getByTestId('business-graph').getByRole('button', { name, exact: true }).click()
      assert(Boolean(await projection()), `${name}: formal flow detail`)
      await close()
    }
    await page.getByRole('radiogroup', { name: '协作图视角' }).getByText('委托链', { exact: true }).click()
    assert((await page.getByTestId('business-graph').innerText()).includes('根授权'), 'alternate delegation view available')
    await screenshot('desktop-delegation')
    await page.getByRole('radiogroup', { name: '协作图视角' }).getByText('请求路径', { exact: true }).click()
    await screenshot('desktop-flow')
    await page.getByRole('tab', { name: '控制链路回放' }).click()
    await page.getByTestId('live-execution').waitFor()
    assert(await page.getByTestId('execution-flow').isVisible(), 'saved execution control-chain view available')
    await navigate('records')
    await page.getByTestId('execution-records').waitFor()
    await page.getByRole('textbox', { name: '搜索执行记录' }).fill('no-such-formal-studio-record')
    await page.getByText('暂无匹配执行记录').waitFor()
    assert(true, 'execution search preserves honest empty state')
    await page.getByRole('textbox', { name: '搜索执行记录' }).fill('')
    if (snapshot.executions.length) {
      await page.getByRole('button', { name: `查看执行 ${snapshot.executions[0].execution_id}` }).click()
      assert((await projection()).execution.execution_id === snapshot.executions[0].execution_id, 'execution records exact identifier')
      await close()
    }
    await navigate('evidence')
    await page.getByTestId('authorization-explorer').waitFor()
    if (snapshot.credentials.length) {
      await page.getByTestId('credential-flow').locator('.react-flow__node').first().click()
      assert(Boolean((await projection()).credential_id), 'credential graph opens signed credential and budgets')
      await close()
    }
    await page.locator('.advanced-authorization > summary').click()
    await page.getByRole('button', { name: '共同授权状态', exact: true }).click()
    const approval = page.getByRole('dialog')
    await approval.getByText('本入口未查询审批记录').waitFor()
    assert((await approval.innerText()).includes('外部独立签名主体'), 'joint approval preserves independent signer boundary')
    await approval.getByRole('button', { name: '关闭', exact: true }).click()
    await approval.waitFor({ state: 'hidden' })
    for (const tab of ['执行回执', '审计记录']) {
      await page.getByRole('tab', { name: tab, exact: true }).click()
      await page.getByTestId('audit-evidence').waitFor()
      assert((await page.getByTestId('audit-evidence').innerText()).length > 30, `${tab}: persisted evidence view`)
      await screenshot(`desktop-${tab === '执行回执' ? 'receipts' : 'audit'}`)
    }
    await navigate('history')
    await page.getByTestId('history-view').waitFor()
    await page.getByRole('textbox', { name: '搜索历史记录' }).fill(taskId)
    await page.getByTestId(`history-task-${taskId}`).waitFor()
    await page.waitForFunction(() => document.querySelectorAll('.history-task-link').length === 1, undefined, { timeout: 10000 })
    assert(await page.locator('.history-task-link').count() === 1, 'history search resolves exact task')
    await page.getByTestId(`history-task-${taskId}`).click()
    await page.getByTestId('task-overview').waitFor()
    assert(new URL(page.url()).searchParams.get('task') === taskId, 'history restores task workbench and URL')
    await page.reload({ waitUntil: 'domcontentloaded' })
    await page.getByTestId('task-overview').waitFor()
    assert(new URL(page.url()).searchParams.get('task') === taskId, 'refresh preserves historical task selection')
    await navigate('security')
    await page.getByTestId('security-lab').waitFor()
    assert((await page.getByTestId('security-lab').innerText()).includes('确定性安全场景'), 'deterministic attack matrix available independently of LLM')
    const scenario = page.getByTestId('security-lab').locator('.ant-table-row').first()
    await scenario.click()
    assert(Boolean(await projection()), 'security scenario opens real matrix definition')
    await close()
    await screenshot('desktop-security')
    await navigate('benchmark')
    await page.getByTestId('benchmark').waitFor()
    assert((await page.getByTestId('benchmark').innerText()).includes('AgentGuard'), 'benchmark comparison and provenance view retained')
    await screenshot('desktop-benchmark')
    for (const width of [1920, 1024, 768, 390, 320]) {
      await page.setViewportSize({ width, height: width >= 1024 ? 1080 : 844 })
      await navigate('overview')
      await page.getByTestId('task-overview').waitFor()
      await noOverflow(`${width}px overview`)
      if (width < 1000) {
        const sidebar = page.getByRole('complementary', { name: '工作区导航', hidden: true })
        assert(await sidebar.getAttribute('inert') !== null, `${width}px hidden navigation cannot receive focus`)
        await page.waitForFunction(() => document.querySelector('.app-sider').getBoundingClientRect().right <= 0, undefined, { timeout: 5000 })
        await screenshot(`overview-${width}`)
        assert(await sidebar.evaluate((node) => node.getBoundingClientRect().right <= 0), `${width}px closed navigation does not cover content`)
        await page.getByRole('button', { name: '打开导航', exact: true }).click()
        await page.waitForFunction(() => document.querySelector('.app-sider').getBoundingClientRect().left >= 0, undefined, { timeout: 5000 })
        assert(await sidebar.evaluate((node) => node.getBoundingClientRect().width === 240), `${width}px open navigation uses full readable drawer width`)
        assert(await sidebar.locator('.brand-copy').isVisible() && await page.getByTestId('nav-overview').locator('span').isVisible(), `${width}px mobile navigation labels remain readable`)
        await screenshot(`navigation-${width}`)
        await page.getByTestId('nav-overview').click()
        for (const name of ['flow', 'records', 'history', 'evidence', 'security', 'benchmark']) {
          await navigate(name)
          await page.waitForTimeout(350)
          await noOverflow(`${width}px ${name}`)
        }
      } else await screenshot(`overview-${width}`)
    }
    await page.setViewportSize({ width: 1440, height: 1000 })
    await navigate('overview')
    await page.getByRole('button', { name: '收起导航', exact: true }).click()
    await page.waitForFunction(() => document.querySelector('.app-sider').getBoundingClientRect().width <= 71, undefined, { timeout: 5000 })
    const siderWidth = await page.locator('.app-sider').evaluate((node) => node.getBoundingClientRect().width)
    assert(siderWidth <= 71, 'desktop navigation collapses to icon rail')
    await page.getByRole('button', { name: '展开导航', exact: true }).click()
    assert(requests.every((item) => item.method === 'GET' || item.method === 'POST' && /\/api\/extensions\/audit-prefix-binding\/v1\/tasks\/[^/]+\/verify-events$/.test(item.path)), 'browser only reads business state and verifies audit bindings')
    assert(requests.every((item) => item.origin === origin), 'browser stayed behind same-origin BFF')
    assert(!badResponses.length, 'no unhandled HTTP error responses')
    assert(!errors.length, 'no browser warnings or runtime errors')
  } catch (error) {
    failure = String(error.message)
    await screenshot('failed-readonly')
  }
  const report = { status: failure ? 'FAIL' : 'PASS', scope: 'formal_native_readonly_browser', checks, errors, badResponses, requestCount: requests.length, failure }
  return JSON.stringify(report)
}
