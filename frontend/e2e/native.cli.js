async (page) => {
  const origin = new URL(page.url()).origin
  const requests = []
  const badResponses = []
  const consoleProblems = []
  const assert = (condition, message) => { if (!condition) throw new Error(message) }
  const health = await (await page.request.get(`${origin}/healthz`)).json()
  assert(health.runtime === 'native-development', 'not the native Windows frontend')
  page.on('request', (request) => requests.push(request.url()))
  page.on('response', (response) => {
    if (response.status() >= 400) badResponses.push(`${response.status()} ${response.url()}`)
  })
  page.on('console', (message) => {
    if (['warning', 'error'].includes(message.type())) consoleProblems.push(message.text())
  })
  page.on('pageerror', (error) => consoleProblems.push(error.message))
  await page.setViewportSize({ width: 1440, height: 1000 })
  await page.goto(origin, { waitUntil: 'networkidle' })
  await page.getByTestId('task-center').waitFor({ timeout: 30_000 })
  assert(await page.locator('[data-testid^="nav-"]').count() === 4, 'missing UI regions')
  await page.getByRole('button', { name: '运行标准演示' }).click()
  await page.getByTestId('live-execution').waitFor({ timeout: 120_000 })
  await page.getByTestId('run-step-1').waitFor({ timeout: 10_000 })
  await page.getByTestId('execution-decision').getByText('已提交', { exact: true }).waitFor({ timeout: 120_000 })
  const liveText = await page.getByTestId('live-execution').innerText()
  for (const marker of ['授权凭证\n4', '工具请求\n4', '有效回执\n4', '退款 70 元']) {
    assert(liveText.includes(marker), `normal demo omitted ${marker}`)
  }
  await page.screenshot({ path: 'evidence/native-windows/desktop-normal.png', fullPage: true })
  await page.getByRole('tab', { name: '授权与预算', exact: true }).click()
  await page.getByTestId('authorization-explorer').waitFor()
  const authorizationText = await page.getByTestId('authorization-explorer').innerText()
  for (const marker of ['凭证链\n4', '签名有效\n4', '投影收窄检查\n一致']) {
    assert(authorizationText.includes(marker), `authorization omitted ${marker}`)
  }
  await page.getByTestId('nav-security').click()
  await page.getByRole('button', { name: '运行注入演示' }).click()
  await page.getByText('PARAMETER_CONSTRAINT_VIOLATION', { exact: true }).first().waitFor({ timeout: 180_000 })
  await page.waitForFunction(() => {
    const text = document.querySelector('[data-testid="security-lab"]')?.innerText ?? ''
    return text.includes('签名执行回执\n有效') && text.includes('业务副作用\n无')
      && text.includes('审计哈希链（Hash Chain）\n已留证')
  }, undefined, { timeout: 30_000 })
  await page.screenshot({ path: 'evidence/native-windows/desktop-injection.png', fullPage: true })
  await page.getByTestId('nav-workbench').click()
  await page.getByRole('tab', { name: '回执与审计', exact: true }).click()
  await page.getByTestId('audit-evidence').waitFor()
  assert((await page.getByTestId('audit-evidence').innerText()).includes('审计哈希链（Hash Chain）与独立检查点一致'),
    'audit chain or independent checkpoint is not verified')
  await page.getByTestId('nav-benchmark').click()
  await page.getByTestId('benchmark').waitFor()
  assert((await page.getByTestId('benchmark').innerText()).includes('已验证运行'),
    'recorded Compose benchmark could not be loaded')
  await page.setViewportSize({ width: 390, height: 844 })
  await page.getByTestId('nav-workbench').click()
  await page.getByTestId('task-center').waitFor()
  await page.waitForFunction(() => {
    const sider = document.querySelector('.ant-layout-sider')
    return sider && Math.abs(sider.getBoundingClientRect().width - 56) < 1
  })
  const mobileLayout = await page.evaluate(() => ({
    documentWidth: document.documentElement.scrollWidth, viewportWidth: window.innerWidth,
  }))
  assert(mobileLayout.documentWidth <= mobileLayout.viewportWidth, 'mobile Task Center overflows')
  await page.screenshot({ path: 'evidence/native-windows/mobile-tasks.png', fullPage: true })
  await page.getByTestId('nav-security').click()
  await page.getByTestId('security-lab').waitFor()
  const mobileSecurity = await page.evaluate(() => ({
    documentWidth: document.documentElement.scrollWidth, viewportWidth: window.innerWidth,
  }))
  assert(mobileSecurity.documentWidth <= mobileSecurity.viewportWidth, 'mobile Security Lab overflows')
  await page.screenshot({ path: 'evidence/native-windows/mobile-security.png', fullPage: true })
  const origins = [...new Set(requests.map((url) => new URL(url).origin))]
  assert(origins.length === 1 && origins[0] === origin, 'browser requests crossed the same-origin BFF')
  assert(!badResponses.length, `HTTP errors: ${badResponses.join('; ')}`)
  assert(!consoleProblems.length, `console errors: ${consoleProblems.join('; ')}`)
  return JSON.stringify({ status: 'PASS', runtime: 'windows-native', origin,
    normal: 'COMPLETED_4_AGENTS_4_TOOLS_2_LEVEL_DELEGATION',
    injection: 'DENIED_PARAMETER_CONSTRAINT_VIOLATION_EFFECT_NONE',
    console_problems: consoleProblems.length, bad_responses: badResponses.length,
    request_origins: origins, request_count: requests.length,
    mobile_layout: mobileLayout, mobile_security: mobileSecurity,
    benchmark_provenance: 'recorded_compose_result_not_native_performance_claim' })
}
