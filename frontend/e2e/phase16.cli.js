async (page) => {
  const origin = 'http://127.0.0.1:8088'
  const requestUrls = []
  const badResponses = []
  const consoleProblems = []

  const assert = (condition, message) => {
    if (!condition) throw new Error(message)
  }

  page.on('request', (request) => requestUrls.push(request.url()))
  page.on('response', (response) => {
    if (response.status() >= 400) {
      badResponses.push(`${response.status()} ${response.url()}`)
    }
  })
  page.on('console', (message) => {
    if (message.type() === 'error' || message.type() === 'warning') {
      consoleProblems.push(`${message.type()}: ${message.text()}`)
    }
  })
  page.on('pageerror', (error) => consoleProblems.push(`pageerror: ${error.message}`))

  await page.setViewportSize({ width: 1440, height: 1000 })
  await page.goto(origin, { waitUntil: 'networkidle' })
  await page.getByTestId('task-center').waitFor({ timeout: 30_000 })
  assert(await page.locator('[data-testid^="nav-"]').count() === 4, 'four UI regions are not present')
  assert((await page.getByTestId('task-center').innerText()).includes('任务运行台'), 'workbench did not load')

  await page.getByRole('button', { name: '运行标准演示' }).click()
  await page.getByTestId('live-execution').waitFor({ timeout: 120_000 })
  await page.getByTestId('execution-decision').getByText('已提交', { exact: true }).waitFor({ timeout: 120_000 })
  const liveText = await page.getByTestId('live-execution').innerText()
  for (const marker of ['授权凭证\n4', '工具请求\n4', '有效回执\n4', '退款 70 元']) {
    assert(liveText.includes(marker), `normal demo omitted marker: ${marker}`)
  }
  await page.screenshot({ path: 'evidence/phase-16/e2e-desktop-normal.png', fullPage: true })

  await page.getByRole('tab', { name: '授权与预算', exact: true }).click()
  await page.getByTestId('authorization-explorer').waitFor()
  const authorizationText = await page.getByTestId('authorization-explorer').innerText()
  for (const marker of ['凭证链\n4', '签名有效\n4', '投影收窄检查\n一致', '协调智能体', '案例智能体', '退款智能体', '知识智能体']) {
    assert(authorizationText.includes(marker), `authorization view omitted marker: ${marker}`)
  }

  await page.getByRole('tab', { name: '回执与审计', exact: true }).click()
  await page.getByTestId('audit-evidence').waitFor()
  const successfulAuditText = await page.getByTestId('audit-evidence').innerText()
  for (const marker of ['审计哈希链（Hash Chain）与独立检查点一致', 'EXECUTION_RESULT', '允许', '已签名', '已提交']) {
    assert(successfulAuditText.includes(marker), `successful audit view omitted marker: ${marker}`)
  }

  await page.getByTestId('nav-security').click()
  await page.getByRole('button', { name: '运行注入演示' }).click()
  await page.getByText('PARAMETER_CONSTRAINT_VIOLATION', { exact: true }).first().waitFor({ timeout: 180_000 })
  await page.waitForFunction(
    () => {
      const text = document.querySelector('[data-testid="security-lab"]')?.innerText ?? ''
      return text.includes('参数约束校验\n拒绝')
        && text.includes('签名执行回执\n有效')
        && text.includes('业务副作用\n无')
        && text.includes('审计哈希链（Hash Chain）\n已留证')
    },
    undefined,
    { timeout: 30_000 },
  )
  const securityText = await page.getByTestId('security-lab').innerText()
  for (const marker of ['已拒绝', '越权副作用\n0', 'PARAMETER_CONSTRAINT_VIOLATION', '签名执行回执\n有效', '业务副作用\n无', '审计哈希链（Hash Chain）\n已留证']) {
    assert(securityText.includes(marker), `security lab omitted marker: ${marker}`)
  }
  await page.screenshot({ path: 'evidence/phase-16/e2e-desktop-injection.png', fullPage: true })

  await page.getByTestId('nav-workbench').click()
  await page.getByRole('tab', { name: '回执与审计', exact: true }).click()
  await page.getByTestId('audit-evidence').waitFor()
  const deniedAuditText = await page.getByTestId('audit-evidence').innerText()
  for (const marker of ['AUTHORIZATION_DENIAL', '拒绝', 'PARAMETER_CONSTRAINT_VIOLATION', '无', '有效']) {
    assert(deniedAuditText.includes(marker), `denied audit view omitted marker: ${marker}`)
  }

  await page.getByTestId('nav-benchmark').click()
  await page.getByTestId('benchmark').waitFor()
  const benchmarkText = await page.getByTestId('benchmark').innerText()
  if (benchmarkText.includes('等待正式评测')) {
    assert(benchmarkText.includes('不会用占位数字代替'), 'benchmark page does not disclose missing measurements')
  } else {
    assert(benchmarkText.includes('已验证运行'), 'benchmark page has neither pending disclosure nor verified provenance')
  }

  await page.setViewportSize({ width: 390, height: 844 })
  await page.getByTestId('nav-history').click()
  await page.getByTestId('history-view').waitFor()
  const mobileLayout = await page.evaluate(() => {
    const table = document.querySelector('.history-table .ant-table-content')
    return {
      documentWidth: document.documentElement.scrollWidth,
      viewportWidth: window.innerWidth,
      tableClientWidth: table?.clientWidth ?? 0,
      tableScrollWidth: table?.scrollWidth ?? 0,
    }
  })
  assert(mobileLayout.documentWidth <= mobileLayout.viewportWidth, `mobile page overflows: ${JSON.stringify(mobileLayout)}`)
  assert(mobileLayout.tableScrollWidth > mobileLayout.tableClientWidth, `mobile task table lacks bounded horizontal scroll: ${JSON.stringify(mobileLayout)}`)
  await page.screenshot({ path: 'evidence/phase-16/e2e-mobile-task-center.png', fullPage: true })

  await page.getByTestId('nav-security').click()
  await page.getByTestId('security-lab').waitFor()
  const mobileSecurity = await page.evaluate(() => ({
    documentWidth: document.documentElement.scrollWidth,
    viewportWidth: window.innerWidth,
  }))
  assert(mobileSecurity.documentWidth <= mobileSecurity.viewportWidth, `mobile security page overflows: ${JSON.stringify(mobileSecurity)}`)
  await page.screenshot({ path: 'evidence/phase-16/e2e-mobile-security-lab.png', fullPage: true })

  const requestOrigins = [...new Set(requestUrls.map((value) => new URL(value).origin))]
  assert(requestOrigins.length === 1 && requestOrigins[0] === origin, `browser crossed the BFF boundary: ${requestOrigins.join(',')}`)
  assert(badResponses.length === 0, `browser received error responses: ${badResponses.join('; ')}`)
  assert(consoleProblems.length === 0, `browser console problems: ${consoleProblems.join('; ')}`)

  return JSON.stringify({
    status: 'PASS',
    normal: 'COMPLETED_4_AGENTS_4_TOOLS',
    prompt_injection: 'DENIED_PARAMETER_CONSTRAINT_VIOLATION_EFFECT_NONE',
    request_origins: requestOrigins,
    request_count: requestUrls.length,
    console_problems: consoleProblems.length,
    bad_responses: badResponses.length,
    mobile_layout: mobileLayout,
  })
}
