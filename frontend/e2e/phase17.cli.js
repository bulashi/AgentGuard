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
    if (response.status() >= 400) badResponses.push(`${response.status()} ${response.url()}`)
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
  await page.getByTestId('nav-benchmark').click()
  await page.getByTestId('benchmark').waitFor({ timeout: 30_000 })

  const benchmarkText = await page.getByTestId('benchmark').innerText()
  for (const marker of [
    '已验证',
    '公平基线对比',
    'AgentGuard',
    '共享静态凭据',
    '常规智能体 RBAC',
    '授权到业务效果的唯一映射',
    '多级共享预算守恒',
    '未知结果安全性',
    '证据交叉验证',
    'AEC-01',
    'AEC-04',
    '隔离消融',
    '移除原子准入（Atomic Admission）',
    '全部强制安全门禁通过',
  ]) {
    assert(benchmarkText.includes(marker), `benchmark page omitted marker: ${marker}`)
  }
  assert(!benchmarkText.includes('PENDING_PHASE_17'), 'verified benchmark page still reports pending')
  assert(!benchmarkText.includes('"latency_ms"'), 'benchmark page renders raw summary JSON')
  await page.screenshot({ path: 'evidence/phase-17/desktop-benchmark-verified.png', fullPage: true })

  await page.setViewportSize({ width: 390, height: 844 })
  await page.waitForFunction(
    () => {
      const sider = document.querySelector('.ant-layout-sider')
      return Boolean(sider && Math.abs(sider.getBoundingClientRect().width - 56) <= 0.5)
    },
    undefined,
    { timeout: 5_000 },
  )
  await page.mouse.move(389, 843)
  await page.waitForFunction(
    () =>
      ![...document.querySelectorAll('.ant-tooltip')].some((tooltip) => {
        const style = window.getComputedStyle(tooltip)
        const rect = tooltip.getBoundingClientRect()
        return style.visibility !== 'hidden' && rect.width > 0 && rect.height > 0
      }),
    undefined,
    { timeout: 2_000 },
  )
  const mobileLayout = await page.evaluate(() => {
    const table = document.querySelector('.benchmark-comparison-panel .ant-table-content')
    const sider = document.querySelector('.ant-layout-sider')
    const content = document.querySelector('.content-inner')
    const benchmark = document.querySelector('[data-testid="benchmark"]')
    const siderStyle = sider ? window.getComputedStyle(sider) : null
    const siderRect = sider?.getBoundingClientRect()
    const contentRect = content?.getBoundingClientRect()
    const benchmarkRect = benchmark?.getBoundingClientRect()
    return {
      documentWidth: document.documentElement.scrollWidth,
      viewportWidth: window.innerWidth,
      viewportMeta: document.querySelector('meta[name="viewport"]')?.getAttribute('content') ?? null,
      mediaQueryMatches: window.matchMedia('(max-width: 992px)').matches,
      devicePixelRatio: window.devicePixelRatio,
      siderClassName: sider?.className ?? null,
      siderInlineStyle: sider?.getAttribute('style') ?? null,
      siderComputedWidth: siderStyle?.width ?? null,
      siderComputedMinWidth: siderStyle?.minWidth ?? null,
      siderComputedMaxWidth: siderStyle?.maxWidth ?? null,
      siderComputedFlex: siderStyle?.flex ?? null,
      siderWidth: siderRect?.width ?? 0,
      contentWidth: contentRect?.width ?? 0,
      contentRightGap: contentRect ? window.innerWidth - contentRect.right : window.innerWidth,
      benchmarkWidth: benchmarkRect?.width ?? 0,
      benchmarkRightGap: benchmarkRect ? window.innerWidth - benchmarkRect.right : window.innerWidth,
      tableClientWidth: table?.clientWidth ?? 0,
      tableScrollWidth: table?.scrollWidth ?? 0,
    }
  })
  assert(
    mobileLayout.documentWidth <= mobileLayout.viewportWidth,
    `mobile benchmark page overflows: ${JSON.stringify(mobileLayout)}`,
  )
  assert(
    mobileLayout.siderWidth > 0 && mobileLayout.siderWidth <= 80,
    `mobile sider did not collapse as expected: ${JSON.stringify(mobileLayout)}`,
  )
  assert(
    mobileLayout.contentWidth >= mobileLayout.viewportWidth - mobileLayout.siderWidth - 1,
    `mobile content does not fill the available width: ${JSON.stringify(mobileLayout)}`,
  )
  assert(
    mobileLayout.contentRightGap <= 1,
    `mobile content leaves an unexpected right gap: ${JSON.stringify(mobileLayout)}`,
  )
  assert(
    mobileLayout.benchmarkWidth >= mobileLayout.contentWidth - 28,
    `mobile benchmark content is compressed: ${JSON.stringify(mobileLayout)}`,
  )
  assert(
    mobileLayout.benchmarkRightGap <= 14,
    `mobile benchmark leaves an unexpected right gap: ${JSON.stringify(mobileLayout)}`,
  )
  assert(
    mobileLayout.tableScrollWidth > mobileLayout.tableClientWidth,
    `mobile benchmark table lacks bounded horizontal scroll: ${JSON.stringify(mobileLayout)}`,
  )
  await page.screenshot({ path: 'evidence/phase-17/mobile-benchmark-viewport.png', fullPage: false })
  await page.screenshot({ path: 'evidence/phase-17/mobile-benchmark-verified.png', fullPage: true })

  const requestOrigins = [...new Set(requestUrls.map((value) => new URL(value).origin))]
  assert(
    requestOrigins.length === 1 && requestOrigins[0] === origin,
    `browser crossed the BFF boundary: ${requestOrigins.join(',')}`,
  )
  assert(badResponses.length === 0, `browser received error responses: ${badResponses.join('; ')}`)
  assert(consoleProblems.length === 0, `browser console problems: ${consoleProblems.join('; ')}`)

  return JSON.stringify({
    status: 'PASS',
    benchmark: 'VERIFIED_STRUCTURED_METRICS',
    request_origins: requestOrigins,
    request_count: requestUrls.length,
    console_problems: consoleProblems.length,
    bad_responses: badResponses.length,
    mobile_layout: mobileLayout,
  })
}
