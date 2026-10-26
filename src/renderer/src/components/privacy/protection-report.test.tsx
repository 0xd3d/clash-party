import React, { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it, vi } from 'vitest'
import zh from '../../locales/zh-CN.json'
import type { PrivacyProtectionReport } from '../../../../shared/privacyAudit'
import ProtectionReport from './protection-report'
vi.stubGlobal('React', React)
vi.mock('@heroui/react', () => ({
  Chip: ({ children }: { children: React.ReactNode }) => createElement('span', null, children)
}))
vi.mock('react-i18next', () => ({
  useTranslation: () => ({
    t: (key: string, options?: { count?: number; defaultValue?: string }) =>
      ((zh[key as keyof typeof zh] as string) ?? options?.defaultValue ?? key).replace(
        '{{count}}',
        String(options?.count ?? '')
      )
  })
}))
const report: PrivacyProtectionReport = {
  platform: 'darwin',
  source: 'applied',
  findings: [
    { id: 'tunEnabled', level: 'pass' },
    { id: 'dnsEncrypted', level: 'pass' },
    { id: 'macDNSGuard', level: 'pass' },
    { id: 'networkGuard', level: 'pass' },
    { id: 'udpRouting', level: 'pass' }
  ],
  diagnostics: [{ id: 'dnsGuard', value: 'PF corePid=123' }]
}
describe('protection status disclosure', () => {
  it('shows four normal groups with collapsed checks and folded native details', () => {
    const html = renderToStaticMarkup(createElement(ProtectionReport, { report }))
    for (const label of ['系统流量接管', 'DNS 防护', '隧道异常后的公网断网保护', '公网 UDP 策略'])
      expect(html).toContain(label)
    expect(html).not.toContain('<details open')
    expect(html.indexOf('诊断详情')).toBeLessThan(html.indexOf('PF corePid=123'))
    expect(html).not.toMatch(/无泄漏|全部安全/)
  })
  it('shows a pending address and its remedy outside the collapsed normal checks', () => {
    const r = {
      ...report,
      findings: [
        ...report.findings,
        { id: 'routePublicExclusion', level: 'warning', detail: '203.0.113.0/24' } as const
      ]
    }
    const html = renderToStaticMarkup(createElement(ProtectionReport, { report: r }))
    const traffic = html.slice(0, html.indexOf('</section>'))
    expect(traffic.indexOf('203.0.113.0/24')).toBeLessThan(traffic.indexOf('<details>'))
    expect(traffic).toContain('删除或收窄')
    expect(traffic).toContain('需要处理或确认')
  })
})
