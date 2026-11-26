import { describe, expect, it } from 'vitest'
import { deriveTrafficReadiness } from '../../shared/trafficReadiness'

describe('deriveTrafficReadiness', () => {
  it('returns idle without a live core', () => {
    expect(
      deriveTrafficReadiness({
        corePid: undefined,
        corePhase: 'ready',
        tunEnabled: true,
        networkProtection: true,
        report: null
      })
    ).toBe('idle')
  })

  it('returns ready when guards and TUN pass', () => {
    expect(
      deriveTrafficReadiness({
        corePid: 42,
        corePhase: 'ready',
        tunEnabled: true,
        networkProtection: true,
        report: {
          platform: 'darwin',
          source: 'applied',
          findings: [
            { id: 'tunEnabled', level: 'pass' },
            { id: 'networkGuard', level: 'pass' },
            { id: 'macDNSGuard', level: 'pass' },
            { id: 'dnsEnabled', level: 'pass' },
            { id: 'dnsProxyOutbound', level: 'pass' }
          ]
        }
      })
    ).toBe('ready')
  })
})
