import { execFileSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { parse } from 'yaml'

describe('native source and signing boundaries', () => {
  it('keeps local signing, both Geo caches, frameworks and device profiles out of Git', () => {
    for (const file of [
      'apps/ios/Config/Local.xcconfig',
      'apps/ios/Vendor/MihomoMobile.xcframework/Info.plist',
      'apps/ios/.derived-data-device/Build/Products/App.app/embedded.mobileprovision',
      'apps/ios/ClashParty/Resources/GeoResources/geosite.dat',
      'apps/ios/ClashPartyTunnel/Resources/GeoResources/geosite.dat',
      'apps/ios/ClashPartyTunnel/Resources/GeoResources/country.mmdb',
      'build/native/party.mihomo.dns-guard'
    ])
      expect(() =>
        execFileSync('git', ['check-ignore', '--quiet', '--no-index', '--', file])
      ).not.toThrow()
  })
  it('uses shared configurable identifiers without publishing a signing team', () => {
    const project = readFileSync('apps/ios/ClashParty.xcodeproj/project.pbxproj', 'utf8')
    expect(project).not.toMatch(/DEVELOPMENT_TEAM\s*=\s*[^;\n]+;/)
    expect(project).toContain('$(CLASH_PARTY_IOS_BUNDLE_ID)')
    for (const resource of ['ClashParty', 'ClashPartyTunnel']) {
      const entitlement = readFileSync(
        `apps/ios/${resource}/Resources/${resource}.entitlements`,
        'utf8'
      )
      expect(entitlement).toContain('$(CLASH_PARTY_IOS_APP_GROUP)')
    }
  })
  it('keeps the iOS workflow unsigned and separate from device installation', () => {
    const text = readFileSync('.github/workflows/ios.yml', 'utf8')
    const workflow = parse(text)
    expect(workflow.permissions).toEqual({ contents: 'read' })
    const commands = workflow.jobs['unsigned-build'].steps
      .map((step: { run?: string }) => step.run ?? '')
      .join('\n')
    expect(commands).toContain('CODE_SIGNING_ALLOWED=NO')
    expect(commands).not.toMatch(/devicectl|simctl\s+boot|build-install-run-device|\bsudo\b/)
  })
})
