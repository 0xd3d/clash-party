import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { adaptUnifiedProfile, compileUnifiedProfile, unifiedPlatforms } from './unifiedProfile'
const cases = JSON.parse(readFileSync('tests/fixtures/unified-profiles.json', 'utf8')) as {
  name: string
  input: unknown
  validPlatforms: string[]
}[]
describe('portable configuration contract', () => {
  for (const fixture of cases)
    for (const platform of unifiedPlatforms) {
      it(`${fixture.name}: ${platform}`, () => {
        if (fixture.validPlatforms.includes(platform)) {
          const before = JSON.stringify(fixture.input)
          const result = compileUnifiedProfile(fixture.input, platform)
          expect((result.rules as string[]).at(-1)).toBe('MATCH,Overseas')
          expect(result.dns).toEqual((fixture.input as { common: { dns: unknown } }).common.dns)
          expect(JSON.stringify(fixture.input)).toBe(before)
        } else
          expect(() => compileUnifiedProfile(fixture.input, platform)).toThrow('Unified profile:')
      })
    }
  it('preserves ordinary YAML and rejects envelopes encoded differently on desktop and mobile', () => {
    const regular = { proxies: [] }
    expect(adaptUnifiedProfile('proxies: []', regular, 'darwin')).toBe(regular)
    expect(() =>
      adaptUnifiedProfile('format: clash-party-unified', cases[0].input, 'darwin')
    ).toThrow('JSON syntax')
    expect(() =>
      adaptUnifiedProfile(JSON.stringify(cases[0].input), cases[0].input, 'linux')
    ).toThrow('platform linux')
  })
})
