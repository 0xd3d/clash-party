import { readFileSync } from 'node:fs'
import assert from 'node:assert/strict'
import { parse } from 'yaml'
import { compileUnifiedProfile, type UnifiedPlatform } from '../src/shared/unifiedProfile'
const cases = JSON.parse(readFileSync('tests/fixtures/unified-profiles.json', 'utf8')) as {
  name: string
  input: unknown
}[]
const results = JSON.parse(readFileSync(process.argv[2], 'utf8')) as {
  name: string
  platform: UnifiedPlatform
  rejected?: boolean
  profile?: unknown
  yaml?: string
}[]
assert.equal(results.length, cases.length * 3)
for (const row of results) {
  const fixture = cases.find((item) => item.name === row.name)
  assert.ok(fixture)
  if (row.rejected) assert.throws(() => compileUnifiedProfile(fixture.input, row.platform))
  else {
    const expected = compileUnifiedProfile(fixture.input, row.platform)
    assert.deepEqual(
      row.profile,
      expected,
      `${row.name}/${row.platform}: Swift and TypeScript diverged`
    )
    assert.equal(typeof row.yaml, 'string')
    assert.deepEqual(
      parse(row.yaml as string),
      expected,
      `${row.name}: mobile YAML serialization changed policy`
    )
  }
}
process.stdout.write(
  `${results.length} cross-platform contract cases passed; nodes, DNS and ordered rules agree.\n`
)
