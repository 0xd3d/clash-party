import { readFileSync, writeFileSync, mkdirSync } from 'node:fs'
import { pathToFileURL } from 'node:url'

export function createReleasePlan(baseVersion, env) {
  if (!/^\d+\.\d+\.\d+$/.test(baseVersion)) throw new Error('Expected a numeric base version')
  if (!/^[a-f0-9]{40}$/.test(env.GITHUB_SHA ?? ''))
    throw new Error('Expected the full source commit')
  const tagged = (env.GITHUB_REF ?? '').startsWith('refs/tags/')
  const tag = tagged ? env.GITHUB_REF.slice('refs/tags/'.length) : null
  if (tagged && tag !== `v${baseVersion}`)
    throw new Error('Stable tag must match package.json version')
  for (const key of ['GITHUB_RUN_NUMBER', 'GITHUB_RUN_ATTEMPT']) {
    if (!/^[1-9]\d*$/.test(env[key] ?? '')) throw new Error(`Invalid ${key}`)
  }
  const version = tagged ? baseVersion : `${baseVersion}-fork.${env.GITHUB_RUN_NUMBER}`
  return { version, tag: `v${version}`, commit: env.GITHUB_SHA, prerelease: !tagged }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const pkg = JSON.parse(readFileSync('package.json', 'utf8'))
  if (process.argv.includes('--apply')) {
    const plan = JSON.parse(readFileSync('release-metadata/release-plan.json', 'utf8'))
    const expected = createReleasePlan(pkg.version, process.env)
    if (JSON.stringify(plan) !== JSON.stringify(expected))
      throw new Error('Release plan does not match this workflow/commit')
    pkg.version = plan.version
    writeFileSync('package.json', JSON.stringify(pkg, null, 2) + '\n')
  } else {
    const plan = createReleasePlan(pkg.version, process.env)
    mkdirSync('release-metadata', { recursive: true })
    writeFileSync('release-metadata/release-plan.json', JSON.stringify(plan, null, 2) + '\n')
    const notes = `Source: ${plan.commit}\n\nNative Windows x64/ARM64 and macOS Intel/Apple Silicon builds.\n\nChecks: review, unit tests, packaged architecture, resources and Electron native module loading. This is not Windows hardware network/leak certification.\n\nWindows installers are unsigned. macOS app signatures are ad-hoc; PKGs are unsigned and not notarized.\n\nPrivate node credentials and operating policies are not embedded.\n\n${plan.prerelease ? 'Automatic preview build. Existing stable updates are not replaced.' : 'Stable tagged build.'}\n`
    writeFileSync('release-metadata/release-notes.md', notes)
    // JSON is valid YAML, and the existing updater consumes version/changelog.
    if (!plan.prerelease)
      writeFileSync(
        'release-metadata/latest.yml',
        JSON.stringify({ version: plan.version, changelog: notes }, null, 2) + '\n'
      )
    console.log(JSON.stringify(plan))
  }
}
