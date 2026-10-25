import { readFileSync, readdirSync, copyFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { execFileSync, spawnSync } from 'node:child_process'
import path from 'node:path'
import { createReleasePlan } from './release-plan.mjs'
import { assertReleaseTag } from './release-tag.mjs'

const plan = JSON.parse(readFileSync('release-metadata/release-plan.json', 'utf8'))
const pkg = JSON.parse(readFileSync('package.json', 'utf8'))
if (JSON.stringify(plan) !== JSON.stringify(createReleasePlan(pkg.version, process.env)))
  throw new Error('Untrusted release plan')
if (process.env.GH_REPO !== process.env.GITHUB_REPOSITORY)
  throw new Error('Publication must target this fork')
const repository = process.env.GH_REPO
assertReleaseTag(repository, plan)
const root = 'release-assets'
const required = []
for (const arch of ['x64', 'arm64']) {
  required.push(
    `clash-party-windows-${plan.version}-${arch}-setup.exe`,
    `clash-party-windows-${plan.version}-${arch}-portable.7z`,
    `clash-party-macos-${plan.version}-${arch}.pkg`
  )
}
for (const name of required) {
  const bytes = readFileSync(path.join(root, name))
  const expected = readFileSync(path.join(root, `${name}.sha256`), 'utf8')
    .trim()
    .split(/\s+/)[0]
  if (createHash('sha256').update(bytes).digest('hex') !== expected)
    throw new Error(`Checksum mismatch: ${name}`)
}
for (const platform of ['win32', 'darwin'])
  for (const arch of ['x64', 'arm64']) {
    const manifest = JSON.parse(
      readFileSync(path.join(root, `build-manifest-${platform}-${arch}.json`), 'utf8')
    )
    if (
      manifest.version !== plan.version ||
      manifest.commit !== plan.commit ||
      manifest.platform !== platform ||
      manifest.arch !== arch ||
      manifest.nativeModuleLoaded !== true
    )
      throw new Error('Invalid package manifest')
  }
if (!plan.prerelease) copyFileSync('release-metadata/latest.yml', path.join(root, 'latest.yml'))
const assets = readdirSync(root).map((name) => path.join(root, name))
// Unique tags per workflow run avoid destructive overwrites and retain every successful build.
const existing = spawnSync(
  'gh',
  ['release', 'view', plan.tag, '-R', repository, '--json', 'tagName,assets,isDraft,isPrerelease'],
  { encoding: 'utf8' }
)
if (existing.status === 0) {
  const release = JSON.parse(existing.stdout)
  const names = new Set(release.assets.map((asset) => asset.name))
  if (release.tagName !== plan.tag || release.isPrerelease !== plan.prerelease)
    throw new Error('Existing release identity/channel conflict')
  if (release.isDraft) {
    execFileSync('gh', ['release', 'upload', plan.tag, '-R', repository, '--clobber', ...assets], {
      stdio: 'inherit'
    })
    assertReleaseTag(repository, plan)
    execFileSync(
      'gh',
      [
        'release',
        'edit',
        plan.tag,
        '-R',
        repository,
        '--verify-tag',
        '--draft=false',
        ...(plan.prerelease
          ? ['--prerelease=true', '--latest=false']
          : ['--prerelease=false', '--latest'])
      ],
      { stdio: 'inherit' }
    )
  } else if (
    required.some((name) => !names.has(name) || !names.has(`${name}.sha256`)) ||
    (!plan.prerelease && !names.has('latest.yml')) ||
    ['win32', 'darwin'].some((platform) =>
      ['x64', 'arm64'].some((arch) => !names.has(`build-manifest-${platform}-${arch}.json`))
    )
  )
    throw new Error('Existing release conflicts with the planned source/assets')
  console.log(
    'The completed release for this commit already exists; its immutable assets are preserved.'
  )
} else {
  assertReleaseTag(repository, plan)
  execFileSync(
    'gh',
    [
      'release',
      'create',
      plan.tag,
      '-R',
      repository,
      '--verify-tag',
      '--title',
      plan.tag,
      '--notes-file',
      'release-metadata/release-notes.md',
      ...(plan.prerelease ? ['--prerelease', '--latest=false'] : ['--latest']),
      ...assets
    ],
    { stdio: 'inherit' }
  )
}
