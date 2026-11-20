import { mkdirSync } from 'node:fs'
import { execFileSync } from 'node:child_process'
import os from 'node:os'
import path from 'node:path'

if (process.platform !== 'darwin') {
  console.log('Skipping macOS boot leak guard build on non-macOS CI')
  process.exit(0)
}

const arch = process.env.npm_config_arch || process.arch
if (!['arm64', 'x64'].includes(arch) || arch !== process.arch) {
  throw new Error('Build the boot leak guard on a matching native macOS runner')
}
const output = path.resolve('build/native/party.mihomo.boot-guard')
mkdirSync(path.dirname(output), { recursive: true })
execFileSync(
  '/usr/bin/xcrun',
  [
    'swiftc',
    '-O',
    '-module-cache-path',
    path.join(os.tmpdir(), 'clash-party-boot-leak-guard-swift-cache'),
    '-target',
    `${arch === 'x64' ? 'x86_64' : 'arm64'}-apple-macos12.0`,
    'integrations/macos-boot-leak-guard/policy.swift',
    'integrations/macos-boot-leak-guard/main.swift',
    '-o',
    output
  ],
  { stdio: 'inherit' }
)
execFileSync('/usr/bin/codesign', ['--force', '--sign', '-', '--options', 'runtime', output], {
  stdio: 'inherit'
})
execFileSync(output, ['--self-test'], { stdio: 'inherit' })
console.log(`Built boot leak guard: ${output}`)
