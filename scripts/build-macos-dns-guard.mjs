import { mkdirSync } from 'node:fs'
import { execFileSync } from 'node:child_process'
import os from 'node:os'
import path from 'node:path'

if (process.platform !== 'darwin') throw new Error('The DNS guard is macOS-only')
const arch = process.env.npm_config_arch || process.arch
if (!['arm64', 'x64'].includes(arch) || arch !== process.arch)
  throw new Error('Build the DNS guard on a matching native macOS runner')
const output = path.resolve('build/native/party.mihomo.dns-guard')
mkdirSync(path.dirname(output), { recursive: true })
execFileSync(
  '/usr/bin/xcrun',
  [
    'swiftc',
    '-O',
    '-module-cache-path',
    path.join(os.tmpdir(), 'clash-party-dns-guard-swift-cache'),
    '-target',
    `${arch === 'x64' ? 'x86_64' : 'arm64'}-apple-macos12.0`,
    '-framework',
    'Security',
    'integrations/macos-dns-guard-native/main.swift',
    '-o',
    output
  ],
  { stdio: 'inherit' }
)
execFileSync('/usr/bin/codesign', ['--force', '--sign', '-', '--options', 'runtime', output], {
  stdio: 'inherit'
})
// This mode validates only in-memory fixtures, never PF, DNS, root state or installation.
execFileSync(output, ['--self-test'], { stdio: 'inherit' })
console.log(`Built fixed-purpose DNS guard: ${output}`)
