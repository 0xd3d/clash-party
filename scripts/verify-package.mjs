import { existsSync, readFileSync, writeFileSync, readdirSync } from 'node:fs'
import { execFileSync } from 'node:child_process'
import { createRequire } from 'node:module'
import { pathToFileURL } from 'node:url'
import path from 'node:path'
import os from 'node:os'

export function assertBinaryArchitecture(bytes, platform, arch) {
  if (platform === 'win32') {
    if (bytes.length < 64 || bytes.toString('ascii', 0, 2) !== 'MZ')
      throw new Error('Not a PE binary')
    const pe = bytes.readUInt32LE(60)
    if (pe + 6 > bytes.length || bytes.toString('ascii', pe, pe + 4) !== 'PE\0\0')
      throw new Error('Invalid PE header')
    if (bytes.readUInt16LE(pe + 4) !== { x64: 0x8664, arm64: 0xaa64 }[arch])
      throw new Error('PE architecture mismatch')
  } else if (platform === 'darwin') {
    if (bytes.length < 8 || bytes.readUInt32LE(0) !== 0xfeedfacf)
      throw new Error('Not a thin 64-bit Mach-O')
    if (bytes.readUInt32LE(4) !== { x64: 0x1000007, arm64: 0x100000c }[arch])
      throw new Error('Mach-O architecture mismatch')
  } else throw new Error('Unsupported package platform')
}

export function assertDesktopArchivePaths(paths) {
  if (paths.some((name) => /^[\\/]*(?:apps|modules)(?:[\\/]|$)/.test(name)))
    throw new Error('Native mobile sources or build artifacts leaked into the desktop package')
}

export function packagedAppDirectory(platform, arch) {
  if (platform === 'darwin')
    return arch === 'x64' ? 'dist/mac/Clash Party.app' : 'dist/mac-arm64/Clash Party.app'
  if (platform === 'win32') return arch === 'x64' ? 'dist/win-unpacked' : 'dist/win-arm64-unpacked'
  throw new Error('Unsupported package platform')
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const hostOnly = process.argv[2] === '--host'
  const [platform, arch] = process.argv.slice(hostOnly ? 3 : 2)
  if (process.platform !== platform || process.arch !== arch)
    throw new Error('A matching native OS/architecture runner is required')
  if (!hostOnly) {
    const require = createRequire(import.meta.url)
    const asar = require('@electron/asar')
    const app = packagedAppDirectory(platform, arch)
    const resources = path.resolve(app, platform === 'darwin' ? 'Contents/Resources' : 'resources')
    const executable = path.resolve(
      app,
      platform === 'darwin' ? 'Contents/MacOS/Clash Party' : 'Clash Party.exe'
    )
    const binding =
      platform === 'darwin' ? `sysproxy.darwin-${arch}.node` : `sysproxy.win32-${arch}-msvc.node`
    const binaries = [
      executable,
      ...['mihomo', 'mihomo-alpha', 'mihomo-smart'].map((name) =>
        path.join(resources, 'sidecar', name + (platform === 'win32' ? '.exe' : ''))
      ),
      path.join(resources, 'sidecar', binding)
    ]
    if (platform === 'darwin')
      binaries.push(
        path.join(resources, 'files/party.mihomo.helper'),
        path.join(resources, 'files/party.mihomo.dns-guard')
      )
    for (const binary of binaries) assertBinaryArchitecture(readFileSync(binary), platform, arch)
    const archive = path.join(resources, 'app.asar')
    assertDesktopArchivePaths(asar.listPackage(archive))
    const pkg = JSON.parse(asar.extractFile(archive, 'package.json').toString())
    const main = asar.extractFile(archive, path.normalize(pkg.main)).toString()
    for (const marker of [
      'system-dns-state.json',
      'inspectPrivacyProtection',
      'disable_non_proxied_udp',
      process.env.CLASH_PARTY_UPDATE_REPOSITORY
    ]) {
      if (!marker || !main.includes(marker))
        throw new Error(`Missing package capability: ${marker}`)
    }
    const extension = JSON.parse(
      readFileSync(path.join(resources, 'integrations/webrtc-guard/manifest.json'), 'utf8')
    )
    if (
      JSON.stringify(extension.permissions) !== '["privacy"]' ||
      extension.host_permissions?.length
    )
      throw new Error('Unexpected browser permissions')
    for (const file of ['background.mjs', 'controller.mjs', 'popup.html', 'LICENSE'])
      if (!existsSync(path.join(resources, 'integrations/webrtc-guard', file)))
        throw new Error('Incomplete browser tool')
    if (
      platform === 'darwin' &&
      !existsSync(path.join(resources, 'integrations/macos-dns-guard/guard.sh'))
    )
      throw new Error('Missing optional macOS DNS guard')
    if (platform === 'darwin')
      execFileSync('codesign', ['--verify', '--deep', '--strict', app], { stdio: 'inherit' })
    const smoke = `process.chdir(${JSON.stringify(os.tmpdir())});process.resourcesPath=${JSON.stringify(resources)};const m=require(${JSON.stringify(path.join(resources, 'app.asar/node_modules/sysproxy-rs'))});for(const key of ['getSystemProxy','setSystemProxy','triggerManualProxy','triggerAutoProxy'])if(typeof m[key]!=='function')throw Error(key);console.log('packaged-native-module-ok')`
    const output = execFileSync(executable, ['-e', smoke], {
      env: { ...process.env, ELECTRON_RUN_AS_NODE: '1' },
      encoding: 'utf8',
      timeout: 30000
    })
    if (!output.includes('packaged-native-module-ok'))
      throw new Error('Packaged native module failed to load')
    const files = readdirSync('dist').filter((name) =>
      /(?:\.pkg|setup\.exe|portable\.7z)$/.test(name)
    )
    if (platform === 'win32') {
      const portable = files.find((name) => name.endsWith('portable.7z'))
      if (!portable) throw new Error('Portable archive missing')
      const listing = execFileSync('7z', ['l', '-ba', path.join('dist', portable)], {
        encoding: 'utf8'
      })
      if (!listing.split(/\r?\n/).some((line) => /(?:^|\s)PORTABLE$/.test(line.trim())))
        throw new Error('Portable marker missing from archive')
      execFileSync('7z', ['t', path.join('dist', portable)], { stdio: 'inherit' })
    }
    if (files.length !== (platform === 'darwin' ? 1 : 2))
      throw new Error('Missing installer/archive')
    writeFileSync(
      `dist/build-manifest-${platform}-${arch}.json`,
      JSON.stringify(
        {
          commit: process.env.GITHUB_SHA,
          version: pkg.version,
          platform,
          arch,
          nativeModuleLoaded: true,
          binaries: binaries.map((name) => path.basename(name)),
          artifacts: files,
          networkCertification: false
        },
        null,
        2
      ) + '\n'
    )
  }
}
