import { existsSync, mkdirSync, readFileSync } from 'node:fs'
import { execFileSync } from 'node:child_process'
import path from 'node:path'
import { pathToFileURL } from 'node:url'
import { assertBinaryArchitecture } from './verify-package.mjs'

export function parseDeveloperEnvironment(text) {
  const env = {}
  for (const line of text.split(/\r?\n/)) {
    const separator = line.indexOf('=')
    if (separator > 0) env[line.slice(0, separator).toUpperCase()] = line.slice(separator + 1)
  }
  if (!env.PATH || !env.INCLUDE || !env.LIB)
    throw new Error('MSVC developer environment is incomplete')
  return env
}

export function windowsDeveloperInvocation(developerCommand, arch) {
  if (!['x64', 'arm64'].includes(arch)) throw new Error('Unsupported Windows guard architecture')
  if (!/^[A-Za-z]:\\/.test(developerCommand) || /[%!"\r\n&|<>^]/.test(developerCommand))
    throw new Error('Unsupported Visual Studio installation path')
  return {
    args: [
      '/d',
      '/v:off',
      '/s',
      '/c',
      `""${developerCommand}" -no_logo -arch=${arch} -host_arch=${arch} >nul && set"`
    ],
    // cmd.exe parses the /c command itself. Node's default argv quoting would escape these
    // quotes for a C runtime parser and turn a path with spaces into a different command.
    options: { windowsVerbatimArguments: true }
  }
}

export function windowsGuardCompilerArguments(arch, output) {
  if (!['x64', 'arm64'].includes(arch)) throw new Error('Unsupported Windows guard architecture')
  return [
    '/nologo',
    '/std:c++17',
    '/EHsc',
    '/O2',
    '/MT',
    '/W4',
    '/WX',
    '/utf-8',
    '/DUNICODE',
    '/D_UNICODE',
    '/DNOMINMAX',
    '/DWIN32_LEAN_AND_MEAN',
    '/D_WIN32_WINNT=0x0A00',
    path.resolve('integrations/windows-network-guard/main.cpp'),
    `/Fo:${path.join(path.dirname(output), 'network-guard.obj')}`,
    `/Fe:${output}`,
    '/link',
    '/Brepro',
    `/MACHINE:${arch === 'x64' ? 'X64' : 'ARM64'}`,
    'Fwpuclnt.lib',
    'Advapi32.lib',
    'Iphlpapi.lib',
    'Setupapi.lib',
    'Ole32.lib',
    'Rpcrt4.lib',
    'Ws2_32.lib'
  ]
}

export function buildWindowsNetworkGuard(arch = process.env.npm_config_arch || process.arch) {
  if (process.platform !== 'win32' || arch !== process.arch || !['x64', 'arm64'].includes(arch))
    throw new Error('Build the guard on a matching native Windows x64/ARM64 runner')
  const programFiles = process.env['ProgramFiles(x86)'] || process.env.ProgramFiles
  if (!programFiles) throw new Error('Cannot locate the Visual Studio installer')
  const vswhere = path.join(programFiles, 'Microsoft Visual Studio', 'Installer', 'vswhere.exe')
  if (!existsSync(vswhere))
    throw new Error('Visual Studio with the Windows SDK and C++ tools is required')
  const installation = execFileSync(
    vswhere,
    [
      '-latest',
      '-products',
      '*',
      '-requires',
      arch === 'arm64'
        ? 'Microsoft.VisualStudio.Component.VC.Tools.ARM64'
        : 'Microsoft.VisualStudio.Component.VC.Tools.x86.x64',
      '-property',
      'installationPath'
    ],
    { encoding: 'utf8' }
  ).trim()
  if (!installation) throw new Error('A Visual Studio C++ toolchain was not found')
  const developerCommand = path.join(installation, 'Common7', 'Tools', 'VsDevCmd.bat')
  // Only the trusted tool installation path enters cmd.exe. Repository/source paths are passed
  // directly to cl.exe as an argv array, including when the checkout path contains spaces.
  const invocation = windowsDeveloperInvocation(developerCommand, arch)
  const text = execFileSync(
    process.env.ComSpec || process.env.COMSPEC || 'cmd.exe',
    invocation.args,
    { ...invocation.options, encoding: 'utf8', maxBuffer: 4 * 1024 * 1024 }
  )
  const env = parseDeveloperEnvironment(text)
  const output = path.resolve('build/native/windows', arch, 'party.mihomo.network-guard.exe')
  mkdirSync(path.dirname(output), { recursive: true })
  execFileSync('cl.exe', windowsGuardCompilerArguments(arch, output), { env, stdio: 'inherit' })
  assertBinaryArchitecture(readFileSync(output), 'win32', arch)
  // This execution is deliberately limited to in-memory protocol and policy fixtures.
  const result = JSON.parse(execFileSync(output, ['--self-test'], { encoding: 'utf8' }))
  if (result.protocolVersion !== 1 || result.selfTest !== 'passed' || result.cases < 10)
    throw new Error('Native guard self-test failed')
  // The separate fixture executable exercises real Windows job inheritance, explicit breakaway,
  // parent-job termination and startup error capture. It cannot install filters or start IPC.
  const launchFixture = path.join(
    path.dirname(output),
    'launch fixture',
    'guard-launch-selftest.exe'
  )
  mkdirSync(path.dirname(launchFixture), { recursive: true })
  const launchArgs = windowsGuardCompilerArguments(arch, launchFixture).map((arg) => {
    if (arg === path.resolve('integrations/windows-network-guard/main.cpp'))
      return path.resolve('integrations/windows-network-guard/launch-selftest.cpp')
    if (arg.startsWith('/Fo:'))
      return `/Fo:${path.join(path.dirname(output), 'launch-selftest.obj')}`
    return arg
  })
  execFileSync('cl.exe', launchArgs, { env, stdio: 'inherit' })
  const launchResult = JSON.parse(
    execFileSync(launchFixture, [], { encoding: 'utf8', timeout: 30000 })
  )
  if (launchResult.launchSelfTest !== 'passed' || launchResult.cases !== 4)
    throw new Error('Native independent-launch regression failed')
  console.log(
    `Built Windows ${arch} guard; ${result.cases} policy and ${launchResult.cases} process/job checks passed.`
  )
  return output
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const args = process.argv.slice(2)
  if (args.length > 1 || (args[0] && !/^--(?:x64|arm64)$/.test(args[0])))
    throw new Error('Usage: node scripts/build-windows-network-guard.mjs [--x64|--arm64]')
  buildWindowsNetworkGuard(args[0]?.slice(2))
}
