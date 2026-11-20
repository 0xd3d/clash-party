import { readFile, writeFile } from 'fs/promises'
import path from 'path'
import { getAppConfig, getControledMihomoConfig } from '../config'
import { getRuntimeConfig } from './factory'
import { dataDir } from '../utils/dirs'
import { atomicWriteFile } from '../utils/safeFile'
import {
  collectLiteralProxyServerIPs,
  parseBootLeakPolicyFile,
  type BootLeakPolicySnapshot
} from './bootLeakPolicy'
import { DEFAULT_MIHOMO_PORTS } from '../../shared/appConfig'

const policyFileName = 'boot-leak-policy.json'

export function bootLeakPolicyPath(): string {
  return path.join(dataDir(), policyFileName)
}

export async function readBootLeakPolicyFile(): Promise<BootLeakPolicySnapshot | null> {
  try {
    return parseBootLeakPolicyFile(await readFile(bootLeakPolicyPath(), 'utf8'))
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null
    throw error
  }
}

export async function buildBootLeakPolicySnapshot(): Promise<BootLeakPolicySnapshot> {
  const [appConfig, controlled, runtime] = await Promise.all([
    getAppConfig(),
    getControledMihomoConfig(),
    getRuntimeConfig()
  ])
  const mixedPort = controlled['mixed-port'] ?? DEFAULT_MIHOMO_PORTS.mixed
  const dnsSection = controlled.dns
  const dnsListen =
    typeof dnsSection === 'object' && dnsSection && typeof dnsSection.listen === 'string'
      ? dnsSection.listen.split(':').pop()
      : undefined
  const dnsListenPort = dnsListen && /^\d+$/.test(dnsListen) ? Number(dnsListen) : 1053
  const proxies = Array.isArray(runtime.proxies) ? runtime.proxies : []
  return {
    disabled: appConfig.macBootLeakGuard === false,
    mixedPort,
    dnsListenPort,
    proxyServers: collectLiteralProxyServerIPs(proxies)
  }
}

export async function syncBootLeakPolicy(): Promise<void> {
  if (process.platform !== 'darwin') return
  const snapshot = await buildBootLeakPolicySnapshot()
  await atomicWriteFile(
    bootLeakPolicyPath(),
    JSON.stringify({ version: 1, ...snapshot }, null, 2),
    {
      mode: 0o644
    }
  )
}

export async function touchBootLeakPolicyDisabled(disabled: boolean): Promise<void> {
  if (process.platform !== 'darwin') return
  let current: BootLeakPolicySnapshot
  try {
    current = (await readBootLeakPolicyFile()) ?? (await buildBootLeakPolicySnapshot())
  } catch {
    current = await buildBootLeakPolicySnapshot()
  }
  current.disabled = disabled
  await writeFile(bootLeakPolicyPath(), JSON.stringify({ version: 1, ...current }, null, 2), {
    encoding: 'utf8',
    mode: 0o644
  })
}
