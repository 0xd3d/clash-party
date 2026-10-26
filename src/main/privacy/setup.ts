import { access, cp, mkdir, mkdtemp, rm } from 'node:fs/promises'
import { constants } from 'node:fs'
import { createHash, randomUUID } from 'node:crypto'
import { isDeepStrictEqual } from 'node:util'
import path from 'node:path'
import os from 'node:os'
import { BrowserWindow } from 'electron'
import { getAppConfig, patchAppConfig } from '../config/app'
import { runtimeConfigWriteQueue } from '../config/runtimeConfigQueue'
import {
  getStoredControledMihomoConfig,
  persistProtectionSetupControl
} from '../config/controledMihomo'
import { getProfileConfig, getProfileItem, getProfileStr } from '../config/profile'
import { generateProfile } from '../core/factory'
import { checkProfileConfig, getAppliedCoreConfig, restartCore } from '../core/manager'
import { requireWindowsTunPrivileges } from '../core/permissions'
import { macDNSGuardPath } from '../core/macDNSGuard'
import { protectionTarget } from '../core/networkProtectionPolicy'
import { dataDir, mihomoWorkDir, mihomoProfileWorkDir } from '../utils/dirs'
import { atomicWriteFile, WriteQueue } from '../utils/safeFile'
import { stringify } from '../utils/yaml'
import type { ProtectionSetupPreview, ProtectionSetupResult } from '../../shared/protectionSetup'
import { planProtectionSetup } from './setupPlan'
import { executeProtectionSetup } from './setupTransaction'
import { inspectPrivacyProtection } from './index'

const queue = new WriteQueue()
const previews = new Map<string, { fingerprint: string; expires: number }>()
const canonical = (value: unknown): unknown =>
  Array.isArray(value)
    ? value.map(canonical)
    : value && typeof value === 'object'
      ? Object.fromEntries(
          Object.entries(value)
            .sort(([a], [b]) => a.localeCompare(b))
            .map(([key, item]) => [key, canonical(item)])
        )
      : value
const fingerprint = (value: unknown): string =>
  createHash('sha256')
    .update(JSON.stringify(canonical(value)))
    .digest('hex')

async function snapshot() {
  const [appValue, controlValue, profiles] = await Promise.all([
    getAppConfig(),
    getStoredControledMihomoConfig(),
    getProfileConfig(true)
  ])
  const app = structuredClone(appValue),
    control = structuredClone(controlValue)
  const id = profiles.current
  if (!id || id === 'default')
    throw new Error('Import and select a complete profile before protection setup')
  const [item, source] = await Promise.all([getProfileItem(id), getProfileStr(id)])
  const plan = planProtectionSetup(app, control, process.platform)
  const candidateApp = { ...app, ...plan.appPatch }
  const directory = await mkdtemp(path.join(os.tmpdir(), 'clash-protection-setup-'))
  try {
    const file = path.join(directory, 'config.yaml')
    const generated = await generateProfile(structuredClone(plan.control), {
      profileId: id,
      appConfig: candidateApp,
      outputPath: file,
      updateRuntimeConfig: false
    })
    const runtime = generated.runtimeConfig
    const work = app.diffWorkDir ? mihomoProfileWorkDir(id) : mihomoWorkDir()
    // Give -t its own cache/work directory, never the running core's database.
    for (const name of [
      'rulesets',
      'Country.mmdb',
      'geoip.dat',
      'geosite.dat',
      'ASN.mmdb',
      'Model.bin'
    ]) {
      const origin = path.join(work, name)
      try {
        await access(origin)
      } catch {
        continue
      }
      await cp(origin, path.join(directory, name), { recursive: true })
    }
    await checkProfileConfig(file, app.core, item?.ageSecretKey, {
      workDir: directory,
      timeoutMs: 10_000
    })
    plan.appPatch.networkProtectionProxyGroup = protectionTarget(runtime)
    const settingsChanged =
      !isDeepStrictEqual(control, plan.control) ||
      Object.entries(plan.appPatch).some(([key, value]) => !isDeepStrictEqual(app[key], value))
    return {
      id,
      item,
      source,
      profiles,
      app,
      control,
      plan,
      runtime,
      settingsChanged,
      fingerprint: fingerprint({ id, source, app, control, runtime })
    }
  } finally {
    await rm(directory, { recursive: true, force: true })
  }
}
type Snapshot = Awaited<ReturnType<typeof snapshot>>

/** Builds and checks a hypothetical candidate; no settings, core or native guard changes. */
export async function previewProtectionSetup(): Promise<ProtectionSetupPreview> {
  const value = await runtimeConfigWriteQueue.run(snapshot)
  for (const [token, entry] of previews) if (entry.expires < Date.now()) previews.delete(token)
  while (previews.size >= 8) {
    const oldest = previews.keys().next().value
    if (!oldest) break
    previews.delete(oldest)
  }
  const token = randomUUID()
  previews.set(token, { fingerprint: value.fingerprint, expires: Date.now() + 120_000 })
  const proxyGroup = value.plan.appPatch.networkProtectionProxyGroup
  if (!proxyGroup) throw new Error('Protection target was not established')
  return {
    token,
    profileName: value.item?.name || value.id,
    proxyGroup,
    changes: value.plan.changes
  }
}

async function backup(value: Snapshot): Promise<string> {
  const parent = path.join(dataDir(), 'privacy-setup-backups')
  await mkdir(parent, { recursive: true, mode: 0o700 })
  const directory = await mkdtemp(path.join(parent, 'setup-'))
  for (const [name, content] of [
    ['app.yaml', stringify(value.app)],
    ['control.yaml', stringify(value.control)],
    ['profiles.yaml', stringify(value.profiles)],
    ['active-profile.yaml', value.source]
  ])
    await atomicWriteFile(path.join(directory, name), content, { encoding: 'utf8', mode: 0o600 })
  return directory
}

/** User-confirmed setup; does not run automatically when a profile is imported. */
export async function applyProtectionSetup(token: string): Promise<ProtectionSetupResult> {
  if (typeof token !== 'string' || token.length > 64)
    throw new Error('Invalid protection setup preview')
  return queue.run(async () => {
    const entry = previews.get(token)
    previews.delete(token)
    if (!entry || entry.expires < Date.now())
      throw new Error('Protection setup preview expired; preview again')
    try {
      return await executeProtectionSetup({
        withSettingsLock: (operation) => runtimeConfigWriteQueue.run(operation),
        validate: async () => {
          const value = await snapshot()
          if (value.fingerprint !== entry.fingerprint)
            throw new Error('Configuration changed; preview protection setup again')
          return value
        },
        alreadyVerified: async (value) => {
          if (
            value.settingsChanged ||
            fingerprint(getAppliedCoreConfig()) !== fingerprint(value.runtime)
          )
            return null
          const report = await inspectPrivacyProtection()
          const required =
            process.platform === 'darwin' ? ['macDNSGuard', 'networkGuard'] : ['networkGuard']
          if (
            report.source !== 'applied' ||
            !required.every((id) => report.findings.some((f) => f.id === id && f.level === 'pass'))
          )
            return null
          return { backupPath: null, restarted: false, verified: true, report }
        },
        checkPermissions: async (value) => {
          await requireWindowsTunPrivileges(value.runtime)
          if (process.platform === 'darwin') await access(macDNSGuardPath, constants.X_OK)
        },
        backup,
        commit: async (value) => {
          await persistProtectionSetupControl(value.plan.control, value.control)
          try {
            await patchAppConfig(value.plan.appPatch)
          } catch (error) {
            // No guard/start has happened yet. CAS prevents undoing concurrent user edits.
            await persistProtectionSetupControl(value.control, value.plan.control)
            throw error
          }
        },
        restart: restartCore,
        verify: inspectPrivacyProtection
      })
    } finally {
      for (const window of BrowserWindow.getAllWindows()) {
        for (const event of [
          'appConfigUpdated',
          'controledMihomoConfigUpdated',
          'groupsUpdated',
          'rulesUpdated'
        ])
          window.webContents.send(event)
      }
    }
  })
}
