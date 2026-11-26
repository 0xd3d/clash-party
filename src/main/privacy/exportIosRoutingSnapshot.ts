import { mkdir, readFile, rename, writeFile } from 'fs/promises'
import path from 'path'
import { dialog, type SaveDialogOptions } from 'electron'
import { getAppConfig } from '../config'
import { getProfileConfig } from '../config/profile'
import { getCurrentCorePID } from '../core/manager'
import { getAxios } from '../core/mihomoApi'
import { mihomoCorePath, mihomoWorkConfigPath } from '../utils/dirs'
import { parse } from '../utils/yaml'
import {
  buildIosRoutingSnapshotFromSources,
  type ExportConfig
} from './exportIosRoutingSnapshotCore'

type ProxyRecord = { now?: string }
type ProxiesResponse = { proxies: Record<string, ProxyRecord> }

export type { IosRoutingSnapshot } from './exportIosRoutingSnapshotCore'
export { buildIosRoutingSnapshotFromSources } from './exportIosRoutingSnapshotCore'

export async function exportIosRoutingSnapshot(
  options?: SaveDialogOptions
): Promise<string | null> {
  if (!getCurrentCorePID()) {
    throw new Error('Desktop core is not running; start the core before exporting iOS rules.')
  }

  const [{ current }, appConfig] = await Promise.all([getProfileConfig(), getAppConfig()])
  const configPath = mihomoWorkConfigPath(current)
  const config = parse<ExportConfig>(await readFile(configPath, 'utf8'))
  const instance = await getAxios()
  const proxies = (await instance.get<never, ProxiesResponse>('/proxies')).proxies
  const coreName = appConfig.core ?? 'mihomo'
  const mihomoBinary = mihomoCorePath(coreName)
  const snapshot = await buildIosRoutingSnapshotFromSources(
    config,
    proxies,
    path.dirname(configPath),
    mihomoBinary
  )

  const dialogResult = await dialog.showSaveDialog({
    title: 'Export iOS routing snapshot',
    defaultPath: 'clashparty-ios-routing-snapshot.json',
    filters: [{ name: 'JSON', extensions: ['json'] }],
    ...options
  })
  if (dialogResult.canceled || !dialogResult.filePath) {
    return null
  }

  const destination = dialogResult.filePath
  await mkdir(path.dirname(destination), { recursive: true })
  const temporary = destination + '.tmp'
  await writeFile(temporary, JSON.stringify(snapshot, null, 2) + '\n', 'utf8')
  await rename(temporary, destination)
  return destination
}
