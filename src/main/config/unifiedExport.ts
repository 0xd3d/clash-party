import { mkdtemp, rm } from 'fs/promises'
import { tmpdir } from 'os'
import { isAbsolute, join, normalize } from 'path'
import { app, dialog } from 'electron'
import {
  createUnifiedProfile,
  UNIFIED_PROFILE_LIMIT,
  type UnifiedProfileExportResult
} from '../../shared/unifiedProfile'
import { atomicWriteFile } from '../utils/safeFile'
import { generateProfile } from '../core/factory'
import { convertMrsRuleset, getProfileConfig } from './profile'
import { getAppConfig } from './app'

type RecordValue = Record<string, unknown>

function record(value: unknown, context: string): RecordValue {
  if (!value || typeof value !== 'object' || Array.isArray(value))
    throw new Error(`统一配置导出失败：${context} 不是对象`)
  return value as RecordValue
}

function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T
}

function portableRules(config: RecordValue): string[] {
  if (!Array.isArray(config.rules)) return []
  return config.rules.filter((rule): rule is string => typeof rule === 'string')
}

/** Convert cached MRS providers to inline providers so the same JSON works on iOS. */
async function makePortableConfig(
  config: unknown
): Promise<{ config: RecordValue; warnings: string[] }> {
  const portable = clone(record(config, '运行配置'))
  const warnings: string[] = []
  const providers = portable['rule-providers']
  if (!providers || typeof providers !== 'object' || Array.isArray(providers))
    return { config: portable, warnings }

  const converted = record(providers, '规则提供者')
  const next: RecordValue = {}
  for (const [name, raw] of Object.entries(converted)) {
    const provider = record(raw, `规则提供者 ${name}`)
    if (provider.format !== 'mrs') {
      next[name] = provider
      continue
    }
    if (typeof provider.path !== 'string' || typeof provider.behavior !== 'string')
      throw new Error(`统一配置导出失败：规则提供者 ${name} 缺少可转换的本地缓存`)
    const providerPath = normalize(provider.path)
    if (isAbsolute(providerPath) || providerPath === '..' || providerPath.startsWith('../'))
      throw new Error(`统一配置导出失败：规则提供者 ${name} 的缓存路径不在配置工作目录内`)
    let text: string
    try {
      text = await convertMrsRuleset(provider.path, provider.behavior)
    } catch {
      throw new Error(`统一配置导出失败：规则提供者 ${name} 无法转换为 iOS 可读格式`)
    }
    const payload = text
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter((line) => line && !line.startsWith('#'))
    if (!payload.length) throw new Error(`统一配置导出失败：规则提供者 ${name} 转换结果为空`)
    next[name] = { type: 'inline', behavior: provider.behavior, payload }
    warnings.push(`已将规则提供者“${name}”转换为跨平台内联规则`)
  }
  portable['rule-providers'] = next
  return { config: portable, warnings }
}

function revision(): string {
  const now = new Date()
  const stamp = now
    .toISOString()
    .replace(/[-:]/g, '')
    .replace(/\.\d{3}Z$/, 'Z')
  return `mac-export-${stamp}`
}

/** Export the effective active profile without touching the running core. */
export async function exportUnifiedProfile(): Promise<UnifiedProfileExportResult> {
  const appConfig = await getAppConfig()
  if (appConfig.operationMode === 'simple')
    throw new Error('统一配置导出需要标准模式；简易模式请先切换到标准模式')

  const { current } = await getProfileConfig(true)
  if (!current) throw new Error('统一配置导出失败：当前没有活动配置')

  const work = await mkdtemp(join(tmpdir(), 'clash-party-unified-'))
  const output = join(work, 'effective.yaml')
  try {
    const generated = await generateProfile(undefined, {
      profileId: current,
      outputPath: output,
      updateRuntimeConfig: false
    })
    const portableResult = await makePortableConfig(generated.runtimeConfig)
    const document = createUnifiedProfile(portableResult.config, revision())
    const text = `${JSON.stringify(document, null, 2)}\n`
    if (Buffer.byteLength(text, 'utf8') > UNIFIED_PROFILE_LIMIT)
      throw new Error('统一配置导出失败：文件超过 8 MiB 限制')

    const defaultPath = join(
      app.getPath('documents'),
      `clash-party-unified-${new Date().toISOString().slice(0, 10)}.json`
    )
    const { canceled, filePath } = await dialog.showSaveDialog({
      title: '导出三端通用配置',
      defaultPath,
      filters: [{ name: 'Clash Party unified JSON', extensions: ['json'] }],
      properties: ['createDirectory', 'showOverwriteConfirmation']
    })
    if (canceled || !filePath) return { canceled: true, warnings: portableResult.warnings }
    await atomicWriteFile(filePath, text, { encoding: 'utf8', mode: 0o600 })

    const processCount = portableRules(portableResult.config).filter((rule) =>
      /(?:^|[,(])PROCESS-(?:NAME|PATH|NAME-REGEX|PATH-REGEX),/i.test(rule)
    ).length
    const warnings = [...portableResult.warnings]
    if (processCount)
      warnings.push(`${processCount} 条进程规则仅在 macOS/Windows 生效，iOS 会安全跳过`)
    warnings.push('文件包含节点凭据，仅通过私有路径导入，不要上传到 GitHub 或公开 Release')
    return {
      canceled: false,
      path: filePath,
      revision: document.revision,
      warnings
    }
  } finally {
    // The temporary effective profile is never exposed or retained.
    await rm(work, { recursive: true, force: true }).catch(() => {})
  }
}
