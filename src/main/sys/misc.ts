import { exec, execFile, spawn } from 'child_process'
import { readFile } from 'fs/promises'
import path from 'path'
import { promisify } from 'util'
import { app, dialog, nativeImage, nativeTheme, shell } from 'electron'
import i18next from 'i18next'
import {
  dataDir,
  exePath,
  mihomoCorePath,
  overridePath,
  profilePath,
  resourcesDir
} from '../utils/dirs'
import { checkAdminPrivileges } from '../core/admin'
import { configureFirewallRules } from './firewall'

export function getFilePath(
  ext: string[],
  title?: string,
  filterName?: string
): string[] | undefined {
  return dialog.showOpenDialogSync({
    title: title || i18next.t('common.dialog.selectSubscriptionFile'),
    filters: [{ name: filterName || `${ext} file`, extensions: ext }],
    properties: ['openFile']
  })
}

export async function readTextFile(filePath: string): Promise<string> {
  return await readFile(filePath, 'utf8')
}

export async function readImageFileDataURL(filePath: string): Promise<string> {
  const ext = path.extname(filePath).toLowerCase()
  if (['.ico', '.icns'].includes(ext)) {
    const icon = nativeImage.createFromPath(filePath)
    if (!icon.isEmpty()) return icon.toDataURL()
  }

  const mimeType =
    ext === '.jpg' || ext === '.jpeg'
      ? 'image/jpeg'
      : ext === '.webp'
        ? 'image/webp'
        : ext === '.gif'
          ? 'image/gif'
          : ext === '.ico'
            ? 'image/x-icon'
            : ext === '.icns'
              ? 'image/icns'
              : 'image/png'
  const data = await readFile(filePath)

  return `data:${mimeType};base64,${data.toString('base64')}`
}

export function openFile(type: 'profile' | 'override', id: string, ext?: 'yaml' | 'js'): void {
  if (type === 'profile') {
    shell.openPath(profilePath(id))
  }
  if (type === 'override') {
    shell.openPath(overridePath(id, ext || 'js'))
  }
}

export async function openUWPTool(): Promise<void> {
  const execPromise = promisify(exec)
  const execFilePromise = promisify(execFile)
  const uwpToolPath = path.join(resourcesDir(), 'files', 'enableLoopback.exe')

  const isAdmin = await checkAdminPrivileges()

  if (!isAdmin) {
    const escapedPath = uwpToolPath.replace(/'/g, "''")
    const command = `powershell -NoProfile -Command "Start-Process -FilePath '${escapedPath}' -Verb RunAs -Wait"`

    await execPromise(command, { windowsHide: true })
    return
  }
  await execFilePromise(uwpToolPath)
}

export async function setupFirewall(): Promise<void> {
  if (process.platform !== 'win32') return
  const execute = promisify(execFile)
  const netsh = path.join(process.env.SystemRoot || String.raw`C:\Windows`, 'System32', 'netsh.exe')
  await configureFirewallRules(
    [
      { name: 'mihomo', program: mihomoCorePath('mihomo') },
      { name: 'mihomo-alpha', program: mihomoCorePath('mihomo-alpha') },
      { name: 'Mihomo Party', program: exePath() }
    ],
    {
      isAdministrator: checkAdminPrivileges,
      execute: (args) =>
        execute(netsh, args, { windowsHide: true, timeout: 15000, maxBuffer: 64 * 1024 }),
      adminRequired: i18next.t('tun.firewall.adminRequired'),
      commandFailed: i18next.t('tun.firewall.commandFailed')
    }
  )
}

export function setNativeTheme(theme: 'system' | 'light' | 'dark'): void {
  nativeTheme.themeSource = theme
}

export function resetAppConfig(): void {
  if (process.platform === 'win32') {
    spawn(
      'cmd',
      [
        '/C',
        `"timeout /t 2 /nobreak >nul && rmdir /s /q "${dataDir()}" && start "" "${exePath()}""`
      ],
      {
        shell: true,
        detached: true
      }
    ).unref()
  } else {
    const script = `while kill -0 ${process.pid} 2>/dev/null; do
  sleep 0.1
done
  rm -rf '${dataDir()}'
  ${process.argv.join(' ')} & disown
exit
`
    spawn('sh', ['-c', `"${script}"`], {
      shell: true,
      detached: true,
      stdio: 'ignore'
    })
  }
  app.quit()
}
