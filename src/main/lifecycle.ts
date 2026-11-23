import { spawn, exec, execFileSync } from 'child_process'
import { promisify } from 'util'
import { stat } from 'fs/promises'
import { existsSync } from 'fs'
import { app, powerMonitor } from 'electron'
import { getAppConfig } from './config'
import { stopCoreForExit, cleanupCoreWatcher } from './core/manager'
import { primeAdminPrivilegesCache } from './core/admin'
import { triggerSysProxy, disableSysProxySync } from './sys/sysproxy'
import { closeTrafficUsage } from './traffic/recorder'
import { exePath } from './utils/dirs'
import { saveMainWindowState } from './window'

export function customRelaunch(): void {
  const script = `while kill -0 ${process.pid} 2>/dev/null; do
  sleep 0.1
done
${process.argv.join(' ')} & disown
exit
`
  spawn('sh', ['-c', script], {
    detached: true,
    stdio: 'ignore'
  })
}

export async function fixUserDataPermissions(): Promise<void> {
  if (process.platform !== 'darwin') return

  const userDataPath = app.getPath('userData')
  if (!existsSync(userDataPath)) return

  try {
    const stats = await stat(userDataPath)
    const currentUid = process.getuid?.() || 0

    if (stats.uid === 0 && currentUid !== 0) {
      const execPromise = promisify(exec)
      const username = process.env.USER || process.env.LOGNAME
      if (username) {
        await execPromise(`chown -R "${username}:staff" "${userDataPath}"`)
        await execPromise(`chmod -R u+rwX "${userDataPath}"`)
      }
    }
  } catch {
    // ignore
  }
}

export function setupPlatformSpecifics(): void {
  if (process.platform === 'linux') {
    app.relaunch = customRelaunch
  }

  // https://github.com/electron/electron/issues/43278
  // https://github.com/electron/electron/issues/36698
  const electronMajor = parseInt(process.versions.electron.split('.')[0], 10) || 0
  if (process.platform === 'win32' && !exePath().startsWith('C') && electronMajor < 38) {
    app.commandLine.appendSwitch('in-process-gpu')
  }

  if (process.platform === 'win32') {
    const elevated = isWindowsElevatedSync()
    if (elevated === true) {
      primeAdminPrivilegesCache(true)
      app.commandLine.appendSwitch('disable-gpu-sandbox')
    }
  }
}

function isWindowsElevatedSync(): boolean | null {
  if (process.platform !== 'win32') return false
  try {
    execFileSync('fltmc', [], { stdio: 'ignore', windowsHide: true, timeout: 800 })
    return true
  } catch {
    // 只有成功结果可安全缓存；所有失败交给异步 fltmc + net session 回退确认。
    return null
  }
}

export function setupAppLifecycle(): void {
  let sysProxyDisabled = false
  let cleanupPromise: Promise<void> | null = null

  const withTimeout = async (promise: Promise<void>, timeout: number): Promise<void> => {
    let timeoutId: NodeJS.Timeout | null = null

    try {
      await Promise.race([
        promise,
        new Promise<void>((resolve) => {
          timeoutId = setTimeout(resolve, timeout)
        })
      ])
    } finally {
      if (timeoutId) clearTimeout(timeoutId)
    }
  }

  const cleanupBeforeExit = (): Promise<void> => {
    if (cleanupPromise) return cleanupPromise

    cleanupPromise = (async () => {
      saveMainWindowState() // 硬退出补一次落盘

      cleanupCoreWatcher()

      if (process.platform !== 'darwin') {
        disableSysProxySync()
        sysProxyDisabled = true
      }

      const cleanupTasks: Promise<unknown>[] = [stopCoreForExit(), closeTrafficUsage()]
      if (process.platform === 'darwin') {
        const { sysProxy } = await getAppConfig()
        if (sysProxy?.enable) {
          cleanupTasks.push(
            triggerSysProxy(false, { helperTimeout: 750, force: true }).then(() => {
              sysProxyDisabled = true
            })
          )
        } else {
          sysProxyDisabled = true
        }
      }

      // DNS recovery gets a bounded grace period before core termination starts.
      // Reserve time for SIGINT then SIGKILL plus the serialized native guard release;
      // a slow privileged operation must not leave an orphan core after app.exit().
      await withTimeout(
        Promise.allSettled(cleanupTasks).then(() => {}),
        20000
      )
    })()

    return cleanupPromise
  }

  app.on('window-all-closed', () => {
    // Keep the app and tray alive when lightweight tray mode destroys the renderer window.
  })

  // Windows 注销/关机可能先触发窗口 session-end；复用同一清理 Promise，
  // 避免与 powerMonitor.shutdown 重复执行普通、无界的核心和代理清理。
  app.on('browser-window-created', (_event, window) => {
    window.on('session-end', async () => {
      await cleanupBeforeExit()
      app.exit()
    })
  })

  app.on('before-quit', async (e) => {
    e.preventDefault()
    await cleanupBeforeExit()
    app.exit()
  })

  powerMonitor.on('shutdown', async () => {
    await cleanupBeforeExit()
    app.exit()
  })

  // 合盖和睡眠不拆 TUN、不把系统 DNS 还给路由器。卡住的 mihomo 由 macOS stall monitor
  // 单独重启核心。此处不再注册 resume，避免和 sys/resume.ts 叠加重启。

  app.on('will-quit', () => {
    if (!sysProxyDisabled) {
      disableSysProxySync()
    }
  })
}

export function getSystemLanguage(): 'zh-CN' | 'en-US' {
  const locale = app.getLocale()
  return locale.startsWith('zh') ? 'zh-CN' : 'en-US'
}
