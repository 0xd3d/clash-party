import { createWebRTCGuard } from './controller.mjs'

const browser = globalThis.chrome
const guard = createWebRTCGuard(browser.privacy.network.webRTCIPHandlingPolicy, browser.runtime)

browser.runtime.onInstalled.addListener((details) => {
  // Updating must not re-enable a setting the user has restored.
  void guard.initialize(details.reason === 'install')
})

browser.runtime.onStartup.addListener(() => {
  // The browser persists regular settings. Startup only reads, without reclaiming control.
  void guard.initialize()
})
