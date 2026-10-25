import { createWebRTCGuard, TARGET_POLICY } from './controller.mjs'

const browser = globalThis.chrome
const document = globalThis.document
const guard = createWebRTCGuard(browser.privacy.network.webRTCIPHandlingPolicy, browser.runtime)
const enable = document.getElementById('enable')
const restore = document.getElementById('restore')
const refresh = document.getElementById('refresh')
const result = document.getElementById('result')

const messages = {
  enabled: '已设置并确认 / Enabled and verified',
  already_enabled: '本扩展已启用 / Already enabled by this extension',
  managed: '浏览器或策略已锁定，未更改 / Managed or locked; unchanged',
  other_extension: '其他扩展正在控制，未更改 / Another extension controls this setting',
  unavailable: '当前无法控制此设置 / Setting cannot be controlled',
  verification_failed: '复查未确认成功，请查看当前状态 / Readback did not confirm success',
  error: '浏览器 API 操作失败，请刷新检查 / Browser API failed; refresh to inspect',
  restored: '已撤销本扩展控制 / This extension’s control was cleared',
  not_owned: '本扩展未控制此设置，未更改 / Not controlled by this extension; unchanged'
}

function describe(state) {
  if (!state.readable) return '无法读取，未确认 / Unavailable; not verified'
  const restriction =
    state.value === TARGET_POLICY
      ? '限制值已读取 / Restricted value read'
      : '未读取到限制值 / Restricted value not active'
  const owners = {
    controlled_by_this_extension: '本扩展 / This extension',
    controllable_by_this_extension: '可由本扩展启用 / Available to enable',
    controlled_by_other_extensions: '其他扩展 / Another extension',
    not_controllable: '浏览器或策略锁定 / Managed or locked'
  }
  return `${restriction} · ${owners[state.levelOfControl] || '未知控制来源 / Unknown owner'}`
}

async function render() {
  const state = await guard.status()
  document.getElementById('regular-status').textContent = describe(state.regular)
  const privateScope = !state.incognito.readable
    ? ''
    : state.incognito.incognitoSpecific === true
      ? ' · 隐身专用覆盖 / Private override'
      : state.incognito.incognitoSpecific === false
        ? ' · 继承普通配置 / Inherits regular setting'
        : ' · 覆盖来源未确认 / Scope not confirmed'
  document.getElementById('incognito-status').textContent = describe(state.incognito) + privateScope
  const owner = state.regular.readable ? state.regular.levelOfControl : undefined
  enable.disabled = !['controlled_by_this_extension', 'controllable_by_this_extension'].includes(
    owner
  )
  restore.disabled = owner !== 'controlled_by_this_extension'
}

async function act(operation) {
  enable.disabled = restore.disabled = refresh.disabled = true
  try {
    if (operation) {
      const outcome = await operation()
      result.textContent = messages[outcome.code] || messages.error
    }
    await render()
  } finally {
    refresh.disabled = false
  }
}

enable.addEventListener('click', () => void act(() => guard.enable()))
restore.addEventListener('click', () => void act(() => guard.restore()))
refresh.addEventListener('click', () => void act())
void act()
