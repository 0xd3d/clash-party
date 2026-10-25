import { readFile } from 'fs/promises'
import { describe, expect, it, vi } from 'vitest'
import {
  createWebRTCGuard,
  TARGET_POLICY,
  type BrowserRuntimeAPI,
  type BrowserSettingAPI,
  type BrowserSettingValue
} from '../integrations/webrtc-guard/controller.mjs'

const available: BrowserSettingValue = {
  value: 'default',
  levelOfControl: 'controllable_by_this_extension'
}

const owned: BrowserSettingValue = {
  value: TARGET_POLICY,
  levelOfControl: 'controlled_by_this_extension'
}

function fixture(initial = available, underlying = available) {
  let regular = { ...initial }
  let privateOverride: BrowserSettingValue | undefined
  const runtime: BrowserRuntimeAPI = {}
  const responses: Array<BrowserSettingValue | Error | null> = []
  const events: string[] = []
  let setError = false
  let clearError = false

  function fail(callback: () => void) {
    runtime.lastError = { message: 'Browser refused the operation' }
    callback()
    runtime.lastError = undefined
  }

  const setting = {
    get: vi.fn<BrowserSettingAPI['get']>((details, callback) => {
      events.push(`get:${details.incognito ? 'private' : 'regular'}`)
      const queued = responses.shift()
      if (queued instanceof Error) {
        fail(() => callback(undefined as unknown as BrowserSettingValue))
      } else if (queued === null) {
        callback(undefined as unknown as BrowserSettingValue)
      } else {
        callback(
          queued || {
            ...(details.incognito && privateOverride ? privateOverride : regular),
            incognitoSpecific: Boolean(details.incognito && privateOverride)
          }
        )
      }
    }),
    set: vi.fn<BrowserSettingAPI['set']>((details, callback) => {
      events.push(`set:${details.scope}:${details.value}`)
      if (setError) fail(callback)
      else {
        regular = { value: details.value, levelOfControl: 'controlled_by_this_extension' }
        callback()
      }
    }),
    clear: vi.fn<BrowserSettingAPI['clear']>((details, callback) => {
      events.push(`clear:${details.scope}`)
      if (clearError) fail(callback)
      else {
        regular = { ...underlying }
        callback()
      }
    })
  }

  return {
    guard: createWebRTCGuard(setting, runtime),
    setting,
    events,
    responses,
    setPrivateOverride: (value: BrowserSettingValue) => {
      privateOverride = value
    },
    failSet: () => {
      setError = true
    },
    failClear: () => {
      clearError = true
    }
  }
}

describe('optional WebRTC guard controller', () => {
  it('checks control, sets only the regular policy, and verifies value and ownership', async () => {
    const state = fixture()

    await expect(state.guard.enable()).resolves.toEqual({ ok: true, code: 'enabled' })

    expect(state.events).toEqual(['get:regular', `set:regular:${TARGET_POLICY}`, 'get:regular'])
    expect(state.setting.set).toHaveBeenCalledWith(
      { value: TARGET_POLICY, scope: 'regular' },
      expect.any(Function)
    )
    expect(state.setting.clear).not.toHaveBeenCalled()
  })

  it('is idempotent on installation, startup and repeated enable', async () => {
    const state = fixture()
    await expect(state.guard.initialize(true)).resolves.toEqual({ ok: true, code: 'enabled' })
    await expect(state.guard.initialize(true)).resolves.toEqual({
      ok: true,
      code: 'already_enabled'
    })
    await expect(state.guard.initialize()).resolves.toEqual({
      ok: true,
      code: 'already_enabled'
    })
    await expect(state.guard.enable()).resolves.toEqual({ ok: true, code: 'already_enabled' })
    expect(state.setting.set).toHaveBeenCalledTimes(1)
  })

  it('does not re-enable restored settings on startup or update', async () => {
    const state = fixture(owned)
    await expect(state.guard.restore()).resolves.toEqual({ ok: true, code: 'restored' })
    await expect(state.guard.initialize(false)).resolves.toEqual({ ok: true, code: 'unchanged' })
    await expect(state.guard.initialize()).resolves.toEqual({ ok: true, code: 'unchanged' })
    expect(state.setting.set).not.toHaveBeenCalled()
  })

  it.each([
    ['not_controllable', 'managed'],
    ['controlled_by_other_extensions', 'other_extension'],
    ['unexpected_browser_value', 'unavailable']
  ])('does not take control from %s', async (levelOfControl, code) => {
    const state = fixture({ value: TARGET_POLICY, levelOfControl })
    await expect(state.guard.enable()).resolves.toEqual({ ok: false, code })
    expect(state.events).toEqual(['get:regular'])
    expect(state.setting.set).not.toHaveBeenCalled()
    expect(state.setting.clear).not.toHaveBeenCalled()
  })

  it.each([
    { value: 'default', levelOfControl: 'controlled_by_this_extension' },
    { value: TARGET_POLICY, levelOfControl: 'controlled_by_other_extensions' }
  ])('does not claim protection after a conflicting readback: %j', async (readback) => {
    const state = fixture()
    state.responses.push(available, readback)
    await expect(state.guard.enable()).resolves.toEqual({
      ok: false,
      code: 'verification_failed'
    })
    expect(state.setting.clear).not.toHaveBeenCalled()
  })

  it('clears only its own regular setting and retains the underlying policy', async () => {
    const underlying = { value: TARGET_POLICY, levelOfControl: 'not_controllable' }
    const state = fixture(owned, underlying)

    await expect(state.guard.restore()).resolves.toEqual({ ok: true, code: 'restored' })
    expect(state.events).toEqual(['get:regular', 'clear:regular', 'get:regular'])
    expect(state.setting.clear).toHaveBeenCalledWith({ scope: 'regular' }, expect.any(Function))
    expect(state.setting.set).not.toHaveBeenCalled()
    expect((await state.guard.status()).regular).toMatchObject(underlying)
  })

  it.each(['not_controllable', 'controlled_by_other_extensions', 'controllable_by_this_extension'])(
    'restore leaves %s untouched',
    async (levelOfControl) => {
      const state = fixture({ value: TARGET_POLICY, levelOfControl })
      await expect(state.guard.restore()).resolves.toEqual({ ok: true, code: 'not_owned' })
      expect(state.setting.clear).not.toHaveBeenCalled()
      expect(state.setting.set).not.toHaveBeenCalled()
    }
  )

  it('verifies that clear actually released control', async () => {
    const state = fixture(owned)
    state.responses.push(owned, owned)
    await expect(state.guard.restore()).resolves.toEqual({
      ok: false,
      code: 'verification_failed'
    })
  })

  it.each([new Error('read failed'), null])(
    'rejects failed or malformed reads: %s',
    async (read) => {
      const state = fixture()
      state.responses.push(read)
      await expect(state.guard.enable()).resolves.toEqual({ ok: false, code: 'error' })
      expect(state.setting.set).not.toHaveBeenCalled()
    }
  )

  it('handles a failed readback without claiming success', async () => {
    const state = fixture()
    state.responses.push(available, new Error('readback failed'))
    await expect(state.guard.enable()).resolves.toEqual({ ok: false, code: 'error' })
    expect(state.setting.set).toHaveBeenCalledTimes(1)
  })

  it('handles browser errors from set and clear', async () => {
    const enabling = fixture()
    enabling.failSet()
    await expect(enabling.guard.enable()).resolves.toEqual({ ok: false, code: 'error' })
    expect(enabling.events).toEqual(['get:regular', `set:regular:${TARGET_POLICY}`])

    const restoring = fixture(owned)
    restoring.failClear()
    await expect(restoring.guard.restore()).resolves.toEqual({ ok: false, code: 'error' })
  })

  it('serializes repeated user operations without leaving enable after restore', async () => {
    const state = fixture()
    await Promise.all([state.guard.enable(), state.guard.restore()])
    expect(state.events).toEqual([
      'get:regular',
      `set:regular:${TARGET_POLICY}`,
      'get:regular',
      'get:regular',
      'clear:regular',
      'get:regular'
    ])
    expect((await state.guard.status()).regular).toMatchObject(available)
  })

  it('reports a private override separately from the regular setting', async () => {
    const state = fixture(owned)
    state.setPrivateOverride({ value: 'default', levelOfControl: 'not_controllable' })

    await expect(state.guard.status()).resolves.toEqual({
      regular: { readable: true, ...owned, incognitoSpecific: false },
      incognito: {
        readable: true,
        value: 'default',
        levelOfControl: 'not_controllable',
        incognitoSpecific: true
      }
    })
    expect(state.events).toEqual(['get:regular', 'get:private'])
    expect(state.setting.set).not.toHaveBeenCalled()
  })

  it('does not invent private protection when the private read fails', async () => {
    const state = fixture(owned)
    state.responses.push(owned, new Error('private access unavailable'))
    await expect(state.guard.status()).resolves.toEqual({
      regular: { readable: true, ...owned, incognitoSpecific: undefined },
      incognito: { readable: false }
    })
  })
})

describe('optional WebRTC guard package', () => {
  it('ships an unpacked Chromium MV3 extension with only the privacy permission', async () => {
    const manifest = JSON.parse(
      await readFile(new URL('../integrations/webrtc-guard/manifest.json', import.meta.url), 'utf8')
    )
    expect(manifest.manifest_version).toBe(3)
    expect(manifest.permissions).toEqual(['privacy'])
    expect(manifest.host_permissions).toBeUndefined()
    expect(manifest.optional_permissions).toBeUndefined()
    expect(manifest.background).toEqual({ service_worker: 'background.mjs', type: 'module' })
    expect(manifest.action.default_popup).toBe('popup.html')
  })
})
