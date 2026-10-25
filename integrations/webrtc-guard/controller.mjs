export const TARGET_POLICY = 'disable_non_proxied_udp'

const ownership = 'controlled_by_this_extension'
const available = 'controllable_by_this_extension'

// Only this API is injected; the controller never reads tabs, addresses or browsing data.
export function createWebRTCGuard(setting, runtime = {}) {
  let pending = Promise.resolve()

  function call(method, details) {
    return new Promise((resolve, reject) => {
      try {
        setting[method](details, (result) => {
          const error = runtime.lastError
          if (error) reject(new Error(error.message || 'Browser API failed'))
          else resolve(result)
        })
      } catch (error) {
        reject(error)
      }
    })
  }

  async function read(incognito = false) {
    const result = await call('get', { incognito })
    if (!result || typeof result.value !== 'string' || typeof result.levelOfControl !== 'string') {
      throw new Error('Invalid browser setting response')
    }
    return {
      value: result.value,
      levelOfControl: result.levelOfControl,
      incognitoSpecific:
        typeof result.incognitoSpecific === 'boolean' ? result.incognitoSpecific : undefined
    }
  }

  function conflict(state) {
    if (state.levelOfControl === 'not_controllable') return 'managed'
    if (state.levelOfControl === 'controlled_by_other_extensions') return 'other_extension'
    if (![ownership, available].includes(state.levelOfControl)) return 'unavailable'
    return undefined
  }

  function serialize(operation) {
    const result = pending.then(operation).catch(() => ({ ok: false, code: 'error' }))
    pending = result.then(() => undefined)
    return result
  }

  async function enable() {
    const before = await read()
    const blocked = conflict(before)
    if (blocked) return { ok: false, code: blocked }
    if (before.levelOfControl === ownership && before.value === TARGET_POLICY) {
      return { ok: true, code: 'already_enabled' }
    }
    await call('set', { value: TARGET_POLICY, scope: 'regular' })
    const after = await read()
    if (after.value !== TARGET_POLICY || after.levelOfControl !== ownership) {
      return { ok: false, code: 'verification_failed' }
    }
    return { ok: true, code: 'enabled' }
  }

  return {
    async status() {
      async function snapshot(incognito) {
        try {
          return { readable: true, ...(await read(incognito)) }
        } catch {
          return { readable: false }
        }
      }
      const regular = await snapshot(false)
      const incognito = await snapshot(true)
      return { regular, incognito }
    },
    enable() {
      return serialize(enable)
    },
    restore() {
      return serialize(async () => {
        const before = await read()
        if (before.levelOfControl !== ownership) return { ok: true, code: 'not_owned' }
        await call('clear', { scope: 'regular' })
        const after = await read()
        return after.levelOfControl === ownership
          ? { ok: false, code: 'verification_failed' }
          : { ok: true, code: 'restored' }
      })
    },
    initialize(freshInstall = false) {
      return serialize(async () => {
        if (freshInstall) return enable()
        const state = await read()
        return {
          ok: true,
          code:
            state.levelOfControl === ownership && state.value === TARGET_POLICY
              ? 'already_enabled'
              : 'unchanged'
        }
      })
    }
  }
}
