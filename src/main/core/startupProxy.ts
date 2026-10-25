/** Every Windows start/restart confirms the requested TUN before enabling its saved proxy. */
export async function activateWindowsCoreProxy(
  platform: NodeJS.Platform,
  requested: Partial<IMihomoConfig>,
  readApplied: (timeout: number) => Promise<Partial<IMihomoConfig>>,
  isCurrent: () => boolean,
  activate: () => Promise<void>
): Promise<void> {
  if (platform !== 'win32') return
  const deadline = performance.now() + 5000
  for (;;) {
    if (!isCurrent()) throw new Error('Core changed before proxy activation')
    const remaining = deadline - performance.now()
    if (remaining <= 0)
      throw new Error(
        'The requested Windows TUN protection is not active; proxy activation stopped'
      )
    const applied = await readApplied(Math.max(1, Math.ceil(remaining)))
    if (!isCurrent()) throw new Error('Core changed before proxy activation')
    if (requested.tun?.enable !== true || applied.tun?.enable === true) break
    // The controller starts before Wintun; give the actual interface a bounded readiness window.
    await new Promise((resolve) =>
      setTimeout(resolve, Math.min(100, Math.max(0, deadline - performance.now())))
    )
  }
  await activate()
}
