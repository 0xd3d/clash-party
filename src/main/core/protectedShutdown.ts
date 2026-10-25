/** Keep DNS recovery bounded so privileged core cleanup cannot be starved by a slow helper. */
export async function shutdownProtectedCore(deps: {
  restoreDNS: () => Promise<void>
  stopCore: () => Promise<void>
  releaseGuard: () => Promise<void>
  onError: (message: string, error?: unknown) => void
  recoveryGraceMs?: number
}): Promise<void> {
  let restored = false
  const recovery = deps.restoreDNS().then(
    () => {
      restored = true
    },
    (error) => deps.onError('System DNS recovery incomplete; recovery journal retained', error)
  )
  let timer: ReturnType<typeof setTimeout> | undefined
  try {
    await Promise.race([
      recovery,
      new Promise<void>((resolve) => {
        timer = setTimeout(resolve, deps.recoveryGraceMs ?? 2000)
      })
    ])
  } finally {
    if (timer) clearTimeout(timer)
  }
  // Start SIGINT/kill fallback before waiting behind any in-flight privileged guard operation.
  const stopping = deps.stopCore()
  const releasing = restored
    ? deps
        .releaseGuard()
        .catch((error) =>
          deps.onError('DNS guard recovery incomplete; native journal retained', error)
        )
    : Promise.resolve().then(() =>
        deps.onError('DNS recovery exceeded its grace period; native guard remains enabled')
      )
  await Promise.allSettled([stopping, releasing])
}
