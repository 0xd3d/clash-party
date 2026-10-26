import { useEffect, useRef } from 'react'
import { watchProtectionChanges } from '../../../../shared/privacyPresentation'

/** Discard old reports and in-flight inspections when their input changes. */
export function useProtectionRevision(invalidate: () => void): React.RefObject<number> {
  const revision = useRef(0)
  useEffect(() => {
    const advance = (): void => {
      revision.current++
    }
    const unsubscribe = watchProtectionChanges(
      (event, handler) => window.electron.ipcRenderer.on(event, handler),
      () => {
        advance()
        invalidate()
      }
    )
    return () => {
      advance()
      unsubscribe()
    }
  }, [invalidate])
  return revision
}
