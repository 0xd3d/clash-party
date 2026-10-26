import { Button } from '@heroui/react'
import SettingCard from '@renderer/components/base/base-setting-card'
import { exportWebRTCGuard, inspectPrivacyProtection } from '@renderer/utils/ipc'
import { useCallback, useState } from 'react'
import { useTranslation } from 'react-i18next'
import type { PrivacyProtectionReport } from '../../../../shared/privacyAudit'
import ProtectionReport from './protection-report'
import { useProtectionRevision } from './use-protection-revision'

export default function PrivacyCheck(): React.JSX.Element {
  const { t } = useTranslation()
  const [report, setReport] = useState<PrivacyProtectionReport | null>(null)
  const [checking, setChecking] = useState(false)
  const [exporting, setExporting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [exportedPath, setExportedPath] = useState<string | null>(null)

  const [stale, setStale] = useState(false)
  const invalidate = useCallback(() => {
    setError(null)
    setReport(null)
    setStale(true)
  }, [])
  const revision = useProtectionRevision(invalidate)

  const inspect = async (): Promise<void> => {
    setChecking(true)
    setError(null)
    setReport(null)
    setStale(false)
    const ticket = revision.current
    try {
      const next = await inspectPrivacyProtection()
      if (revision.current === ticket) setReport(next)
    } catch {
      if (revision.current === ticket) setError(t('privacy.error.check'))
    } finally {
      setChecking(false)
    }
  }

  const exportGuard = async (): Promise<void> => {
    setExporting(true)
    setError(null)
    setExportedPath(null)
    try {
      setExportedPath(await exportWebRTCGuard())
    } catch {
      setError(t('privacy.error.export'))
    } finally {
      setExporting(false)
    }
  }

  return (
    <SettingCard>
      <section aria-labelledby="privacy-check-title" className="flex flex-col gap-3 select-text">
        <h3 id="privacy-check-title" className="text-md font-medium">
          {t('privacy.title')}
        </h3>
        <p className="text-sm text-default-600">{t('privacy.scope')}</p>
        <div className="flex flex-wrap gap-2">
          <Button size="sm" color="primary" isLoading={checking} onPress={inspect}>
            {t('privacy.check')}
          </Button>
        </div>
        <details>
          <summary className="cursor-pointer text-sm">{t('privacy.tools')}</summary>
          <div className="flex flex-wrap gap-2 py-2">
            <Button size="sm" variant="flat" isLoading={exporting} onPress={exportGuard}>
              {t('privacy.export')}
            </Button>
            <Button
              size="sm"
              variant="flat"
              onPress={() =>
                window.open('https://browserleaks.com/ip', '_blank', 'noopener,noreferrer')
              }
            >
              {t('privacy.openTest')}
            </Button>
          </div>
          <p className="text-xs text-default-500">{t('privacy.browserNote')}</p>
        </details>
        {error && (
          <p role="alert" className="text-sm text-danger">
            {error}
          </p>
        )}
        {exportedPath && (
          <p role="status" className="text-sm break-all">
            {t('privacy.exported', { path: exportedPath })}
          </p>
        )}
        {stale && (
          <p role="status" className="text-sm text-warning-700">
            {t('privacy.stale')}
          </p>
        )}
        {report && (
          <div aria-live="polite">
            <ProtectionReport report={report} />
          </div>
        )}
      </section>
    </SettingCard>
  )
}
