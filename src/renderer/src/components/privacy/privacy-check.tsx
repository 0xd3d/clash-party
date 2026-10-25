import { Button, Chip } from '@heroui/react'
import SettingCard from '@renderer/components/base/base-setting-card'
import { exportWebRTCGuard, inspectPrivacyProtection } from '@renderer/utils/ipc'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import type { PrivacyProtectionReport } from '../../../../shared/privacyAudit'

const findingColors = {
  pass: 'success',
  warning: 'warning',
  error: 'danger',
  info: 'default'
} as const

export default function PrivacyCheck(): React.JSX.Element {
  const { t } = useTranslation()
  const [report, setReport] = useState<PrivacyProtectionReport | null>(null)
  const [checking, setChecking] = useState(false)
  const [exporting, setExporting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [exportedPath, setExportedPath] = useState<string | null>(null)

  const inspect = async (): Promise<void> => {
    setChecking(true)
    setError(null)
    setReport(null)
    try {
      setReport(await inspectPrivacyProtection())
    } catch {
      setError(t('privacy.error.check'))
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
        {report && (
          <div aria-live="polite" className="flex flex-col gap-2">
            <p className="text-xs text-default-500">
              {t(`privacy.source.${report.source}`)} · {report.platform}
            </p>
            <ul className="flex flex-col gap-2">
              {report.findings.map((finding, index) => (
                <li key={`${finding.id}-${index}`} className="flex items-start gap-2 text-sm">
                  <Chip size="sm" variant="flat" color={findingColors[finding.level]}>
                    {t(`privacy.level.${finding.level}`)}
                  </Chip>
                  <span className="min-w-0 pt-0.5 break-words">
                    {t(`privacy.finding.${finding.id}.${finding.level}`, {
                      defaultValue: t('privacy.finding.unknown')
                    })}
                    {finding.detail && <span className="ml-1">({finding.detail})</span>}
                  </span>
                </li>
              ))}
            </ul>
          </div>
        )}
      </section>
    </SettingCard>
  )
}
