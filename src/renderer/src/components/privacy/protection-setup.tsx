import { Button, Modal, ModalContent, ModalHeader, ModalBody, ModalFooter } from '@heroui/react'
import { useCallback, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { platform } from '@renderer/utils/init'
import SettingCard from '@renderer/components/base/base-setting-card'
import { previewProtectionSetup, applyProtectionSetup } from '@renderer/utils/ipc'
import {
  protectionErrorHint,
  summarizeProtectionReport
} from '../../../../shared/privacyPresentation'
import type {
  ProtectionSetupPreview,
  ProtectionSetupResult
} from '../../../../shared/protectionSetup'
import ProtectionReport from './protection-report'
import { useProtectionRevision } from './use-protection-revision'

export default function ProtectionSetup({
  onApplied
}: {
  onApplied: () => void
}): React.JSX.Element {
  const { t } = useTranslation()
  const [preview, setPreview] = useState<ProtectionSetupPreview | null>(null)
  const [result, setResult] = useState<ProtectionSetupResult | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [stale, setStale] = useState(false)
  const invalidate = useCallback(() => {
    setError(null)
    setResult(null)
    setPreview(null)
    setStale(true)
  }, [])
  const revision = useProtectionRevision(invalidate)
  const summary = result ? summarizeProtectionReport(result.report) : null
  const prepare = async (): Promise<void> => {
    setBusy(true)
    setError(null)
    setResult(null)
    setStale(false)
    const ticket = revision.current
    try {
      const next = await previewProtectionSetup()
      if (ticket === revision.current) setPreview(next)
    } catch (value) {
      if (ticket === revision.current)
        setError(value instanceof Error ? value.message : String(value))
    } finally {
      setBusy(false)
    }
  }
  const apply = async (): Promise<void> => {
    if (!preview) return
    setBusy(true)
    setError(null)
    try {
      setResult(await applyProtectionSetup(preview.token))
      setStale(false)
      setPreview(null)
      onApplied()
    } catch (value) {
      setPreview(null)
      setError(value instanceof Error ? value.message : String(value))
    } finally {
      setBusy(false)
    }
  }
  return (
    <SettingCard>
      <section aria-labelledby="protection-setup-title" className="flex flex-col gap-3 select-text">
        <h3 id="protection-setup-title" className="text-md font-medium">
          {t('privacy.setup.title')}
        </h3>
        <p className="text-sm text-default-600">{t('privacy.setup.description')}</p>
        <div>
          <Button size="sm" color="primary" isLoading={busy} onPress={prepare}>
            {t('privacy.setup.preview')}
          </Button>
        </div>
        {error && (
          <div role="alert" className="text-sm text-danger space-y-2">
            <p>{t('privacy.setup.error.' + protectionErrorHint(error))}</p>
            <details>
              <summary className="cursor-pointer">{t('privacy.diagnostics')}</summary>
              <p className="break-all pt-2">{error}</p>
            </details>
          </div>
        )}
        {stale && (
          <p role="status" className="text-sm text-warning-700">
            {t('privacy.stale')}
          </p>
        )}
        {result && summary && (
          <div role="status" className="text-sm flex flex-col gap-2">
            <p>{t(result.restarted ? 'privacy.setup.applied' : 'privacy.setup.unchanged')}</p>
            <p>
              {t(
                summary.nativeConfirmed
                  ? 'privacy.setup.nativeConfirmed'
                  : 'privacy.setup.nativePending'
              )}
            </p>
            <p>{t('privacy.setup.networkNotRun')}</p>
            {summary.unresolvedCount > 0 && (
              <p className="text-warning-700">
                {t('privacy.setup.pending', {
                  count: summary.unresolvedCount
                })}
              </p>
            )}
            <details open={summary.unresolvedCount > 0}>
              <summary className="cursor-pointer">{t('privacy.setup.viewReport')}</summary>
              <div className="pt-2">
                <ProtectionReport report={result.report} />
              </div>
            </details>
            {result.backupPath && (
              <p className="break-all">
                {t('privacy.setup.backup')}: {result.backupPath}
              </p>
            )}
          </div>
        )}
      </section>
      <Modal
        isOpen={Boolean(preview)}
        hideCloseButton
        isDismissable={!busy}
        onClose={() => !busy && setPreview(null)}
      >
        <ModalContent>
          <ModalHeader>{t('privacy.setup.title')}</ModalHeader>
          <ModalBody>
            <p className="text-sm">
              {t('privacy.setup.profile')}: {preview?.profileName}
            </p>
            <p className="text-sm">
              {t('privacy.setup.target')}: {preview?.proxyGroup}
            </p>
            <ul className="list-disc pl-5 text-sm space-y-1">
              {preview?.changes.map((change) => (
                <li key={change}>{t('privacy.setup.change.' + change)}</li>
              ))}
            </ul>
            <p className="text-sm text-warning-700">{t('privacy.setup.interruption')}</p>
            <p className="text-sm">{t('privacy.setup.permission.' + platform)}</p>
            {platform === 'darwin' && <p className="text-sm">{t('privacy.setup.restoreDNS')}</p>}
          </ModalBody>
          <ModalFooter>
            <Button size="sm" variant="light" isDisabled={busy} onPress={() => setPreview(null)}>
              {t('common.cancel')}
            </Button>
            <Button size="sm" color="primary" isLoading={busy} onPress={apply}>
              {t('privacy.setup.apply')}
            </Button>
          </ModalFooter>
        </ModalContent>
      </Modal>
    </SettingCard>
  )
}
