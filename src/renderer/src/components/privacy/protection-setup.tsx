import { Button, Modal, ModalContent, ModalHeader, ModalBody, ModalFooter } from '@heroui/react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import SettingCard from '@renderer/components/base/base-setting-card'
import { previewProtectionSetup, applyProtectionSetup } from '@renderer/utils/ipc'
import type {
  ProtectionSetupPreview,
  ProtectionSetupResult
} from '../../../../shared/protectionSetup'

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
  const prepare = async (): Promise<void> => {
    setBusy(true)
    setError(null)
    setResult(null)
    try {
      setPreview(await previewProtectionSetup())
    } catch (value) {
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
          <p role="alert" className="text-sm text-danger break-words">
            {error}
          </p>
        )}
        {result && (
          <div role="status" className="text-sm flex flex-col gap-2">
            <p>{t(result.restarted ? 'privacy.setup.success' : 'privacy.setup.already')}</p>
            {result.backupPath && (
              <p className="break-all">
                {t('privacy.setup.backup')}: {result.backupPath}
              </p>
            )}
            <p className="text-xs text-default-500">{t('privacy.setup.verifyNote')}</p>
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
