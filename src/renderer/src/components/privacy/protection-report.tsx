import { Chip } from '@heroui/react'
import { useTranslation } from 'react-i18next'
import type { PrivacyAuditFinding, PrivacyProtectionReport } from '../../../../shared/privacyAudit'
import {
  PRIVACY_GROUPS,
  reportFindings,
  findingGroup,
  isDiagnostic,
  isUnresolved
} from '../../../../shared/privacyPresentation'

function Finding({ finding }: { finding: PrivacyAuditFinding }): React.JSX.Element {
  const { t } = useTranslation()
  return (
    <li className="text-sm break-words space-y-1">
      <p>
        {t(`privacy.finding.${finding.id}.${finding.level}`, {
          defaultValue: t('privacy.finding.unknown')
        })}
      </p>
      {finding.reason && <p>{t('privacy.reason.' + finding.reason)}</p>}
      {finding.detail && <p className="font-mono text-xs break-all">{finding.detail}</p>}
      {finding.origin && (
        <p className="text-xs text-default-500">
          {t('privacy.origin.label')}: {t(`privacy.origin.${finding.origin.source}`)}
          {finding.origin.name && ` · ${finding.origin.name}`} · {finding.origin.key}
        </p>
      )}
      {isUnresolved(finding) && (
        <p className="text-warning-700">
          {t(`privacy.action.${finding.id}`, { defaultValue: t('privacy.action.unknown') })}
        </p>
      )}
    </li>
  )
}

export default function ProtectionReport({
  report
}: {
  report: PrivacyProtectionReport
}): React.JSX.Element {
  const { t } = useTranslation()
  const allFindings = reportFindings(report)
  return (
    <div className="flex flex-col gap-3">
      {PRIVACY_GROUPS.map((group) => {
        const findings = allFindings.filter(
          (finding) => findingGroup(finding) === group && !isDiagnostic(finding)
        )
        const pending = findings.filter(isUnresolved)
        const normal = findings.filter((finding) => !isUnresolved(finding))
        const state =
          report.source === 'unavailable' || !findings.length
            ? 'unavailable'
            : pending.length
              ? 'review'
              : group === 'guard' &&
                  findings.some((f) => f.id === 'networkGuard' && f.level === 'pass')
                ? 'confirmed'
                : 'configured'
        return (
          <section
            key={group}
            className="rounded-lg border border-default-200 p-3 space-y-2"
            aria-label={t('privacy.group.' + group)}
          >
            <div className="flex flex-wrap justify-between gap-2 items-center">
              <h4 className="font-medium text-sm">{t('privacy.group.' + group)}</h4>
              <Chip
                size="sm"
                variant="flat"
                color={
                  pending.some((f) => f.level === 'error')
                    ? 'danger'
                    : state === 'review' || state === 'unavailable'
                      ? 'warning'
                      : 'success'
                }
              >
                {t('privacy.state.' + state)}
              </Chip>
            </div>
            {pending.length > 0 && (
              <ul className="space-y-3" role="list">
                {pending.map((finding, i) => (
                  <Finding key={finding.id + i} finding={finding} />
                ))}
              </ul>
            )}
            {normal.length > 0 && (
              <details>
                <summary className="cursor-pointer text-xs text-default-600">
                  {t('privacy.checkItems', { count: normal.length })}
                </summary>
                <ul className="space-y-2 pt-2">
                  {normal.map((finding, i) => (
                    <Finding key={finding.id + i} finding={finding} />
                  ))}
                </ul>
              </details>
            )}
          </section>
        )
      })}
      <details>
        <summary className="cursor-pointer text-sm">{t('privacy.diagnostics')}</summary>
        <div className="text-xs text-default-500 space-y-2 pt-2 break-all">
          <p>
            {t(`privacy.source.${report.source}`)} · {report.platform}
          </p>
          <ul className="space-y-2">
            {report.findings
              .filter(isDiagnostic)
              .filter((f) => f.id !== 'scope')
              .map((finding) => (
                <Finding key={finding.id} finding={finding} />
              ))}
          </ul>
          {report.diagnostics?.map((entry, i) => (
            <p key={entry.id + i}>
              {t('privacy.diagnostic.' + entry.id, { defaultValue: entry.id })}:{' '}
              <code>{entry.value}</code>
            </p>
          ))}
        </div>
      </details>
    </div>
  )
}
