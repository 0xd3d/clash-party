import {
  cn,
  Modal,
  ModalContent,
  ModalHeader,
  ModalBody,
  ModalFooter,
  Button,
  Input,
  Switch,
  Select,
  SelectItem,
  Dropdown,
  DropdownTrigger,
  DropdownMenu,
  DropdownItem,
  Tabs,
  Tab,
  Tooltip
} from '@heroui/react'
import { toast } from '@renderer/components/base/toast'
import React, { useEffect, useState } from 'react'
import { useOverrideConfig } from '@renderer/hooks/use-override-config'
import { useAppConfig } from '@renderer/hooks/use-app-config'
import { useProfileConfig } from '@renderer/hooks/use-profile-config'
import { useSWRConfig } from 'swr'
import {
  mihomoHotReloadConfig,
  addProfileUpdater,
  getFilePath,
  readTextFile,
  getSimpleConfig,
  previewSimpleConfig,
  addProfileItem as importProfile,
  updateProfileItem as saveProfile
} from '@renderer/utils/ipc'
import { MdDeleteForever, MdInfoOutline } from 'react-icons/md'
import { FaPlus } from 'react-icons/fa6'
import { useTranslation } from 'react-i18next'
import { isValidCron } from 'cron-validator'
import SettingItem from '../base/base-setting-item'
import type { SimpleObject, SimpleSubscriptionOptions } from '../../../../shared/simple-config'
import SimpleProviderOptions from '../simple/simple-provider-options'
import type { HeaderRow } from '../simple/provider-fields'

interface Props {
  item: IProfileItem
  mode?: 'edit' | 'import'
  updateProfileItem?: (item: IProfileItem) => Promise<void>
  addProfileItem?: (item: Partial<IProfileItem>) => Promise<void>
  onClose: () => void
}
const EditInfoModal: React.FC<Props> = (props) => {
  const { item, mode = 'edit', updateProfileItem, addProfileItem, onClose } = props
  const { appConfig } = useAppConfig()
  const simpleMode = appConfig?.operationMode === 'simple'
  const { mutateProfileConfig } = useProfileConfig()
  const { mutate } = useSWRConfig()
  const [simpleOptions, setSimpleOptions] = useState<SimpleSubscriptionOptions>({
    mode: 'group'
  })
  const [providerHeaders, setProviderHeaders] = useState<HeaderRow[]>([])
  const [outbounds, setOutbounds] = useState<string[]>(['DIRECT'])
  const [optionsLoaded, setOptionsLoaded] = useState(false)
  const [saving, setSaving] = useState(false)
  const { overrideConfig } = useOverrideConfig()
  const { items: overrideItems = [] } = overrideConfig || {}
  const [values, setValues] = useState({
    ...item
  })
  const inputWidth = simpleMode
    ? 'w-[65%] min-w-0'
    : 'w-[400px] md:w-[400px] lg:w-[600px] xl:w-[800px]'
  const { t } = useTranslation()
  const isImportMode = mode === 'import'
  useEffect(() => {
    if (!simpleMode || isImportMode) return
    let active = true
    getSimpleConfig()
      .then((state) => {
        if (!active) return
        const source = state.draft.sources.find((source) => source.profileId === item.id)
        const providerOptions = structuredClone(source?.providerOptions || {})
        const header = (providerOptions.header || {}) as Record<string, string[]>
        const customHeaders: HeaderRow[] = []
        for (const [name, values] of Object.entries(header)) {
          const lower = name.toLowerCase()
          if (lower === 'user-agent' || lower === 'authorization') {
            setValues((current) => ({
              ...current,
              [lower === 'user-agent' ? 'userAgent' : 'authToken']: values.join(' ')
            }))
          } else customHeaders.push({ name, values: values.join('\n') })
        }
        delete providerOptions.header
        if (typeof providerOptions['age-secret-key'] === 'string')
          setValues((current) => ({
            ...current,
            ageSecretKey: providerOptions['age-secret-key'] as string
          }))
        delete providerOptions['age-secret-key']
        setProviderHeaders(customHeaders)
        setSimpleOptions({
          mode: source?.mode === 'extract' ? 'nodes' : 'group',
          prefix: source?.prefix,
          providerName: source?.name,
          providerOptions
        })
        setOptionsLoaded(true)
      })
      .catch((error) => {
        if (active) toast.error(String(error))
      })
    return () => {
      active = false
    }
  }, [simpleMode, isImportMode, item.id])
  useEffect(() => {
    if (!simpleMode) return
    let active = true
    previewSimpleConfig()
      .then((preview) => {
        if (active) setOutbounds(preview.references.outbounds)
      })
      .catch(() => {
        // Basic subscription edits must remain available if previewing another source fails.
      })
    return () => {
      active = false
    }
  }, [simpleMode])
  const customHome = values.customHome?.trim() || ''
  const validHome = !customHome || (/^https?:\/\//i.test(customHome) && URL.canParse(customHome))
  const canSave =
    validHome &&
    (!simpleMode || isImportMode || optionsLoaded) &&
    (!isImportMode ||
      (values.type === 'remote' ? Boolean(values.url?.trim()) : values.file != null))

  const onSave = async (): Promise<void> => {
    setSaving(true)
    try {
      const updatedItem = simpleMode
        ? values
        : {
            ...values,
            override: values.override?.filter(
              (i) =>
                overrideItems.find((t) => t.id === i) &&
                !overrideItems.find((t) => t.id === i)?.global
            )
          }
      if (simpleMode) {
        const providerOptions: SimpleObject = { ...simpleOptions.providerOptions }
        const header: Record<string, string[]> = {}
        for (const row of providerHeaders) {
          if (!row.name.trim() && !row.values) continue
          const name = row.name.trim()
          if (['user-agent', 'authorization'].includes(name.toLowerCase()))
            throw new Error('User-Agent 和 Authorization 请在订阅信息中设置')
          if (Object.keys(header).some((key) => key.toLowerCase() === name.toLowerCase()))
            throw new Error('请求头名称不能重复')
          header[name] = row.values.split('\n')
        }
        if (Object.keys(header).length) providerOptions.header = header
        else delete providerOptions.header
        const options = { ...simpleOptions, providerOptions }
        if (isImportMode) await importProfile(updatedItem, options)
        else {
          await saveProfile(updatedItem, options)
          await addProfileUpdater(updatedItem)
        }
        await mutate('getSimpleConfig')
      } else if (isImportMode) {
        if (!addProfileItem) throw new Error('Missing profile import handler')
        await addProfileItem(updatedItem)
      } else {
        if (!updateProfileItem) throw new Error('Missing profile update handler')
        await updateProfileItem(updatedItem)
        await addProfileUpdater(updatedItem)
        await mihomoHotReloadConfig()
      }
      onClose()
    } catch (e) {
      toast.error(String(e))
    } finally {
      if (simpleMode) mutateProfileConfig()
      setSaving(false)
    }
  }

  const selectLocalFile = async (): Promise<void> => {
    const files = await getFilePath(['yml', 'yaml', 'json'])
    if (!files?.length) return

    const file = await readTextFile(files[0])
    const fileName = files[0].split('/').pop()?.split('\\').pop()
    setValues({
      ...values,
      type: 'local',
      file,
      name: values.name || fileName || values.name
    })
  }

  const subscriptionFields = (
    <>
      {isImportMode && (
        <SettingItem title={t('profiles.editInfo.type')}>
          <Select
            classNames={{ trigger: 'data-[hover=true]:bg-default-200' }}
            size="sm"
            className={cn(inputWidth)}
            selectedKeys={new Set([values.type])}
            disallowEmptySelection={true}
            onSelectionChange={(v) => {
              setValues({
                ...values,
                type: v.currentKey as 'remote' | 'local'
              })
            }}
          >
            <SelectItem key="remote">{t('profiles.remote')}</SelectItem>
            <SelectItem key="local">{t('profiles.local')}</SelectItem>
          </Select>
        </SettingItem>
      )}
      <SettingItem title={t('profiles.editInfo.name')}>
        <Input
          size="sm"
          className={cn(inputWidth)}
          value={values.name}
          onValueChange={(v) => {
            setValues({ ...values, name: v })
          }}
        />
      </SettingItem>
      <SettingItem title={t('profiles.editInfo.customHome')}>
        <Input
          size="sm"
          type="url"
          aria-label={t('profiles.editInfo.customHome')}
          className={cn(inputWidth)}
          value={values.customHome || ''}
          isInvalid={!validHome}
          errorMessage={t('profiles.editInfo.invalidHome')}
          placeholder={values.home || t('profiles.editInfo.homePlaceholder')}
          onValueChange={(customHome) => setValues({ ...values, customHome })}
        />
      </SettingItem>
      {simpleMode && (
        <>
          <SettingItem title="导入方式">
            <Tabs
              size="sm"
              aria-label="导入方式"
              selectedKey={simpleOptions.mode}
              onSelectionChange={(mode) => {
                setSimpleOptions({
                  ...simpleOptions,
                  mode: mode as SimpleSubscriptionOptions['mode']
                })
              }}
            >
              <Tab key="group" title="整份订阅" />
              <Tab key="nodes" title="独立节点" />
            </Tabs>
          </SettingItem>
          {simpleOptions.mode === 'group' && (
            <SettingItem title="引用名称">
              <Input
                size="sm"
                className={cn(inputWidth)}
                value={simpleOptions.providerName ?? ''}
                placeholder={values.name}
                onValueChange={(providerName) =>
                  setSimpleOptions({ ...simpleOptions, providerName })
                }
              />
            </SettingItem>
          )}
        </>
      )}
      <SettingItem title={t('profiles.editInfo.ageSecretKey')}>
        <Input
          size="sm"
          type="password"
          className={cn(inputWidth)}
          value={values.ageSecretKey || ''}
          onValueChange={(v) => {
            setValues({ ...values, ageSecretKey: v || undefined })
          }}
          placeholder={t('profiles.editInfo.ageSecretKeyPlaceholder')}
        />
      </SettingItem>
      {isImportMode && values.type === 'local' && (
        <SettingItem title={t('profiles.editInfo.file')}>
          <div className={cn(inputWidth, 'flex justify-end')}>
            <Button size="sm" variant={values.file ? 'flat' : 'solid'} onPress={selectLocalFile}>
              {values.file
                ? values.name || t('profiles.editInfo.selectFile')
                : t('profiles.editInfo.selectFile')}
            </Button>
          </div>
        </SettingItem>
      )}
      {values.type === 'remote' && (
        <>
          <SettingItem title={t('profiles.editInfo.url')}>
            <Input
              size="sm"
              className={cn(inputWidth)}
              value={values.url}
              onValueChange={(v) => {
                setValues({ ...values, url: v })
              }}
            />
          </SettingItem>
          <SettingItem title={t('profiles.editInfo.authToken')}>
            <Input
              size="sm"
              type="password"
              className={cn(inputWidth)}
              value={values.authToken || ''}
              onValueChange={(v) => {
                setValues({ ...values, authToken: v })
              }}
              placeholder={t('profiles.editInfo.authTokenPlaceholder')}
            />
          </SettingItem>
          <SettingItem title={t('profiles.editInfo.userAgent')}>
            <Input
              size="sm"
              className={cn(inputWidth)}
              value={values.userAgent || ''}
              onValueChange={(v) => {
                setValues({ ...values, userAgent: v || undefined })
              }}
              placeholder={t('profiles.editInfo.userAgentPlaceholder')}
            />
          </SettingItem>
          <SettingItem title={t('profiles.editInfo.useProxy')}>
            <Switch
              size="sm"
              isSelected={values.useProxy ?? false}
              onValueChange={(v) => {
                setValues({ ...values, useProxy: v })
              }}
            />
          </SettingItem>
          <SettingItem title={t('profiles.editInfo.autoUpdate')}>
            <Switch
              size="sm"
              isSelected={values.autoUpdate ?? false}
              onValueChange={(v) => {
                setValues({ ...values, autoUpdate: v })
              }}
            />
          </SettingItem>
          {values.autoUpdate && (
            <>
              <SettingItem
                title={t('profiles.editInfo.interval')}
                actions={
                  <Tooltip
                    content={
                      typeof values.interval === 'number' ||
                      /^\d+$/.test(values.interval?.toString() || '')
                        ? t('profiles.editInfo.intervalMinutes')
                        : isValidCron(values.interval?.toString() || '', { seconds: false })
                          ? t('profiles.editInfo.intervalCron')
                          : t('profiles.editInfo.intervalHint')
                    }
                  >
                    <button
                      type="button"
                      aria-label={t('profiles.editInfo.intervalHint')}
                      className="ml-1.5 flex h-8 items-center text-foreground-500"
                    >
                      <MdInfoOutline className="text-sm" />
                    </button>
                  </Tooltip>
                }
              >
                <Input
                  size="sm"
                  type="text"
                  className={cn(
                    inputWidth,
                    // 不合法
                    typeof values.interval === 'string' &&
                      !/^\d+$/.test(values.interval) &&
                      !isValidCron(values.interval, { seconds: false }) &&
                      'border-red-500'
                  )}
                  value={values.interval?.toString() ?? ''}
                  onValueChange={(v) => {
                    // 输入限制
                    if (/^[\d\s*\-,/]*$/.test(v)) {
                      // 纯数字
                      if (/^\d+$/.test(v)) {
                        setValues({ ...values, interval: parseInt(v, 10) || 0 })
                        return
                      }
                      // 非纯数字
                      try {
                        setValues({ ...values, interval: v })
                      } catch {
                        // ignore
                      }
                    }
                  }}
                  placeholder={t('profiles.editInfo.intervalPlaceholder')}
                />
              </SettingItem>
              <SettingItem title={t('profiles.editInfo.fixedInterval')}>
                <Switch
                  size="sm"
                  isSelected={values.allowFixedInterval ?? false}
                  onValueChange={(v) => {
                    setValues({ ...values, allowFixedInterval: v })
                  }}
                />
              </SettingItem>
            </>
          )}
          <SettingItem title={t('profiles.editInfo.updateTimeout')}>
            <Input
              size="sm"
              type="text"
              className={cn(inputWidth)}
              value={values.updateTimeout?.toString() ?? ''}
              onValueChange={(v) => {
                if (v === '') {
                  setValues({ ...values, updateTimeout: undefined })
                  return
                }
                if (/^\d+$/.test(v)) {
                  setValues({ ...values, updateTimeout: parseInt(v, 10) })
                }
              }}
              placeholder={t('profiles.editInfo.updateTimeoutPlaceholder')}
            />
          </SettingItem>
        </>
      )}
      {!simpleMode && (
        <SettingItem title={t('profiles.editInfo.override.title')}>
          <div>
            {overrideItems
              .filter((i) => i.global)
              .map((i) => {
                return (
                  <div className="flex mb-2" key={i.id}>
                    <Button disabled fullWidth variant="flat" size="sm">
                      {i.name} ({t('profiles.editInfo.override.global')})
                    </Button>
                  </div>
                )
              })}
            {values.override?.map((i) => {
              if (!overrideItems.find((t) => t.id === i)) return null
              if (overrideItems.find((t) => t.id === i)?.global) return null
              return (
                <div className="flex mb-2" key={i}>
                  <Button disabled fullWidth variant="flat" size="sm">
                    {overrideItems.find((t) => t.id === i)?.name}
                  </Button>
                  <Button
                    color="warning"
                    variant="flat"
                    className="ml-2"
                    size="sm"
                    onPress={() => {
                      setValues({
                        ...values,
                        override: values.override?.filter((t) => t !== i)
                      })
                    }}
                  >
                    <MdDeleteForever className="text-lg" />
                  </Button>
                </div>
              )
            })}
            <Dropdown>
              <DropdownTrigger>
                <Button fullWidth size="sm" variant="flat" color="default">
                  <FaPlus />
                </Button>
              </DropdownTrigger>
              <DropdownMenu
                emptyContent={t('profiles.editInfo.override.noAvailable')}
                onAction={(key) => {
                  setValues({
                    ...values,
                    override: Array.from(values.override || []).concat(key.toString())
                  })
                }}
              >
                {overrideItems
                  .filter((i) => !values.override?.includes(i.id) && !i.global)
                  .map((i) => (
                    <DropdownItem key={i.id}>{i.name}</DropdownItem>
                  ))}
              </DropdownMenu>
            </Dropdown>
          </div>
        </SettingItem>
      )}
    </>
  )

  return (
    <Modal
      backdrop="blur"
      size="5xl"
      classNames={{
        backdrop: 'top-[48px]',
        base: simpleMode
          ? 'w-[min(720px,calc(100vw-32px))] max-h-[min(680px,calc(100dvh-96px))]'
          : 'w-[600px] md:w-[600px] lg:w-[800px] xl:w-[1024px]'
      }}
      hideCloseButton
      isOpen={true}
      onOpenChange={onClose}
      scrollBehavior="inside"
    >
      <ModalContent>
        <ModalHeader className="flex app-drag">
          {isImportMode ? t('profiles.import') : t('profiles.editInfo.title')}
        </ModalHeader>
        <ModalBody className={simpleMode ? 'pt-0' : undefined}>
          {simpleMode ? (
            <SimpleProviderOptions
              values={simpleOptions.providerOptions || {}}
              prefix={
                simpleOptions.prefix ?? `[${simpleOptions.providerName || values.name || '订阅'}] `
              }
              onPrefixChange={(prefix) => setSimpleOptions({ ...simpleOptions, prefix })}
              remote={values.type === 'remote'}
              group={simpleOptions.mode === 'group'}
              outbounds={outbounds}
              headers={providerHeaders}
              disabled={saving || (!isImportMode && !optionsLoaded)}
              onChange={(providerOptions) =>
                setSimpleOptions({ ...simpleOptions, providerOptions })
              }
              onHeadersChange={setProviderHeaders}
            >
              {subscriptionFields}
            </SimpleProviderOptions>
          ) : (
            subscriptionFields
          )}
        </ModalBody>
        <ModalFooter>
          <Button size="sm" variant="light" onPress={onClose}>
            {t('common.cancel')}
          </Button>
          <Button
            size="sm"
            color="primary"
            isDisabled={!canSave || saving}
            isLoading={saving}
            onPress={onSave}
          >
            {isImportMode ? t('profiles.import') : t('common.save')}
          </Button>
        </ModalFooter>
      </ModalContent>
    </Modal>
  )
}

export default EditInfoModal
