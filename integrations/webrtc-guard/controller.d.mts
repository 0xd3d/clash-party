export const TARGET_POLICY: 'disable_non_proxied_udp'

export interface BrowserSettingValue {
  value: string
  levelOfControl: string
  incognitoSpecific?: boolean
}

export interface BrowserSettingAPI {
  get(details: { incognito: boolean }, callback: (value: BrowserSettingValue) => void): void
  set(details: { value: string; scope: 'regular' }, callback: () => void): void
  clear(details: { scope: 'regular' }, callback: () => void): void
}

export interface BrowserRuntimeAPI {
  lastError?: { message?: string }
}

export type GuardResultCode =
  | 'enabled'
  | 'already_enabled'
  | 'managed'
  | 'other_extension'
  | 'unavailable'
  | 'verification_failed'
  | 'error'
  | 'restored'
  | 'not_owned'
  | 'unchanged'

export interface GuardResult {
  ok: boolean
  code: GuardResultCode
}

export type GuardSnapshot = ({ readable: true } & BrowserSettingValue) | { readable: false }

export interface WebRTCGuard {
  status(): Promise<{ regular: GuardSnapshot; incognito: GuardSnapshot }>
  enable(): Promise<GuardResult>
  restore(): Promise<GuardResult>
  initialize(freshInstall?: boolean): Promise<GuardResult>
}

export function createWebRTCGuard(
  setting: BrowserSettingAPI,
  runtime?: BrowserRuntimeAPI
): WebRTCGuard
