import type { ReleasePlan } from './release-plan.mjs'

export interface GitHubResponse {
  status: number
  data?: unknown
}
export type GitHubRequest = (
  method: 'GET' | 'POST',
  endpoint: string,
  fields?: Record<string, string>
) => GitHubResponse
export function resolveReleaseTag(
  repository: string,
  tag: string,
  request?: GitHubRequest
): string | null
export function assertReleaseTag(
  repository: string,
  plan: ReleasePlan,
  request?: GitHubRequest
): void
export function reserveReleaseTag(
  repository: string,
  plan: ReleasePlan,
  request?: GitHubRequest
): void
