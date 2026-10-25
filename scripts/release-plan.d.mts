export interface ReleasePlan {
  version: string
  tag: string
  commit: string
  prerelease: boolean
}
export function createReleasePlan(
  baseVersion: string,
  env: Record<string, string | undefined>
): ReleasePlan
