export interface ReleaseRepositoryEnvironment {
  CLASH_PARTY_UPDATE_REPOSITORY?: string
  GITHUB_REPOSITORY?: string
}

export function validateReleaseRepository(repository: unknown): string
export function resolveReleaseRepository(
  packageRepository: unknown,
  env?: ReleaseRepositoryEnvironment
): string
export function getReleaseRepository(env?: ReleaseRepositoryEnvironment): string
