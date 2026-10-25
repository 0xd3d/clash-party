import { readFileSync } from 'node:fs'

export function validateReleaseRepository(repository) {
  if (
    typeof repository !== 'string' ||
    !/^[A-Za-z0-9][A-Za-z0-9-]{0,38}\/[A-Za-z0-9_.-]{1,100}$/.test(repository) ||
    ['.', '..'].includes(repository.split('/')[1])
  ) {
    throw new Error('Update repository must be a GitHub owner/repo name')
  }
  return repository
}

export function resolveReleaseRepository(packageRepository, env = {}) {
  const override = env.CLASH_PARTY_UPDATE_REPOSITORY || env.GITHUB_REPOSITORY
  if (override) return validateReleaseRepository(override.trim())

  const value = typeof packageRepository === 'string' ? packageRepository : packageRepository?.url
  if (typeof value !== 'string') throw new Error('package.json must declare its GitHub repository')
  const repository = value.replace(/^(?:git\+)?https:\/\/github\.com\//, '').replace(/\.git$/, '')
  return validateReleaseRepository(repository)
}

export function getReleaseRepository(env = process.env) {
  const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'))
  return resolveReleaseRepository(pkg.repository, env)
}
