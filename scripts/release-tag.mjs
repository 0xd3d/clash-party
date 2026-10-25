import { spawnSync } from 'node:child_process'
import { validateReleaseRepository } from './release-repository.mjs'

function githubRequest(method, endpoint, fields = {}) {
  const args = ['api', '--include', '--method', method, endpoint]
  for (const [key, value] of Object.entries(fields)) args.push('-f', `${key}=${value}`)
  const result = spawnSync('gh', args, { encoding: 'utf8' })
  if (result.error) throw result.error
  const output = (result.stdout ?? '').replace(/\r\n/g, '\n')
  const status = output.match(/^HTTP\/\S+\s+(\d{3})\b/)
  const body = output.indexOf('\n\n')
  if (!status || body < 0) throw new Error(`GitHub API request failed: ${result.stderr}`)
  return { status: Number(status[1]), data: JSON.parse(output.slice(body + 2)) }
}

export function resolveReleaseTag(repository, tag, request = githubRequest) {
  validateReleaseRepository(repository)
  const root = `repos/${repository}/git`
  const ref = request('GET', `${root}/ref/tags/${encodeURIComponent(tag)}`)
  if (ref.status === 404) return null
  if (ref.status !== 200) throw new Error(`Cannot read release tag (HTTP ${ref.status})`)
  let object = ref.data?.object
  const seen = new Set()
  for (let depth = 0; depth <= 8; depth++) {
    if (!/^[a-f0-9]{40}$/.test(object?.sha ?? '')) throw new Error('Invalid release tag object')
    if (object.type === 'commit') return object.sha
    if (object.type !== 'tag' || seen.has(object.sha)) throw new Error('Invalid release tag chain')
    if (depth === 8) throw new Error('Release tag exceeds eight annotated tag levels')
    seen.add(object.sha)
    const annotated = request('GET', `${root}/tags/${object.sha}`)
    if (annotated.status !== 200)
      throw new Error(`Cannot peel release tag (HTTP ${annotated.status})`)
    object = annotated.data?.object
  }
  throw new Error('Invalid release tag chain')
}

export function assertReleaseTag(repository, plan, request = githubRequest) {
  const commit = resolveReleaseTag(repository, plan.tag, request)
  if (commit !== plan.commit) throw new Error('Release tag is missing or points to another commit')
}

export function reserveReleaseTag(repository, plan, request = githubRequest) {
  const existing = resolveReleaseTag(repository, plan.tag, request)
  if (existing !== null) {
    if (existing !== plan.commit) throw new Error('Existing release tag points to another commit')
    return
  }
  const created = request('POST', `repos/${repository}/git/refs`, {
    ref: `refs/tags/${plan.tag}`,
    sha: plan.commit
  })
  if (created.status !== 201 && created.status !== 422) {
    throw new Error(
      `Cannot reserve release tag (HTTP ${created.status}). If the branch has advanced, an authorized administrator must pre-create ${plan.tag} at ${plan.commit}; never move an existing tag.`
    )
  }
  // A concurrent creator is accepted only when the actual remote ref resolves to this exact source.
  assertReleaseTag(repository, plan, request)
}
