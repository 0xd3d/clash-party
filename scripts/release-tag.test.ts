import { describe, expect, it, vi } from 'vitest'
import {
  assertReleaseTag,
  reserveReleaseTag,
  resolveReleaseTag,
  type GitHubRequest
} from './release-tag.mjs'
import { createReleasePlan } from './release-plan.mjs'

const repository = 'example/fork'
const commit = 'a'.repeat(40)
const other = 'b'.repeat(40)
const plan = createReleasePlan('2.0.4', {
  GITHUB_SHA: commit,
  GITHUB_REF: 'refs/heads/smart_core',
  GITHUB_RUN_NUMBER: '4',
  GITHUB_RUN_ATTEMPT: '1'
})
const ref = `repos/${repository}/git/ref/tags/${plan.tag}`
const object = (sha = commit, type = 'commit') => ({ status: 200, data: { object: { sha, type } } })

describe('immutable remote release tags', () => {
  it('resolves lightweight and nested annotated tags to the actual commit', () => {
    const request = vi
      .fn<GitHubRequest>()
      .mockReturnValueOnce(object(other, 'tag'))
      .mockReturnValueOnce(object('c'.repeat(40), 'tag'))
      .mockReturnValueOnce(object())
    expect(resolveReleaseTag(repository, plan.tag, request)).toBe(commit)
    expect(request.mock.calls.map(([, endpoint]) => endpoint)).toEqual([
      ref,
      `repos/${repository}/git/tags/${other}`,
      `repos/${repository}/git/tags/${'c'.repeat(40)}`
    ])
  })

  it('never writes an existing tag that already matches the plan', () => {
    const request = vi.fn<GitHubRequest>().mockReturnValue(object())
    reserveReleaseTag(repository, plan, request)
    expect(request.mock.calls).toEqual([['GET', ref]])
  })

  it('creates a missing ref at the exact planned source and reads it back', () => {
    const request = vi
      .fn<GitHubRequest>()
      .mockReturnValueOnce({ status: 404 })
      .mockReturnValueOnce({ status: 201 })
      .mockReturnValueOnce(object())
    reserveReleaseTag(repository, plan, request)
    expect(request.mock.calls).toEqual([
      ['GET', ref],
      ['POST', `repos/${repository}/git/refs`, { ref: `refs/tags/${plan.tag}`, sha: commit }],
      ['GET', ref]
    ])
  })

  it('accepts a simultaneous creator only after checking its ref source', () => {
    const request = vi
      .fn<GitHubRequest>()
      .mockReturnValueOnce({ status: 404 })
      .mockReturnValueOnce({ status: 422 })
      .mockReturnValueOnce(object())
    expect(() => reserveReleaseTag(repository, plan, request)).not.toThrow()
    request
      .mockReset()
      .mockReturnValueOnce({ status: 404 })
      .mockReturnValueOnce({ status: 422 })
      .mockReturnValueOnce(object(other))
    expect(() => reserveReleaseTag(repository, plan, request)).toThrow('another commit')
  })

  it('fails explicitly on the remaining reservation race instead of granting broader permissions', () => {
    const request = vi
      .fn<GitHubRequest>()
      .mockReturnValueOnce({ status: 404 })
      .mockReturnValueOnce({ status: 403 })
    expect(() => reserveReleaseTag(repository, plan, request)).toThrow(
      `an authorized administrator must pre-create ${plan.tag} at ${commit}`
    )
    expect(request).toHaveBeenCalledTimes(2)
  })

  it('refuses missing and conflicting source tags before publication', () => {
    expect(() => assertReleaseTag(repository, plan, () => ({ status: 404 }))).toThrow('missing')
    const request = vi.fn<GitHubRequest>().mockReturnValue(object(other))
    expect(() => reserveReleaseTag(repository, plan, request)).toThrow('another commit')
    expect(request.mock.calls).toEqual([['GET', ref]])
  })

  it('does not treat an authorization failure as a missing tag', () => {
    const request = vi.fn<GitHubRequest>().mockReturnValue({ status: 403 })
    expect(() => reserveReleaseTag(repository, plan, request)).toThrow('HTTP 403')
    expect(request.mock.calls).toEqual([['GET', ref]])
  })

  it('rejects cycles, invalid targets and excessive annotated nesting', () => {
    const cycle = vi.fn<GitHubRequest>().mockReturnValue(object(other, 'tag'))
    expect(() => resolveReleaseTag(repository, plan.tag, cycle)).toThrow('chain')
    expect(cycle).toHaveBeenCalledTimes(2)
    expect(() => resolveReleaseTag(repository, plan.tag, () => object(commit, 'tree'))).toThrow(
      'chain'
    )
    let index = 1
    const deep = vi.fn<GitHubRequest>(() => object((index++).toString(16).padStart(40, '0'), 'tag'))
    expect(() => resolveReleaseTag(repository, plan.tag, deep)).toThrow('eight')
    expect(deep).toHaveBeenCalledTimes(9)
  })
})
