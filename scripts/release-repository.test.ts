import { afterEach, describe, expect, it, vi } from 'vitest'
import { getReleaseRepository, resolveReleaseRepository } from './release-repository.mjs'
import { getDownloadUrl } from './version-utils.mjs'

afterEach(() => vi.unstubAllEnvs())

describe('release repository', () => {
  it('uses package metadata for local builds', () => {
    expect(getReleaseRepository({})).toBe('0xd3d/clash-party')
    expect(resolveReleaseRepository({ url: 'https://github.com/example/client.git' })).toBe(
      'example/client'
    )
    expect(resolveReleaseRepository('git+https://github.com/example/client.git')).toBe(
      'example/client'
    )
  })

  it('uses the Actions repository unless an explicit build override is supplied', () => {
    const metadata = { url: 'https://github.com/example/local.git' }
    expect(resolveReleaseRepository(metadata, { GITHUB_REPOSITORY: 'another/fork' })).toBe(
      'another/fork'
    )
    expect(
      resolveReleaseRepository(metadata, {
        GITHUB_REPOSITORY: 'another/fork',
        CLASH_PARTY_UPDATE_REPOSITORY: ' custom/releases '
      })
    ).toBe('custom/releases')
  })

  it.each([
    '',
    'owner',
    '/repo',
    'owner/repo/other',
    'owner/..',
    'owner/.',
    'owner/repo?branch=main',
    'owner/repo#main',
    'owner/repo\nother',
    'https://example.com/owner/repo',
    'https://github.com/owner/repo'
  ])('rejects invalid explicit repositories without falling back: %j', (repository) => {
    expect(() =>
      resolveReleaseRepository('fallback/client', {
        CLASH_PARTY_UPDATE_REPOSITORY: repository || ' ',
        GITHUB_REPOSITORY: 'actions/client'
      })
    ).toThrow('owner/repo')
  })

  it('requires package repository metadata when no build override is present', () => {
    expect(() => resolveReleaseRepository(undefined)).toThrow('package.json')
    expect(() => resolveReleaseRepository('https://example.com/owner/repo.git')).toThrow(
      'owner/repo'
    )
  })

  it('uses the same resolved repository for release note download links', () => {
    vi.stubEnv('GITHUB_REPOSITORY', 'example/actions-fork')
    vi.stubEnv('CLASH_PARTY_UPDATE_REPOSITORY', '')
    expect(getDownloadUrl(false, '2.0.5')).toBe(
      'https://github.com/example/actions-fork/releases/download/v2.0.5'
    )
    vi.stubEnv('CLASH_PARTY_UPDATE_REPOSITORY', 'example/custom-fork')
    expect(getDownloadUrl(true, '2.0.5-d1025.abcdef0')).toBe(
      'https://github.com/example/custom-fork/releases/download/dev'
    )
  })
})
