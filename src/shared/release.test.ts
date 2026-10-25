import { describe, expect, it } from 'vitest'
import { latestReleaseMetadataUrl, releaseUrls } from './release'

describe('fork update URLs', () => {
  const repository = 'example/custom-fork'

  it('keeps metadata, integrity checks, downloads and the release page in one repository', () => {
    expect(latestReleaseMetadataUrl(repository)).toBe(
      'https://github.com/example/custom-fork/releases/latest/download/latest.yml'
    )
    expect(releaseUrls('2.0.5', repository)).toEqual({
      page: 'https://github.com/example/custom-fork/releases/tag/v2.0.5',
      api: 'https://api.github.com/repos/example/custom-fork/releases/tags/v2.0.5',
      download: 'https://github.com/example/custom-fork/releases/download/v2.0.5/'
    })
  })

  it('preserves prerelease versions and encodes build metadata in a single tag segment', () => {
    expect(releaseUrls('2.0.5-d1025.abcdef0+local.1', repository).page).toBe(
      'https://github.com/example/custom-fork/releases/tag/v2.0.5-d1025.abcdef0%2Blocal.1'
    )
  })

  it.each(['', 'v2.0.5', '2.0', '../2.0.5', '2.0.5/other', '2.0.5;command', '2.0.5\n'])(
    'rejects malformed update metadata before creating download paths: %j',
    (version) => {
      expect(() => releaseUrls(version, repository)).toThrow('Invalid update version')
    }
  )
})
