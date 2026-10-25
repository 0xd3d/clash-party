export function validateReleaseVersion(version: string): void {
  if (
    !/^\d+\.\d+\.\d+(?:-[A-Za-z0-9]+(?:[.-][A-Za-z0-9]+)*)?(?:\+[A-Za-z0-9]+(?:[.-][A-Za-z0-9]+)*)?$/.test(
      version
    )
  ) {
    throw new Error('Invalid update version')
  }
}

export function latestReleaseMetadataUrl(repository = __UPDATE_REPOSITORY__): string {
  return `https://github.com/${repository}/releases/latest/download/latest.yml`
}

export function releaseUrls(
  version: string,
  repository = __UPDATE_REPOSITORY__
): { page: string; api: string; download: string } {
  validateReleaseVersion(version)
  const tag = encodeURIComponent(`v${version}`)
  return {
    page: `https://github.com/${repository}/releases/tag/${tag}`,
    api: `https://api.github.com/repos/${repository}/releases/tags/${tag}`,
    download: `https://github.com/${repository}/releases/download/${tag}/`
  }
}
