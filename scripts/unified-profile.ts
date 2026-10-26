import { readFileSync, writeFileSync } from 'node:fs'
import { parse, stringify } from 'yaml'
import {
  compileUnifiedProfile,
  unifiedPlatforms,
  type UnifiedPlatform
} from '../src/shared/unifiedProfile'

// No profile, node or credential values are printed. Outputs stay local and are never applied.
const [command, input, platform, output] = process.argv.slice(2)
if (!input || !['check', 'render'].includes(command)) {
  throw new Error(
    'Usage: tsx scripts/unified-profile.ts check FILE | render FILE macos|windows|ios OUTPUT'
  )
}
const source = JSON.parse(readFileSync(input, 'utf8'))
if (command === 'check') {
  for (const target of unifiedPlatforms) {
    const profile = compileUnifiedProfile(source, target)
    process.stdout.write(
      `${target}: schema accepted, ${(profile.rules as string[]).length} rules; core/network tests still required\n`
    )
  }
} else {
  if (!unifiedPlatforms.includes(platform as UnifiedPlatform) || !output)
    throw new Error('A platform and output file are required')
  const rendered = stringify(compileUnifiedProfile(source, platform as UnifiedPlatform))
  // Verify serializer round trip before creating a private, non-overwriting output file.
  if (!parse(rendered)) throw new Error('Invalid rendered profile')
  writeFileSync(output, rendered, { mode: 0o600, flag: 'wx' })
  process.stdout.write('Platform profile exported; no running application was changed.\n')
}
