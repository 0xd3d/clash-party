export function parseDeveloperEnvironment(text: string): Record<string, string>
export function windowsDeveloperInvocation(
  developerCommand: string,
  arch: string
): { args: string[]; options: { windowsVerbatimArguments: true } }
export function windowsGuardCompilerArguments(arch: string, output: string): string[]
export function buildWindowsNetworkGuard(arch?: string): string
