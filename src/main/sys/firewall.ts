export type FirewallRule = { name: string; program: string }
export type FirewallCommandFailure = Error & {
  stdout?: string
  stderr?: string
  code?: string | number
}

type FirewallActions = {
  isAdministrator(): Promise<boolean>
  execute(args: string[]): Promise<unknown>
  adminRequired: string
  commandFailed: string
}

/** Preflight before any deletion; never resets policy, disables services or releases guards. */
export async function configureFirewallRules(
  rules: FirewallRule[],
  actions: FirewallActions
): Promise<void> {
  if (!(await actions.isAdministrator())) throw new Error(actions.adminRequired)
  for (const rule of rules) {
    // Keep the previous allow-rule scope. Limit removal to this exact executable,
    // rather than removing unrelated applications' rules with a shared name.
    await actions
      .execute([
        'advfirewall',
        'firewall',
        'delete',
        'rule',
        `name=${rule.name}`,
        `program=${rule.program}`
      ])
      .catch(() => {})
    try {
      await actions.execute([
        'advfirewall',
        'firewall',
        'add',
        'rule',
        `name=${rule.name}`,
        'dir=in',
        'action=allow',
        `program=${rule.program}`,
        'enable=yes',
        'profile=any'
      ])
    } catch (error) {
      const failure =
        error && typeof error === 'object' ? (error as FirewallCommandFailure) : undefined
      const output = [failure?.stdout, failure?.stderr]
        .filter((value): value is string => typeof value === 'string' && value.trim().length > 0)
        .map((value) => value.trim())
        .join('\n')
      throw new Error(
        `${actions.commandFailed}\n${rule.name}: ${rule.program}\n${failure?.code === undefined ? '' : `Exit: ${failure.code}\n`}${(output || failure?.message || String(error)).slice(0, 8192)}`,
        { cause: error }
      )
    }
  }
}
