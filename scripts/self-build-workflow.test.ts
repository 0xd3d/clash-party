import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { parse } from 'yaml'

interface WorkflowStep {
  uses?: string
  run?: string
  with?: Record<string, unknown>
}

interface BuildJob {
  'runs-on': string
  env: Record<string, string>
  steps: WorkflowStep[]
}

describe('self-build workflow safety', () => {
  const source = readFileSync(
    new URL('../.github/workflows/self-build.yml', import.meta.url),
    'utf8'
  )
  const workflow = parse(source)

  it('is manual, read-only and uploads artifacts without any release or deployment action', () => {
    expect(Object.keys(workflow.on)).toEqual(['workflow_dispatch'])
    expect(workflow.permissions).toEqual({ contents: 'read' })
    expect(source).not.toContain('secrets.')
    for (const job of Object.values(workflow.jobs) as BuildJob[]) {
      const actions = job.steps.flatMap((step) => (step.uses ? [step.uses.split('@')[0]] : []))
      expect(actions).toContain('actions/upload-artifact')
      expect(
        actions.every((action) =>
          [
            'actions/checkout',
            'actions/setup-node',
            'pnpm/action-setup',
            'actions/upload-artifact'
          ].includes(action)
        )
      ).toBe(true)
      const commands = job.steps.map((step) => step.run ?? '').join('\n')
      expect(commands).not.toMatch(
        /gh\s+release|curl|telegram|pnpm\s+(?:run\s+)?updater|installer\s+-pkg|launchctl/
      )
      const checkout = job.steps.find((step) => step.uses?.startsWith('actions/checkout@'))
      expect(checkout?.with?.['persist-credentials']).toBe(false)
    }
  })

  it('prepares target resources on the corresponding OS and disables publication in build scripts', () => {
    const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'))
    for (const [name, job] of Object.entries(workflow.jobs) as [string, BuildJob][]) {
      expect(job['runs-on']).toBe(name === 'windows' ? 'windows-latest' : 'macos-latest')
      expect(job.env.npm_config_arch).toBe('${{ matrix.arch }}')
      expect(job.steps.some((step) => step.run === 'pnpm install --frozen-lockfile')).toBe(true)
      expect(pkg.scripts[name === 'windows' ? 'build:win' : 'build:mac']).toContain(
        '--publish never'
      )
    }
    expect(workflow.env.CLASH_PARTY_UPDATE_REPOSITORY).toBe('${{ github.repository }}')
    expect(workflow.env.CSC_IDENTITY_AUTO_DISCOVERY).toBe('false')
    expect(
      workflow.jobs.macos.steps.some((step: WorkflowStep) =>
        step.run?.includes('-c.mac.identity=-')
      )
    ).toBe(true)
  })
})
