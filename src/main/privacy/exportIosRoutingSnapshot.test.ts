import { mkdtemp, writeFile } from 'fs/promises'
import { tmpdir } from 'os'
import path from 'path'
import { describe, expect, it } from 'vitest'
import { buildIosRoutingSnapshotFromSources } from './exportIosRoutingSnapshotCore'

describe('buildIosRoutingSnapshotFromSources', () => {
  it('preserves order and strips node credentials from exported policy', async () => {
    const baseDir = await mkdtemp(path.join(tmpdir(), 'ios-export-'))
    await writeFile(
      path.join(baseDir, 'foreign.yaml'),
      'payload:\n  - +.claude.ai\n  - exact.example.org\n'
    )
    const config = {
      proxies: [{ uuid: 'must-not-export' }],
      rules: [
        'NETWORK,udp,Route',
        'RULE-SET,foreign,Route',
        'DOMAIN-SUFFIX,qq.com,DIRECT',
        'MATCH,Route'
      ],
      'rule-providers': {
        foreign: { type: 'file', behavior: 'domain', path: 'foreign.yaml', format: 'yaml' }
      }
    }
    const snapshot = await buildIosRoutingSnapshotFromSources(
      config,
      { Route: { now: 'Node' }, Node: {} },
      baseDir,
      '/usr/bin/false'
    )
    expect(snapshot.rules).toEqual([
      'NETWORK,udp,__IOS_PROXY__',
      'DOMAIN-SUFFIX,claude.ai,__IOS_PROXY__',
      'DOMAIN,exact.example.org,__IOS_PROXY__',
      'DOMAIN-SUFFIX,qq.com,DIRECT',
      'MATCH,__IOS_PROXY__'
    ])
    expect(JSON.stringify(snapshot)).not.toContain('must-not-export')
  })
})
