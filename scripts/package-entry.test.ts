import { createRequire } from 'node:module'
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import { describe, expect, it } from 'vitest'
const require = createRequire(import.meta.url)
const asar = require('@electron/asar') as {
  createPackage(source: string, destination: string): Promise<void>
  extractFile(archive: string, file: string): Buffer
}
describe('cross-platform packaged entry validation', () => {
  it('normalizes the declared forward-slash entry before accessing ASAR on the native host', async () => {
    const dir = await mkdtemp(path.join(os.tmpdir(), 'clash-entry-'))
    try {
      const source = path.join(dir, 'source')
      await mkdir(path.join(source, 'out', 'main'), { recursive: true })
      const main = './out/main/index.js'
      await writeFile(path.join(source, 'package.json'), JSON.stringify({ main }))
      await writeFile(path.join(source, 'out', 'main', 'index.js'), 'const packaged = true')
      const archive = path.join(dir, 'app.asar')
      await asar.createPackage(source, archive)
      const pkg = JSON.parse(asar.extractFile(archive, 'package.json').toString()) as {
        main: string
      }
      expect(asar.extractFile(archive, path.normalize(pkg.main)).toString()).toBe(
        'const packaged = true'
      )
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })
})
