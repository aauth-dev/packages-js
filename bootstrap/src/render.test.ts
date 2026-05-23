import { describe, it, expect } from 'vitest'
import type { BackendInfo } from '@aauth/local-keys'
import {
  shapeKeystores,
  renderSkillListMarkdown,
  topLevelHelp,
  COMMAND_HELP,
  colorizeJson,
} from './render.js'
import type { SkillSummary } from './skills.js'

describe('shapeKeystores', () => {
  it('maps BackendInfo to the keystore output shape', () => {
    const backends: BackendInfo[] = [
      { backend: 'software', description: 'OS keychain', algorithms: ['EdDSA', 'ES256'], deviceId: 'local' },
      { backend: 'secure-enclave', description: 'macOS Secure Enclave', algorithms: ['ES256'], deviceId: 'local' },
    ]
    expect(shapeKeystores(backends)).toEqual([
      { keystore: 'software', description: 'OS keychain', algorithms: ['EdDSA', 'ES256'] },
      { keystore: 'secure-enclave', description: 'macOS Secure Enclave', algorithms: ['ES256'] },
    ])
  })

  it('returns an empty array for no backends', () => {
    expect(shapeKeystores([])).toEqual([])
  })
})

describe('renderSkillListMarkdown', () => {
  const skills: SkillSummary[] = [
    { name: 'setup', description: 'Set up an agent identity', when: '' },
    { name: 'github-pages', description: 'Publish to GitHub Pages', when: '' },
  ]

  it('renders a markdown title and a ## heading per skill (not bold, not JSON)', () => {
    const md = renderSkillListMarkdown(skills)
    expect(md).toContain('# AAuth bootstrap skills')
    expect(md).toContain('## setup')
    expect(md).toContain('Set up an agent identity')
    expect(md).toContain('## github-pages')
    expect(md).not.toContain('**setup**')
    expect(md.trimStart().startsWith('[')).toBe(false) // not a JSON array
  })

  it('points at `skill <name>`', () => {
    expect(renderSkillListMarkdown(skills)).toContain('skill <name>')
  })
})

describe('help text', () => {
  it('top-level help shows the version and the v1 commands', () => {
    const help = topLevelHelp('1.2.3')
    expect(help).toContain('v1.2.3')
    for (const cmd of ['list', 'create', 'delete', 'token', 'skill', 'help']) {
      expect(help).toContain(cmd)
    }
    // GLOBAL section was dropped; --version/--help are silent aliases.
    expect(help).not.toContain('GLOBAL')
  })

  it('has per-command help for every v1 command', () => {
    for (const cmd of ['list', 'create', 'delete', 'token', 'skill', 'help']) {
      expect(COMMAND_HELP[cmd]).toBeTruthy()
      expect(COMMAND_HELP[cmd]).toContain('DESCRIPTION')
    }
  })

  it('result-bearing commands include an EXAMPLE with a sample response', () => {
    for (const cmd of ['list', 'create', 'delete', 'token', 'skill']) {
      expect(COMMAND_HELP[cmd]).toContain('EXAMPLE')
      expect(COMMAND_HELP[cmd]).toContain('$ npx @aauth/bootstrap')
    }
  })
})

describe('colorizeJson', () => {
  const json = JSON.stringify({ a: 'hi', n: 42, b: true, z: null }, null, 2)

  it('adds ANSI codes', () => {
    const out = colorizeJson(json)
    expect(out).toContain('\x1b[') // has color
    expect(out).not.toBe(json)
  })

  it('is purely additive — stripping ANSI yields the original JSON', () => {
    const stripped = colorizeJson(json).replace(/\x1b\[[0-9]*m/g, '')
    expect(stripped).toBe(json)
    expect(JSON.parse(stripped)).toEqual({ a: 'hi', n: 42, b: true, z: null })
  })
})
