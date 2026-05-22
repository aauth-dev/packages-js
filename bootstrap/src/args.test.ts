import { describe, it, expect } from 'vitest'
import { parseArgs } from './args.js'

describe('parseArgs', () => {
  it('parses a bare invocation (no command)', () => {
    const r = parseArgs([])
    expect(r.command).toBeUndefined()
    expect(r.positional).toEqual([])
  })

  it('parses a command with a positional URL', () => {
    const r = parseArgs(['create', 'https://me.github.io'])
    expect(r.command).toBe('create')
    expect(r.positional[1]).toBe('https://me.github.io')
  })

  it('parses value flags', () => {
    const r = parseArgs([
      'create', 'https://me.github.io',
      '--keystore', 'secure-enclave',
      '--algorithm', 'ES256',
      '--person-server', 'https://person.example',
    ])
    expect(r.flags.keystore).toBe('secure-enclave')
    expect(r.flags.algorithm).toBe('ES256')
    expect(r.flags['person-server']).toBe('https://person.example')
  })

  it('treats --help / -h as help, --version as version', () => {
    expect(parseArgs(['list', '--help']).help).toBe(true)
    expect(parseArgs(['-h']).help).toBe(true)
    expect(parseArgs(['--version']).version).toBe(true)
  })

  it('parses token flags including --local and --lifetime', () => {
    const r = parseArgs(['token', '--local', 'claude', '--lifetime', '600'])
    expect(r.command).toBe('token')
    expect(r.flags.local).toBe('claude')
    expect(r.flags.lifetime).toBe('600')
  })

  it('keeps a URL positional that follows a boolean-only context', () => {
    const r = parseArgs(['delete', 'https://me.github.io'])
    expect(r.positional).toEqual(['delete', 'https://me.github.io'])
    expect(r.command).toBe('delete')
  })

  it('reads the skill name as the second positional', () => {
    const r = parseArgs(['skill', 'github-pages'])
    expect(r.command).toBe('skill')
    expect(r.positional[1]).toBe('github-pages')
  })
})
