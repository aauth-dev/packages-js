import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { parseArgs } from './args.js'

describe('parseArgs', () => {
  const originalEnv = { ...process.env }
  const mockExit = vi.spyOn(process, 'exit').mockImplementation(() => {
    throw new Error('process.exit called')
  })

  beforeEach(() => {
    vi.clearAllMocks()
    delete process.env.AAUTH_AGENT_URL
    delete process.env.AAUTH_LOCAL
    delete process.env.AAUTH_AUTH_TOKEN
    delete process.env.AAUTH_SIGNING_KEY
    delete process.env.AAUTH_PERSON_SERVER
  })

  afterEach(() => {
    process.env = { ...originalEnv }
  })

  it('parses URL as positional arg', () => {
    const result = parseArgs(['node', 'cli.js', 'https://whoami.aauth.dev'])
    expect(result.url).toBe('https://whoami.aauth.dev')
  })

  it('has correct defaults', () => {
    const result = parseArgs(['node', 'cli.js', 'https://example.com'])
    expect(result.method).toBe('GET')
    expect(result.local).toBeUndefined()
    expect(result.skill).toBe(false)
    expect(result.authorize).toBe(false)
    expect(result.agentOnly).toBe(false)
    expect(result.jsonInput).toBe(false)
    expect(result.nonInteractive).toBe(false)
    expect(result.verbose).toBe(false)
    expect(result.headers).toEqual([])
    expect(result.browser).toBeUndefined()
  })

  it('parses -X / --method', () => {
    expect(parseArgs(['node', 'cli.js', '-X', 'POST', 'https://x.com']).method).toBe('POST')
    expect(parseArgs(['node', 'cli.js', '--method', 'PUT', 'https://x.com']).method).toBe('PUT')
  })

  it('parses -d / --data', () => {
    expect(parseArgs(['node', 'cli.js', '-d', '{"a":1}', 'https://x.com']).data).toBe('{"a":1}')
    expect(parseArgs(['node', 'cli.js', '--data', 'body', 'https://x.com']).data).toBe('body')
  })

  it('parses -H / --header as repeatable', () => {
    const result = parseArgs([
      'node', 'cli.js',
      '-H', 'Accept: text/plain',
      '-H', 'X-Custom: foo',
      'https://x.com',
    ])
    expect(result.headers).toEqual(['Accept: text/plain', 'X-Custom: foo'])
  })

  it('parses --json', () => {
    expect(parseArgs(['node', 'cli.js', '--json']).jsonInput).toBe(true)
  })

  it('parses --authorize', () => {
    expect(parseArgs(['node', 'cli.js', '--authorize', 'https://x.com']).authorize).toBe(true)
  })

  it('parses --agent-only', () => {
    expect(parseArgs(['node', 'cli.js', '--agent-only', 'https://x.com']).agentOnly).toBe(true)
  })

  it('parses --operations', () => {
    const result = parseArgs(['node', 'cli.js', '--operations', 'listNotes,createNote', 'https://x.com'])
    expect(result.operations).toBe('listNotes,createNote')
  })

  it('parses --scope', () => {
    const result = parseArgs(['node', 'cli.js', '--scope', 'email profile', 'https://x.com'])
    expect(result.scope).toBe('email profile')
  })

  it('parses --agent-url', () => {
    const result = parseArgs(['node', 'cli.js', '--agent-url', 'https://me.github.io', 'https://x.com'])
    expect(result.agentUrl).toBe('https://me.github.io')
  })

  it('parses --local', () => {
    const result = parseArgs(['node', 'cli.js', '--local', 'claude', 'https://x.com'])
    expect(result.local).toBe('claude')
  })

  it('parses --auth-token and --signing-key', () => {
    const result = parseArgs([
      'node', 'cli.js',
      '--auth-token', 'eyJ.test',
      '--signing-key', '{"kty":"OKP"}',
      'https://x.com',
    ])
    expect(result.authToken).toBe('eyJ.test')
    expect(result.signingKey).toBe('{"kty":"OKP"}')
  })

  it('parses --person-server', () => {
    const result = parseArgs(['node', 'cli.js', '--person-server', 'https://hello.coop', 'https://x.com'])
    expect(result.personServer).toBe('https://hello.coop')
  })

  it('parses --browser as true', () => {
    expect(parseArgs(['node', 'cli.js', '--browser', 'https://x.com']).browser).toBe(true)
  })

  it('parses --no-browser as false', () => {
    expect(parseArgs(['node', 'cli.js', '--no-browser', 'https://x.com']).browser).toBe(false)
  })

  it('parses --non-interactive', () => {
    expect(parseArgs(['node', 'cli.js', '--non-interactive', 'https://x.com']).nonInteractive).toBe(true)
  })

  it('parses -v / --verbose', () => {
    expect(parseArgs(['node', 'cli.js', '-v', 'https://x.com']).verbose).toBe(true)
    expect(parseArgs(['node', 'cli.js', '--verbose', 'https://x.com']).verbose).toBe(true)
  })

  it('parses --skill', () => {
    expect(parseArgs(['node', 'cli.js', '--skill']).skill).toBe(true)
  })

  it('exits on --help', () => {
    expect(() => parseArgs(['node', 'cli.js', '--help'])).toThrow('process.exit called')
    expect(mockExit).toHaveBeenCalledWith(1)
  })

  it('exits on -h', () => {
    expect(() => parseArgs(['node', 'cli.js', '-h'])).toThrow('process.exit called')
  })

  it('exits on unknown option', () => {
    expect(() => parseArgs(['node', 'cli.js', '--bogus', 'https://x.com'])).toThrow('process.exit called')
    expect(mockExit).toHaveBeenCalledWith(1)
  })

  // Env var fallbacks
  it('falls back to AAUTH_AGENT_URL', () => {
    process.env.AAUTH_AGENT_URL = 'https://env-agent.example.com'
    expect(parseArgs(['node', 'cli.js', 'https://x.com']).agentUrl).toBe('https://env-agent.example.com')
  })

  it('falls back to AAUTH_LOCAL', () => {
    process.env.AAUTH_LOCAL = 'env-local'
    expect(parseArgs(['node', 'cli.js', 'https://x.com']).local).toBe('env-local')
  })

  it('falls back to AAUTH_AUTH_TOKEN', () => {
    process.env.AAUTH_AUTH_TOKEN = 'env-token'
    expect(parseArgs(['node', 'cli.js', 'https://x.com']).authToken).toBe('env-token')
  })

  it('falls back to AAUTH_SIGNING_KEY', () => {
    process.env.AAUTH_SIGNING_KEY = '{"kty":"OKP"}'
    expect(parseArgs(['node', 'cli.js', 'https://x.com']).signingKey).toBe('{"kty":"OKP"}')
  })

  it('falls back to AAUTH_PERSON_SERVER', () => {
    process.env.AAUTH_PERSON_SERVER = 'https://ps.example.com'
    expect(parseArgs(['node', 'cli.js', 'https://x.com']).personServer).toBe('https://ps.example.com')
  })

  it('CLI args override env vars', () => {
    process.env.AAUTH_AGENT_URL = 'https://env.example.com'
    process.env.AAUTH_LOCAL = 'env-local'
    const result = parseArgs([
      'node', 'cli.js',
      '--agent-url', 'https://cli.example.com',
      '--local', 'cli-local',
      'https://x.com',
    ])
    expect(result.agentUrl).toBe('https://cli.example.com')
    expect(result.local).toBe('cli-local')
  })

  it('parses all options together', () => {
    const result = parseArgs([
      'node', 'cli.js',
      '--authorize',
      '-X', 'POST',
      '-d', '{"body":true}',
      '-H', 'X-Test: yes',
      '--agent-url', 'https://me.github.io',
      '--local', 'claude',
      '--scope', 'email',
      '--operations', 'listNotes',
      '--person-server', 'https://hello.coop',
      '--no-browser',
      '-v',
      'https://notes.aauth.dev',
    ])
    expect(result).toMatchObject({
      authorize: true,
      method: 'POST',
      data: '{"body":true}',
      headers: ['X-Test: yes'],
      agentUrl: 'https://me.github.io',
      local: 'claude',
      scope: 'email',
      operations: 'listNotes',
      personServer: 'https://hello.coop',
      browser: false,
      verbose: true,
      url: 'https://notes.aauth.dev',
    })
  })
})
