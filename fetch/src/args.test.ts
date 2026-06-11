import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { parseArgs, promptValue } from './args.js'

// parseArgs slices argv[2:], so prefix with two placeholders.
const argv = (...rest: string[]) => ['node', 'aauth-fetch', ...rest]

describe('parseArgs', () => {
  const originalEnv = { ...process.env }
  beforeEach(() => {
    for (const k of ['AAUTH_AGENT_URL', 'AAUTH_LOCAL', 'AAUTH_AUTH_TOKEN', 'AAUTH_SIGNING_KEY', 'AAUTH_ACCESS_TOKEN', 'AAUTH_PERSON_SERVER']) {
      delete process.env[k]
    }
  })
  afterEach(() => { process.env = { ...originalEnv } })

  it('has correct defaults', () => {
    const a = parseArgs(argv())
    expect(a).toMatchObject({
      method: 'GET', headers: [], jsonInput: false, agentOnly: false,
      nonInteractive: false, explain: false, debug: false, help: false, version: false,
    })
    expect(a.command).toBeUndefined()
    expect(a.url).toBeUndefined()
  })

  it('parses a URL positional (default fetch)', () => {
    const a = parseArgs(argv('https://api.example'))
    expect(a.command).toBeUndefined()
    expect(a.url).toBe('https://api.example')
  })

  it('parses the authorize command + url', () => {
    const a = parseArgs(argv('authorize', 'https://api.example/authorize', '--operations', 'a,b'))
    expect(a.command).toBe('authorize')
    expect(a.url).toBe('https://api.example/authorize')
    expect(a.operations).toBe('a,b')
  })

  it('parses the skill command + name', () => {
    const a = parseArgs(argv('skill', 'protocol'))
    expect(a.command).toBe('skill')
    expect(a.skillName).toBe('protocol')
  })

  it('parses curl-style request flags', () => {
    const a = parseArgs(argv('https://api.example', '-X', 'POST', '-d', '{"a":1}', '-H', 'x-a: 1', '-H', 'x-b: 2'))
    expect(a.method).toBe('POST')
    expect(a.data).toBe('{"a":1}')
    expect(a.headers).toEqual(['x-a: 1', 'x-b: 2'])
  })

  it('parses --json (stdin input)', () => {
    expect(parseArgs(argv('--json')).jsonInput).toBe(true)
  })

  it('parses --agent-provider (renamed from --agent-url)', () => {
    expect(parseArgs(argv('https://x', '--agent-provider', 'https://me.github.io')).agentProvider).toBe('https://me.github.io')
  })

  it('parses --local / --person-server / --auth-token / --signing-key', () => {
    const a = parseArgs(argv('https://x', '--local', 'claude', '--person-server', 'https://ps', '--auth-token', 'jwt', '--signing-key', '{}'))
    expect(a).toMatchObject({ local: 'claude', personServer: 'https://ps', authToken: 'jwt', signingKey: '{}' })
  })

  it('parses --aauth-access-token (flag and AAUTH_ACCESS_TOKEN env)', () => {
    expect(parseArgs(argv('https://x', '--aauth-access-token', 'tok-1')).opaqueToken).toBe('tok-1')
    process.env.AAUTH_ACCESS_TOKEN = 'tok-env'
    expect(parseArgs(argv('https://x')).opaqueToken).toBe('tok-env')
    // flag wins over env
    expect(parseArgs(argv('https://x', '--aauth-access-token', 'tok-flag')).opaqueToken).toBe('tok-flag')
  })

  it('parses --agent-only', () => {
    expect(parseArgs(argv('https://x', '--agent-only')).agentOnly).toBe(true)
  })

  it('parses person-server hints', () => {
    const a = parseArgs(argv('https://x', '--login-hint', 'u', '--domain-hint', 'd', '--tenant', 't', '--justification', 'why'))
    expect(a).toMatchObject({ loginHint: 'u', domainHint: 'd', tenant: 't', justification: 'why' })
  })

  it('parses --prompt-login / --prompt-consent and derives the wire prompt value', () => {
    expect(promptValue(parseArgs(argv('https://x')))).toBeUndefined()
    expect(promptValue(parseArgs(argv('https://x', '--prompt-consent')))).toBe('consent')
    expect(promptValue(parseArgs(argv('https://x', '--prompt-login')))).toBe('login')
    expect(promptValue(parseArgs(argv('https://x', '--prompt-login', '--prompt-consent')))).toBe('login consent')
  })

  it('ignores the removed --capabilities flag (and its value)', () => {
    const a = parseArgs(argv('https://x', '--capabilities', 'interaction,payment'))
    expect(a.url).toBe('https://x')
    expect((a as Record<string, unknown>).capabilities).toBeUndefined()
  })

  it('parses --browser and --non-interactive', () => {
    const a = parseArgs(argv('https://x', '--browser', '--non-interactive'))
    expect(a.browser).toBe(true)
    expect(a.nonInteractive).toBe(true)
  })

  it('treats -v / --verbose / --debug as debug (no exit)', () => {
    expect(parseArgs(argv('https://x', '-v')).debug).toBe(true)
    expect(parseArgs(argv('https://x', '--verbose')).debug).toBe(true)
    expect(parseArgs(argv('https://x', '--debug')).debug).toBe(true)
    // debug is distinct from explain
    expect(parseArgs(argv('https://x', '--debug')).explain).toBe(false)
  })

  it('parses --explain', () => {
    expect(parseArgs(argv('https://x', '--explain')).explain).toBe(true)
    expect(parseArgs(argv('https://x', '--explain')).debug).toBe(false)
  })

  it('parses --explain-log', () => {
    expect(parseArgs(argv('https://x', '--explain', '--explain-log', '/tmp/run.log')).explainLog).toBe('/tmp/run.log')
    expect(parseArgs(argv('https://x', '--explain')).explainLog).toBeUndefined()
  })

  it('treats --help / -h / --version as flags (no process.exit)', () => {
    expect(parseArgs(argv('--help')).help).toBe(true)
    expect(parseArgs(argv('-h')).help).toBe(true)
    expect(parseArgs(argv('--version')).version).toBe(true)
  })

  it('falls back to AAUTH_AGENT_URL → agentProvider; CLI wins', () => {
    process.env.AAUTH_AGENT_URL = 'https://env.example'
    expect(parseArgs(argv('https://x')).agentProvider).toBe('https://env.example')
    expect(parseArgs(argv('https://x', '--agent-provider', 'https://cli.example')).agentProvider).toBe('https://cli.example')
  })
})
