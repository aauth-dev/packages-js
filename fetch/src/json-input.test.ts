import { describe, it, expect } from 'vitest'
import { mergeJsonInput } from './json-input.js'
import type { FetchArgs } from './args.js'

function baseArgs(overrides?: Partial<FetchArgs>): FetchArgs {
  return {
    agentOnly: false,
    method: 'GET',
    headers: [],
    jsonInput: true,
    nonInteractive: false,
    verbose: false,
    help: false,
    version: false,
    url: 'https://default.example.com',
    ...overrides,
  }
}

describe('mergeJsonInput', () => {
  it('overrides url from JSON', () => {
    const result = mergeJsonInput(baseArgs(), { url: 'https://json.example.com' })
    expect(result.url).toBe('https://json.example.com')
  })

  it('overrides method from JSON', () => {
    const result = mergeJsonInput(baseArgs(), { url: 'https://x.com', method: 'POST' })
    expect(result.method).toBe('POST')
  })

  it('converts JSON headers object to key: value strings', () => {
    const result = mergeJsonInput(baseArgs({ headers: ['Existing: yes'] }), {
      url: 'https://x.com',
      headers: { 'Content-Type': 'application/json', 'X-Custom': 'val' },
    })
    expect(result.headers).toEqual([
      'Content-Type: application/json',
      'X-Custom: val',
    ])
  })

  it('keeps CLI headers when JSON has no headers', () => {
    const result = mergeJsonInput(baseArgs({ headers: ['Keep: this'] }), {
      url: 'https://x.com',
    })
    expect(result.headers).toEqual(['Keep: this'])
  })

  it('stringifies JSON body object', () => {
    const result = mergeJsonInput(baseArgs(), {
      url: 'https://x.com',
      body: { title: 'hello', content: 'world' },
    })
    expect(result.data).toBe('{"title":"hello","content":"world"}')
  })

  it('stringifies JSON body string', () => {
    const result = mergeJsonInput(baseArgs(), {
      url: 'https://x.com',
      body: 'raw string',
    })
    expect(result.data).toBe('"raw string"')
  })

  it('does not override data when body is undefined', () => {
    const result = mergeJsonInput(baseArgs({ data: 'existing' }), {
      url: 'https://x.com',
    })
    expect(result.data).toBe('existing')
  })

  it('overrides authToken from JSON', () => {
    const result = mergeJsonInput(baseArgs(), {
      url: 'https://x.com',
      authToken: 'eyJ.json.token',
    })
    expect(result.authToken).toBe('eyJ.json.token')
  })

  it('stringifies signingKey object from JSON', () => {
    const key = { kty: 'OKP', crv: 'Ed25519', x: 'abc', d: 'secret' }
    const result = mergeJsonInput(baseArgs(), {
      url: 'https://x.com',
      signingKey: key,
    })
    expect(result.signingKey).toBe(JSON.stringify(key))
  })

  it('keeps CLI signingKey when JSON has none', () => {
    const result = mergeJsonInput(baseArgs({ signingKey: '{"existing":true}' }), {
      url: 'https://x.com',
    })
    expect(result.signingKey).toBe('{"existing":true}')
  })

  it('overrides agentProvider, local, operations, scope, personServer', () => {
    const result = mergeJsonInput(baseArgs(), {
      url: 'https://x.com',
      agentProvider: 'https://json-agent.com',
      local: 'json-local',
      operations: 'listNotes',
      scope: 'email',
      personServer: 'https://json-ps.com',
    })
    expect(result.agentProvider).toBe('https://json-agent.com')
    expect(result.local).toBe('json-local')
    expect(result.operations).toBe('listNotes')
    expect(result.scope).toBe('email')
    expect(result.personServer).toBe('https://json-ps.com')
  })

  it('overrides the agentOnly boolean', () => {
    const result = mergeJsonInput(baseArgs(), { url: 'https://x.com', agentOnly: true })
    expect(result.agentOnly).toBe(true)
  })

  it('does not override booleans when JSON fields are undefined', () => {
    const result = mergeJsonInput(baseArgs({ agentOnly: true }), { url: 'https://x.com' })
    expect(result.agentOnly).toBe(true)
  })

  it('preserves non-overridable args from CLI', () => {
    const result = mergeJsonInput(
      baseArgs({ skill: false, verbose: true, nonInteractive: true, browser: false }),
      { url: 'https://x.com' },
    )
    expect(result.verbose).toBe(true)
    expect(result.nonInteractive).toBe(true)
    expect(result.browser).toBe(false)
  })
})
