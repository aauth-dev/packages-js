import { describe, it, expect } from 'vitest'
import {
  parseAAuthHeader,
  buildCapabilitiesHeader,
  parseCapabilitiesHeader,
  buildMissionHeader,
  parseMissionHeader,
} from './aauth-header.js'

describe('parseAAuthHeader', () => {
  it('parses requirement=approval', () => {
    const result = parseAAuthHeader('requirement=approval')
    expect(result).toEqual({ requirement: 'approval' })
  })

  it('parses requirement=auth-token with resource-token', () => {
    const header = 'requirement=auth-token; resource-token="eyJhbGciOiJFZERTQSJ9.test"'
    const result = parseAAuthHeader(header)
    expect(result).toEqual({
      requirement: 'auth-token',
      resourceToken: 'eyJhbGciOiJFZERTQSJ9.test',
    })
  })

  it('parses requirement=interaction with url and code', () => {
    const header = 'requirement=interaction; url="https://auth.example/interact"; code="ABCD1234"'
    const result = parseAAuthHeader(header)
    expect(result).toEqual({
      requirement: 'interaction',
      url: 'https://auth.example/interact',
      code: 'ABCD1234',
    })
  })

  it('handles extra whitespace', () => {
    const header = '  requirement=auth-token ;  resource-token="tok123"  '
    const result = parseAAuthHeader(header)
    expect(result).toEqual({
      requirement: 'auth-token',
      resourceToken: 'tok123',
    })
  })

  it('throws on empty header', () => {
    expect(() => parseAAuthHeader('')).toThrow('Empty AAuth-Requirement header')
    expect(() => parseAAuthHeader('  ')).toThrow('Empty AAuth-Requirement header')
  })

  it('throws on missing requirement=', () => {
    expect(() => parseAAuthHeader('pseudonym')).toThrow('Missing requirement=')
  })

  it('throws on unknown requirement level', () => {
    expect(() => parseAAuthHeader('requirement=unknown')).toThrow('Unknown requirement level')
  })

  it('throws on auth-token missing resource-token', () => {
    expect(() => parseAAuthHeader('requirement=auth-token'))
      .toThrow('auth-token challenge missing resource-token')
  })

  it('throws on interaction missing url', () => {
    expect(() => parseAAuthHeader('requirement=interaction; code="ABC"'))
      .toThrow('interaction challenge missing url')
  })

  it('throws on interaction missing code', () => {
    expect(() => parseAAuthHeader('requirement=interaction; url="https://x"'))
      .toThrow('interaction challenge missing code')
  })

  it('ignores unknown parameters', () => {
    const header = 'requirement=approval; unknown="value"'
    const result = parseAAuthHeader(header)
    expect(result).toEqual({ requirement: 'approval' })
  })
})

describe('buildCapabilitiesHeader / parseCapabilitiesHeader', () => {
  it('builds a capabilities header', () => {
    expect(buildCapabilitiesHeader(['interaction', 'clarification']))
      .toBe('interaction, clarification')
  })

  it('parses a capabilities header', () => {
    expect(parseCapabilitiesHeader('interaction, clarification, payment'))
      .toEqual(['interaction', 'clarification', 'payment'])
  })

  it('ignores unknown capabilities', () => {
    expect(parseCapabilitiesHeader('interaction, unknown, payment'))
      .toEqual(['interaction', 'payment'])
  })

  it('handles whitespace variations', () => {
    expect(parseCapabilitiesHeader('interaction,clarification , payment'))
      .toEqual(['interaction', 'clarification', 'payment'])
  })
})

describe('buildMissionHeader / parseMissionHeader', () => {
  const mission = {
    approver: 'https://ps.example',
    s256: 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
  }

  it('builds a mission header', () => {
    expect(buildMissionHeader(mission))
      .toBe('approver="https://ps.example"; s256="dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"')
  })

  it('round-trips mission header', () => {
    const header = buildMissionHeader(mission)
    expect(parseMissionHeader(header)).toEqual(mission)
  })

  it('throws on missing approver', () => {
    expect(() => parseMissionHeader('s256="abc"'))
      .toThrow('Invalid AAuth-Mission header')
  })

  it('throws on missing s256', () => {
    expect(() => parseMissionHeader('approver="https://ps.example"'))
      .toThrow('Invalid AAuth-Mission header')
  })
})
