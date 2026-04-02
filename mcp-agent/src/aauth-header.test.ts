import { describe, it, expect } from 'vitest'
import { parseAAuthHeader } from './aauth-header.js'

describe('parseAAuthHeader', () => {
  it('parses requirement=pseudonym', () => {
    const result = parseAAuthHeader('requirement=pseudonym')
    expect(result).toEqual({ requirement: 'pseudonym' })
  })

  it('parses requirement=identity', () => {
    const result = parseAAuthHeader('requirement=identity')
    expect(result).toEqual({ requirement: 'identity' })
  })

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
    const header = 'requirement=pseudonym; unknown="value"'
    const result = parseAAuthHeader(header)
    expect(result).toEqual({ requirement: 'pseudonym' })
  })
})
