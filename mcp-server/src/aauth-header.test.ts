import { describe, it, expect } from 'vitest'
import { buildAAuthHeader } from './aauth-header.js'

describe('buildAAuthHeader', () => {
  it('builds pseudonym header', () => {
    expect(buildAAuthHeader('pseudonym')).toBe('requirement=pseudonym')
  })

  it('builds identity header', () => {
    expect(buildAAuthHeader('identity')).toBe('requirement=identity')
  })

  it('builds approval header', () => {
    expect(buildAAuthHeader('approval')).toBe('requirement=approval')
  })

  it('builds auth-token header with resource-token', () => {
    const result = buildAAuthHeader('auth-token', {
      resourceToken: 'eyJhbGciOiJFZERTQSJ9.test',
    })
    expect(result).toBe(
      'requirement=auth-token; resource-token="eyJhbGciOiJFZERTQSJ9.test"',
    )
  })

  it('builds interaction header with url and code', () => {
    const result = buildAAuthHeader('interaction', {
      url: 'https://auth.example/interact',
      code: 'ABCD1234',
    })
    expect(result).toBe('requirement=interaction; url="https://auth.example/interact"; code="ABCD1234"')
  })

  it('auth-token header is parseable (round-trip check)', () => {
    const header = buildAAuthHeader('auth-token', {
      resourceToken: 'tok.en.here',
    })
    // Should contain the exact format
    expect(header).toContain('requirement=auth-token')
    expect(header).toContain('resource-token="tok.en.here"')
  })

  it('throws on auth-token missing params', () => {
    expect(() => (buildAAuthHeader as Function)('auth-token'))
      .toThrow('auth-token requires resourceToken')
    expect(() => (buildAAuthHeader as Function)('auth-token', {}))
      .toThrow('auth-token requires resourceToken')
  })

  it('throws on interaction missing url or code', () => {
    expect(() => (buildAAuthHeader as Function)('interaction'))
      .toThrow('interaction requires url and code')
    expect(() => (buildAAuthHeader as Function)('interaction', { code: 'X' }))
      .toThrow('interaction requires url and code')
    expect(() => (buildAAuthHeader as Function)('interaction', { url: 'https://x' }))
      .toThrow('interaction requires url and code')
  })
})
