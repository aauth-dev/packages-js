import { describe, it, expect } from 'vitest'
import {
  resolveProvider,
  resolveKeystoreAlgorithm,
  resolveAgentId,
  resolveLifetime,
  withFullySpecifiedAlg,
} from './resolve.js'

describe('resolveProvider', () => {
  it('uses the explicit flag when given', () => {
    expect(resolveProvider('https://x.example', ['https://a.example', 'https://b.example']))
      .toEqual({ url: 'https://x.example' })
  })
  it('uses the sole configured provider', () => {
    expect(resolveProvider(undefined, ['https://only.example'])).toEqual({ url: 'https://only.example' })
  })
  it('errors when none configured', () => {
    expect(resolveProvider(undefined, []).error).toMatch(/No agent provider/)
  })
  it('errors when multiple and no flag', () => {
    expect(resolveProvider(undefined, ['https://a.example', 'https://b.example']).error).toMatch(/Multiple/)
  })
})

describe('resolveKeystoreAlgorithm', () => {
  it('defaults to software + EdDSA', () => {
    expect(resolveKeystoreAlgorithm(undefined, undefined)).toEqual({ keystore: 'software', algorithm: 'EdDSA' })
  })
  it('defaults a hardware keystore to ES256', () => {
    expect(resolveKeystoreAlgorithm('secure-enclave', undefined)).toEqual({ keystore: 'secure-enclave', algorithm: 'ES256' })
  })
  it('respects an explicit algorithm', () => {
    expect(resolveKeystoreAlgorithm('software', 'ES256')).toEqual({ keystore: 'software', algorithm: 'ES256' })
  })
})

describe('withFullySpecifiedAlg', () => {
  const okp = { kty: 'OKP', crv: 'Ed25519', x: 'abc', use: 'sig', kid: '2026-08-11_a1c' }

  it('replaces the polymorphic EdDSA with Ed25519 (RFC 9864)', () => {
    expect(withFullySpecifiedAlg({ ...okp, alg: 'EdDSA' })).toEqual({ ...okp, alg: 'Ed25519' })
  })

  it('keeps every other JWK member intact, including private material', () => {
    const priv = { ...okp, d: 'secret', alg: 'EdDSA' }
    expect(withFullySpecifiedAlg(priv)).toEqual({ ...priv, alg: 'Ed25519' })
  })

  it('uses the curve — an Ed448 key labelled EdDSA becomes Ed448', () => {
    const jwk = { kty: 'OKP', crv: 'Ed448', x: 'abc', alg: 'EdDSA' }
    expect(withFullySpecifiedAlg(jwk)).toEqual({ ...jwk, alg: 'Ed448' })
  })

  it('leaves an already fully-specified alg alone', () => {
    const ed = { ...okp, alg: 'Ed25519' }
    expect(withFullySpecifiedAlg(ed)).toBe(ed)
    const ec = { kty: 'EC', crv: 'P-256', alg: 'ES256' }
    expect(withFullySpecifiedAlg(ec)).toBe(ec)
  })

  it('passes through null and non-objects rather than throwing', () => {
    expect(withFullySpecifiedAlg(null)).toBeNull()
    expect(withFullySpecifiedAlg(undefined)).toBeUndefined()
    expect(withFullySpecifiedAlg('not a jwk')).toBe('not a jwk')
  })
})

describe('resolveAgentId', () => {
  const host = 'me.github.io'
  it('explicit wins over everything', () => {
    expect(resolveAgentId({ explicit: 'custom@x', local: 'claude', host, configAgentId: 'aauth:local@me.github.io' }))
      .toBe('custom@x')
  })
  it('local builds aauth:<local>@<host>', () => {
    expect(resolveAgentId({ local: 'claude', host, configAgentId: 'aauth:local@me.github.io' }))
      .toBe('aauth:claude@me.github.io')
  })
  it('falls back to config', () => {
    expect(resolveAgentId({ host, configAgentId: 'aauth:local@me.github.io' })).toBe('aauth:local@me.github.io')
  })
  it('undefined when nothing resolves', () => {
    expect(resolveAgentId({ host })).toBeUndefined()
  })
})

describe('resolveLifetime', () => {
  it('defaults to 3600', () => {
    expect(resolveLifetime(undefined)).toBe(3600)
  })
  it('parses a numeric flag', () => {
    expect(resolveLifetime('600')).toBe(600)
  })
  it('falls back to 3600 on non-numeric', () => {
    expect(resolveLifetime('abc')).toBe(3600)
  })
})
