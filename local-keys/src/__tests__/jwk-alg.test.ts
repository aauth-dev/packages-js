import { describe, it, expect } from 'vitest'
import { exportJWK, generateKeyPair } from 'jose'
import {
  deriveFullySpecifiedAlg,
  assertFullySpecifiedAlg,
  hasFullySpecifiedAlg,
  withFullySpecifiedAlg,
  normalizeAlgId,
} from '../jwk-alg.js'
import { generateKey, toPublicJwk } from '../keygen.js'
import { getBackend } from '../backends/index.js'

const ed = { kty: 'OKP', crv: 'Ed25519', x: 'x' }
const p256 = { kty: 'EC', crv: 'P-256', x: 'x', y: 'y' }

describe('deriveFullySpecifiedAlg', () => {
  it('derives from curve', () => {
    expect(deriveFullySpecifiedAlg(ed)).toBe('Ed25519')
    expect(deriveFullySpecifiedAlg({ kty: 'OKP', crv: 'Ed448' })).toBe('Ed448')
    expect(deriveFullySpecifiedAlg(p256)).toBe('ES256')
    expect(deriveFullySpecifiedAlg({ kty: 'EC', crv: 'P-384' })).toBe('ES384')
    expect(deriveFullySpecifiedAlg({ kty: 'EC', crv: 'P-521' })).toBe('ES512')
  })

  it('returns undefined when the material does not determine it', () => {
    expect(deriveFullySpecifiedAlg({ kty: 'RSA' })).toBeUndefined()
    expect(deriveFullySpecifiedAlg({ kty: 'OKP', crv: 'X25519' })).toBeUndefined()
  })
})

describe('assertFullySpecifiedAlg', () => {
  it('accepts a fully-specified alg that agrees with the key', () => {
    expect(() => assertFullySpecifiedAlg({ ...ed, alg: 'Ed25519' })).not.toThrow()
    expect(() => assertFullySpecifiedAlg({ ...p256, alg: 'ES256' })).not.toThrow()
    expect(() => assertFullySpecifiedAlg({ kty: 'RSA', alg: 'RS256' })).not.toThrow()
  })

  it('rejects an absent alg', () => {
    expect(() => assertFullySpecifiedAlg(ed)).toThrow(/'alg' is absent/)
  })

  it('rejects the polymorphic EdDSA and points at Ed25519', () => {
    expect(() => assertFullySpecifiedAlg({ ...ed, alg: 'EdDSA' })).toThrow(
      /alg=EdDSA MUST NOT be used — use Ed25519/,
    )
  })

  it('rejects none, symmetric algs and oct keys', () => {
    expect(() => assertFullySpecifiedAlg({ ...ed, alg: 'none' })).toThrow(/MUST NOT be used/)
    expect(() => assertFullySpecifiedAlg({ kty: 'oct', alg: 'HS256' })).toThrow(/symmetric/)
    expect(() => assertFullySpecifiedAlg({ kty: 'EC', crv: 'P-256', alg: 'HS256' })).toThrow(
      /MUST NOT be used/,
    )
  })

  it('rejects a key whose crv disagrees with its alg', () => {
    expect(() => assertFullySpecifiedAlg({ ...ed, alg: 'ES256' })).toThrow(/disagrees with/)
    expect(() => assertFullySpecifiedAlg({ ...p256, alg: 'ES384' })).toThrow(/disagrees with/)
  })

  it('rejects a key whose kty disagrees with its alg', () => {
    expect(() => assertFullySpecifiedAlg({ kty: 'RSA', alg: 'ES256' })).toThrow(
      /not valid for kty=RSA/,
    )
  })

  it('hasFullySpecifiedAlg mirrors the assertion', () => {
    expect(hasFullySpecifiedAlg({ ...ed, alg: 'Ed25519' })).toBe(true)
    expect(hasFullySpecifiedAlg({ ...ed, alg: 'EdDSA' })).toBe(false)
    expect(hasFullySpecifiedAlg(ed)).toBe(false)
  })
})

describe('withFullySpecifiedAlg', () => {
  it('fills in a missing alg from the key material', () => {
    expect(withFullySpecifiedAlg(ed).alg).toBe('Ed25519')
    expect(withFullySpecifiedAlg(p256).alg).toBe('ES256')
  })

  it('upgrades the legacy polymorphic EdDSA', () => {
    expect(withFullySpecifiedAlg({ ...ed, alg: 'EdDSA' }).alg).toBe('Ed25519')
  })

  it('leaves an already-correct alg alone and does not mutate its input', () => {
    const input = { ...ed, alg: 'Ed25519' }
    const out = withFullySpecifiedAlg(input)
    expect(out.alg).toBe('Ed25519')
    expect(out).not.toBe(input)
    expect(input.alg).toBe('Ed25519')
  })

  it('throws rather than rewriting an alg the material contradicts', () => {
    expect(() => withFullySpecifiedAlg({ ...ed, alg: 'ES256' })).toThrow(/disagrees with/)
  })

  it('uses the fallback only where the material cannot determine the alg', () => {
    expect(withFullySpecifiedAlg({ kty: 'RSA', n: 'n', e: 'AQAB' }, 'RS256').alg).toBe('RS256')
    // A fallback never overrides what the curve says.
    expect(withFullySpecifiedAlg(ed, 'ES256').alg).toBe('Ed25519')
  })

  it('refuses to guess when nothing determines the alg', () => {
    expect(() => withFullySpecifiedAlg({ kty: 'RSA', n: 'n', e: 'AQAB' })).toThrow(
      /needs a fully-specified alg/,
    )
  })
})

describe('normalizeAlgId', () => {
  it('maps the pre-11 config value', () => {
    expect(normalizeAlgId('EdDSA')).toBe('Ed25519')
    expect(normalizeAlgId('ES256')).toBe('ES256')
    expect(normalizeAlgId('Ed25519')).toBe('Ed25519')
  })
})

describe('every JWK this package emits carries a fully-specified alg', () => {
  it('generateKey (Ed25519)', async () => {
    const { privateJwk, publicJwk } = await generateKey('Ed25519')
    expect(publicJwk.alg).toBe('Ed25519')
    expect(privateJwk.alg).toBe('Ed25519')
    expect(() => assertFullySpecifiedAlg(publicJwk)).not.toThrow()
  })

  it('generateKey (ES256)', async () => {
    const { privateJwk, publicJwk } = await generateKey('ES256')
    expect(publicJwk.alg).toBe('ES256')
    expect(privateJwk.alg).toBe('ES256')
  })

  it('toPublicJwk strips `d` and re-derives alg from the curve', async () => {
    const { privateJwk } = await generateKey('Ed25519')
    // Simulate a key stored before -11.
    const stale = { ...privateJwk, alg: 'EdDSA' }
    const pub = toPublicJwk(stale)
    expect(pub.d).toBeUndefined()
    expect(pub.alg).toBe('Ed25519')
    expect(pub.use).toBe('sig')
  })

  it('the software backend generates keys with alg=Ed25519', async () => {
    const key = await getBackend('software').generateKey('Ed25519')
    expect(key.algorithm).toBe('Ed25519')
    expect(key.publicJwk.alg).toBe('Ed25519')
    expect(() => assertFullySpecifiedAlg(key.publicJwk)).not.toThrow()
  })

  it('jose exportJWK output alone would fail the check', async () => {
    // Why the normalization exists: jose emits no `alg` at all.
    const { publicKey } = await generateKeyPair('Ed25519', { crv: 'Ed25519' })
    const bare = await exportJWK(publicKey)
    expect(bare.alg).toBeUndefined()
    expect(hasFullySpecifiedAlg(bare)).toBe(false)
    expect(withFullySpecifiedAlg(bare).alg).toBe('Ed25519')
  })
})
