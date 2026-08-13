import { generateKeyPair, exportJWK } from 'jose'
import type { JWK } from 'jose'
import { publicJwkWithAlg } from './jwk-alg.js'
import type { GeneratedKeyPair } from './types.js'

export function generateKid(): string {
  const now = new Date()
  const date = now.toISOString().slice(0, 10) // YYYY-MM-DD
  const hex = Math.floor(Math.random() * 0xfff)
    .toString(16)
    .padStart(3, '0')
  return `${date}_${hex}`
}

/**
 * Generate an agent signing key.
 *
 * The emitted JWKs carry a fully-specified `alg` (RFC 9864) — `Ed25519`, never
 * the polymorphic `EdDSA`. These keys are published in the agent server's
 * `jwks.json`, where a -11 verifier rejects anything less.
 */
export async function generateKey(
  algorithm: 'Ed25519' | 'ES256' = 'Ed25519',
): Promise<GeneratedKeyPair> {
  const kid = generateKid()
  const alg = algorithm === 'ES256' ? 'ES256' : 'Ed25519'
  // jose 6: keys are non-extractable by default, and these are exported to JWK below
  const opts = alg === 'ES256' ? { crv: 'P-256', extractable: true } : { crv: 'Ed25519', extractable: true }
  const { publicKey, privateKey } = await generateKeyPair(alg, opts)

  const privateJwk = publicJwkWithAlg(await exportJWK(privateKey), alg, 'generated private key')
  const publicJwk = publicJwkWithAlg(await exportJWK(publicKey), alg, 'generated public key')

  privateJwk.kid = kid
  privateJwk.use = 'sig'
  publicJwk.kid = kid
  publicJwk.use = 'sig'

  return { privateJwk, publicJwk }
}

/**
 * Strip private material from a JWK and give it a fully-specified `alg` derived
 * from the key material. Throws when the stored `alg` contradicts the curve.
 */
export function toPublicJwk(jwk: JWK): JWK {
  const { d: _d, ...pub } = jwk
  return { ...publicJwkWithAlg(pub, undefined, 'public JWK'), use: 'sig' }
}
