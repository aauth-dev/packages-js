import { generateKeyPair, exportJWK } from 'jose'
import type { JWK } from 'jose'
import type { GeneratedKeyPair } from './types.js'

export function generateKid(): string {
  const now = new Date()
  const date = now.toISOString().slice(0, 10) // YYYY-MM-DD
  const hex = Math.floor(Math.random() * 0xfff)
    .toString(16)
    .padStart(3, '0')
  return `${date}_${hex}`
}

export async function generateKey(
  algorithm: 'EdDSA' | 'ES256' = 'EdDSA',
): Promise<GeneratedKeyPair> {
  const kid = generateKid()
  const alg = algorithm === 'ES256' ? 'ES256' : 'EdDSA'
  const opts = alg === 'ES256' ? { crv: 'P-256' } : { crv: 'Ed25519' }
  const { publicKey, privateKey } = await generateKeyPair(alg, opts)

  const privateJwk = await exportJWK(privateKey)
  const publicJwk = await exportJWK(publicKey)

  privateJwk.kid = kid
  privateJwk.alg = alg
  privateJwk.use = 'sig'
  publicJwk.kid = kid
  publicJwk.alg = alg
  publicJwk.use = 'sig'

  return { privateJwk, publicJwk }
}

/** Strip private material from a JWK, deriving `alg` from the curve. */
export function toPublicJwk(jwk: JWK): JWK {
  const { d: _d, ...pub } = jwk
  const alg = pub.alg ?? (pub.crv === 'P-256' ? 'ES256' : 'EdDSA')
  return { ...pub, use: 'sig', alg }
}
