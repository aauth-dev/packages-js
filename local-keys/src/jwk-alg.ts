import type { JWK } from 'jose'

/**
 * Fully-specified JWS algorithm identifiers (RFC 9864) for the key types AAuth
 * conveys.
 *
 * AAuth protocol §Signature Algorithms:
 *
 * - The `alg` member MUST be present and MUST be a fully-specified identifier —
 *   one that determines the signature operation completely, including curve and
 *   hash where applicable. A verifier MUST reject a key whose `alg` is absent.
 * - The polymorphic `EdDSA` identifier MUST NOT be used. Use `Ed25519` (or
 *   `Ed448`), which RFC 9864 registered as its fully-specified replacements.
 * - `none`, any algorithm whose JOSE Implementation Requirement is `Prohibited`,
 *   and symmetric algorithms (`oct`, `HS256`, `HS384`, `HS512`) MUST NOT be used.
 * - A verifier MUST reject a key whose `kty` or, where present, `crv` disagrees
 *   with its `alg`.
 *
 * This package is where AAuth agent keys are generated, stored and read back, so
 * it owns the rule rather than each consumer patching keys up on the way out.
 * `@aauth/proxy` carried a private `withFullySpecifiedAlg` for exactly this; it
 * should import this one instead — the version here also enforces the last rule
 * (kty/crv vs. alg disagreement), which the proxy copy did not.
 */
export type FullySpecifiedAlg =
  | 'Ed25519'
  | 'Ed448'
  | 'ES256'
  | 'ES384'
  | 'ES512'
  | 'RS256'
  | 'RS384'
  | 'RS512'
  | 'PS256'
  | 'PS384'
  | 'PS512'

/** Minimal shape needed to reason about a key's algorithm. */
export interface AlgBearingJwk {
  kty?: string
  crv?: string
  alg?: string
}

/** `alg` values this profile forbids outright, whatever the key looks like. */
const PROHIBITED_ALGS = new Set([
  'none',
  'EdDSA', // polymorphic — RFC 9864 deprecated it in favour of Ed25519 / Ed448
  'HS256',
  'HS384',
  'HS512',
  'RSA1_5',
])

/** `alg` values that are fully specified but not derivable from `kty` alone. */
const RSA_ALGS = new Set<string>(['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512'])

const OKP_CURVE_ALG: Record<string, FullySpecifiedAlg> = {
  Ed25519: 'Ed25519',
  Ed448: 'Ed448',
}

const EC_CURVE_ALG: Record<string, FullySpecifiedAlg> = {
  'P-256': 'ES256',
  'P-384': 'ES384',
  'P-521': 'ES512',
}

/**
 * The one fully-specified `alg` the key material implies, or `undefined` when
 * the material does not determine it (RSA leaves padding and hash open).
 */
export function deriveFullySpecifiedAlg(jwk: AlgBearingJwk): FullySpecifiedAlg | undefined {
  if (jwk.kty === 'OKP' && jwk.crv) return OKP_CURVE_ALG[jwk.crv]
  if (jwk.kty === 'EC' && jwk.crv) return EC_CURVE_ALG[jwk.crv]
  return undefined
}

/**
 * Verifier-side check. Throws when the key violates §Signature Algorithms:
 * absent `alg`, a polymorphic/prohibited/symmetric `alg`, or an `alg` that
 * disagrees with the key's own `kty`/`crv`.
 */
export function assertFullySpecifiedAlg(jwk: AlgBearingJwk, context = 'JWK'): void {
  if (jwk.kty === 'oct') {
    throw new Error(`${context}: symmetric keys (kty=oct) MUST NOT be used`)
  }
  if (!jwk.alg) {
    throw new Error(
      `${context}: 'alg' is absent; AAuth requires a fully-specified alg (RFC 9864)`,
    )
  }
  if (PROHIBITED_ALGS.has(jwk.alg)) {
    const hint =
      jwk.alg === 'EdDSA'
        ? ` — use ${deriveFullySpecifiedAlg(jwk) ?? 'Ed25519'} instead`
        : ''
    throw new Error(`${context}: alg=${jwk.alg} MUST NOT be used${hint}`)
  }

  const derived = deriveFullySpecifiedAlg(jwk)
  if (derived) {
    if (jwk.alg !== derived) {
      throw new Error(
        `${context}: alg=${jwk.alg} disagrees with kty=${jwk.kty} crv=${jwk.crv} (expected ${derived})`,
      )
    }
    return
  }

  if (jwk.kty === 'RSA') {
    if (!RSA_ALGS.has(jwk.alg)) {
      throw new Error(`${context}: alg=${jwk.alg} is not valid for kty=RSA`)
    }
    return
  }

  throw new Error(
    `${context}: cannot validate alg=${jwk.alg} against kty=${jwk.kty} crv=${jwk.crv}`,
  )
}

/** True when the key satisfies {@link assertFullySpecifiedAlg}. */
export function hasFullySpecifiedAlg(jwk: AlgBearingJwk): boolean {
  try {
    assertFullySpecifiedAlg(jwk)
    return true
  } catch {
    return false
  }
}

/**
 * Return the key with a fully-specified `alg`, deriving it from `kty`/`crv`.
 *
 * A legacy `alg` the key material contradicts — notably the polymorphic `EdDSA`
 * on an Ed25519 key, which is what every key this package minted before AAuth
 * -11 carries — is replaced by the derived value. A contradiction the material
 * does *not* explain (`alg: ES256` on an Ed25519 key) is a corrupt or
 * substituted key and throws rather than being silently rewritten.
 *
 * When the material does not determine the algorithm (RSA), `fallbackAlg` is
 * used; without one, this throws rather than guessing.
 */
export function withFullySpecifiedAlg<T extends AlgBearingJwk>(
  jwk: T,
  fallbackAlg?: string,
  context = 'JWK',
): T {
  const derived = deriveFullySpecifiedAlg(jwk)

  if (derived) {
    if (jwk.alg && jwk.alg !== derived && !PROHIBITED_ALGS.has(jwk.alg)) {
      throw new Error(
        `${context}: alg=${jwk.alg} disagrees with kty=${jwk.kty} crv=${jwk.crv} (expected ${derived})`,
      )
    }
    return { ...jwk, alg: derived }
  }

  const candidate = jwk.alg && !PROHIBITED_ALGS.has(jwk.alg) ? jwk.alg : fallbackAlg
  if (candidate && jwk.kty === 'RSA' && RSA_ALGS.has(candidate)) {
    return { ...jwk, alg: candidate }
  }

  throw new Error(
    `${context}: needs a fully-specified alg (RFC 9864); cannot derive one from ` +
      `kty=${jwk.kty} crv=${jwk.crv}`,
  )
}

/** {@link withFullySpecifiedAlg} for a `jose` JWK. */
export function publicJwkWithAlg(jwk: JWK, fallbackAlg?: string, context = 'JWK'): JWK {
  return withFullySpecifiedAlg(jwk as AlgBearingJwk, fallbackAlg, context) as JWK
}

/**
 * Map a stored algorithm identifier onto its fully-specified form.
 *
 * `~/.aauth/config.json` written before AAuth -11 records `algorithm: "EdDSA"`
 * for software Ed25519 keys. Reading it back must not put `EdDSA` into a JWT
 * header or a JWK, so normalize at the boundary instead of migrating the file.
 */
export function normalizeAlgId(alg: string): string {
  return alg === 'EdDSA' ? 'Ed25519' : alg
}
