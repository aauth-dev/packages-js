import { jwtVerify, importJWK, calculateJwkThumbprint } from 'jose'
import type { JWK, JSONWebKeySet } from 'jose'
import { TOKEN_TYP, DWK, decodeJwtHeader, decodeJwtPayload } from '@aauth/protocol'
import { AAuthTokenError } from './errors.js'
import { discoverJwks, type FetchLike } from './jwks.js'
import { isServerIdentifier, nowSeconds, timingSafeEqualString } from './util.js'
import type { R3OperationSet } from './r3.js'

// --- Types ---

/** The three AAuth JWTs an agent can present to a resource via `Signature-Key`. */
export type TokenKind = 'agent' | 'person' | 'auth'

export interface VerifyTokenOptions {
  /** Raw JWT, from `@hellocoop/httpsig`'s `result.jwt.raw`. */
  jwt: string
  /** JWK thumbprint of the key that signed the HTTP request, from `result.thumbprint`. */
  httpSignatureThumbprint: string
  /**
   * The resource's own server identifier (AAuth Protocol §Server Identifiers).
   * A person token's or auth token's `aud` MUST equal it.
   */
  resource: string
  /**
   * Which token kinds this call site accepts. REQUIRED — there is no safe
   * default.
   *
   * A person token and a PS-issued auth token carry the same `iss`, `dwk`,
   * `aud`, `sub` and `cnf`; only `typ` distinguishes them (AAuth Protocol
   * §Person Token Is Not Authorization). A call site that requires
   * authorization MUST pass `['auth']`. Including `'person'` there accepts an
   * identity assertion as a grant, and the mistake fails open.
   */
  accept: readonly TokenKind[]
  /** Injectable fetch, for Workers bindings and tests. Defaults to global fetch. */
  fetch?: FetchLike
  /** Seconds of clock skew tolerated on `exp` and `iat`. Default 60. */
  clockToleranceSeconds?: number
  /** Override "now", in seconds since the epoch. For tests. */
  now?: number
}

interface VerifiedBase {
  iss: string
  dwk: string
  jti?: string
  cnf: { jwk: JWK }
  iat: number
  exp: number
  /** Every payload claim, for claims this package does not model. */
  claims: Record<string, unknown>
}

export interface VerifiedAgentToken extends VerifiedBase {
  type: 'agent'
  /** Agent identifier (`aauth:local@domain`), stable across key rotations. */
  sub: string
  jti?: string
  /** The agent's person server, when the agent token declares one. This is the
   *  PS entitled to fetch R3 documents referenced by tokens issued to this
   *  agent (AAuth-R3 §R3 Document Access Restriction). */
  ps?: string
  /** Sub-agent marker: the identifier of this agent's parent. */
  parent_agent?: string
}

export interface VerifiedPersonToken extends VerifiedBase {
  type: 'person'
  /** The person server. `(iss, sub)` is the identity — see `sub`. */
  iss: string
  dwk: string
  /** This resource's identifier. */
  aud: string
  /**
   * Directed user identifier. Unique within `iss`, NOT globally. A resource
   * MUST treat `(iss, sub)` as the identifier, MUST treat the value as opaque,
   * and MUST NOT match a `sub` from one issuer against a record established
   * under another, however the values compare.
   */
  sub: string
  /** REQUIRED on a person token — binds a resource token back to this one. */
  jti: string
  mission_s256?: string
  tenant?: string
}

export interface VerifiedAuthToken extends VerifiedBase {
  type: 'auth'
  aud: string | string[]
  /** The person server the person is represented by. Equal to `iss` when a PS
   *  issued the token. */
  ps: string
  /** Directed user identifier. REQUIRED. `(iss, sub)` is the identity. */
  sub: string
  scope?: string
  account?: string
  mission_s256?: string
  tenant?: string
  r3_uri?: string
  r3_s256?: string
  r3_granted?: R3OperationSet
  /** Operations authorized in principle but requiring a per-call proposal.
   *  Renamed from `r3_conditional` in R3 -02. */
  r3_per_call?: R3OperationSet
}

export type VerifiedToken = VerifiedAgentToken | VerifiedPersonToken | VerifiedAuthToken

export { AAuthTokenError } from './errors.js'
export { clearMetadataCache } from './jwks.js'

// --- Algorithm policy (AAuth Protocol §Signature Algorithms) ---

const PROHIBITED_ALGS = new Set(['none', 'EdDSA', 'HS256', 'HS384', 'HS512'])

function assertFullySpecifiedAlg(alg: unknown, code: string, what: string): asserts alg is string {
  if (typeof alg !== 'string' || alg.length === 0) {
    throw new AAuthTokenError(code, `${what}: alg is REQUIRED and must be fully specified`)
  }
  if (PROHIBITED_ALGS.has(alg)) {
    throw new AAuthTokenError(
      code,
      `${what}: alg "${alg}" MUST NOT be used — use a fully-specified identifier such as Ed25519`,
    )
  }
}

/**
 * Structural checks on a `cnf.jwk`, per AAuth Protocol §Request-Context
 * Binding step 6. Reject a structurally incomplete key before attempting to
 * decode it.
 */
function assertUsableConfirmationKey(jwk: unknown, code: string): asserts jwk is JWK {
  if (!jwk || typeof jwk !== 'object') {
    throw new AAuthTokenError(code, 'Missing required claim: cnf.jwk')
  }
  const k = jwk as Record<string, unknown>
  const kty = k.kty
  if (typeof kty !== 'string') {
    throw new AAuthTokenError(code, 'cnf.jwk is structurally incomplete: missing kty')
  }
  if (kty === 'oct') {
    throw new AAuthTokenError(code, 'cnf.jwk uses a symmetric key type')
  }
  const required: Record<string, string[]> = {
    OKP: ['crv', 'x'],
    EC: ['crv', 'x', 'y'],
    RSA: ['n', 'e'],
  }
  const members = required[kty]
  if (!members) {
    throw new AAuthTokenError(code, `cnf.jwk uses an unsupported key type: ${kty}`)
  }
  for (const m of members) {
    if (typeof k[m] !== 'string') {
      throw new AAuthTokenError(code, `cnf.jwk is structurally incomplete: missing ${m}`)
    }
  }
  assertFullySpecifiedAlg(k.alg, code, 'cnf.jwk')
  if (kty === 'OKP' && k.alg === 'Ed25519' && k.crv !== 'Ed25519') {
    throw new AAuthTokenError(code, 'cnf.jwk crv disagrees with alg')
  }
  if (kty === 'EC' && k.alg === 'ES256' && k.crv !== 'P-256') {
    throw new AAuthTokenError(code, 'cnf.jwk crv disagrees with alg')
  }
}

// --- Helpers ---

const TYP_TO_KIND: Record<string, TokenKind> = {
  [TOKEN_TYP.agent]: 'agent',
  [TOKEN_TYP.person]: 'person',
  [TOKEN_TYP.auth]: 'auth',
}

const ERROR_CODE: Record<TokenKind, string> = {
  agent: 'invalid_agent_token',
  person: 'invalid_person_token',
  auth: 'invalid_auth_token',
}

function requireString(
  claims: Record<string, unknown>,
  name: string,
  code: string,
): string {
  const v = claims[name]
  if (typeof v !== 'string' || v.length === 0) {
    throw new AAuthTokenError(code, `Missing required claim: ${name}`)
  }
  return v
}

function optionalString(claims: Record<string, unknown>, name: string): string | undefined {
  const v = claims[name]
  return typeof v === 'string' && v.length > 0 ? v : undefined
}

function audMatches(aud: unknown, resource: string): boolean {
  if (typeof aud === 'string') return aud === resource
  if (Array.isArray(aud)) return aud.some(a => a === resource)
  return false
}

function selectKey(jwks: JSONWebKeySet, kid: unknown, code: string): JWK {
  const keys = jwks.keys ?? []
  if (typeof kid === 'string' && kid.length > 0) {
    const match = keys.find(k => k.kid === kid)
    if (!match) {
      throw new AAuthTokenError(code, `No key with kid "${kid}" in issuer JWKS`)
    }
    return match
  }
  if (keys.length === 1) return keys[0]
  throw new AAuthTokenError(code, 'JWT header has no kid and issuer JWKS has more than one key')
}

// --- Main function ---

/**
 * Verify an AAuth JWT presented via `Signature-Key: sig=jwt;jwt="…"`.
 *
 * Performs, in order: `typ` recognition, the `accept` check, required-claim
 * structure, expiry, key binding (`cnf.jwk` against the HTTP signing key),
 * `kid` selection and signature verification against the issuer's JWKS
 * discovered at `{iss}/.well-known/{dwk}`, then `iss` and `aud`.
 *
 * Nothing in the returned value is acted upon before the signature verifies.
 */
export async function verifyToken(options: VerifyTokenOptions): Promise<VerifiedToken> {
  const {
    jwt: rawJwt,
    httpSignatureThumbprint,
    resource,
    accept,
    clockToleranceSeconds = 60,
  } = options

  if (!Array.isArray(accept) || accept.length === 0) {
    throw new AAuthTokenError(
      'invalid_configuration',
      'verifyToken requires an `accept` list naming the token kinds this call site allows',
    )
  }
  if (!isServerIdentifier(resource)) {
    throw new AAuthTokenError(
      'invalid_configuration',
      `verifyToken \`resource\` must be a valid HTTPS server identifier, got: ${resource}`,
    )
  }

  // 1. Decode the header. Recognize typ, then check it is acceptable here.
  let header: Record<string, unknown>
  try {
    header = decodeJwtHeader(rawJwt)
  } catch {
    throw new AAuthTokenError('malformed_token', 'Value is not a well-formed JWT')
  }
  const typ = header.typ
  const kind = typeof typ === 'string' ? TYP_TO_KIND[typ] : undefined

  if (!kind) {
    throw new AAuthTokenError('unsupported_token_type', `Unknown JWT typ: ${String(typ)}`)
  }
  if (!accept.includes(kind)) {
    // AAuth Protocol §Person Token Is Not Authorization: a recipient MUST
    // reject an aa-person+jwt wherever an auth token is required.
    throw new AAuthTokenError(
      'token_type_not_accepted',
      `A ${typ} is not accepted here; this endpoint requires: ${accept.join(', ')}`,
    )
  }

  const code = ERROR_CODE[kind]
  assertFullySpecifiedAlg(header.alg, code, 'JWT header')

  // 2. Required claims and structure.
  let claims: Record<string, unknown>
  try {
    claims = decodeJwtPayload(rawJwt)
  } catch {
    throw new AAuthTokenError('malformed_token', 'JWT payload is not decodable JSON')
  }

  const iss = requireString(claims, 'iss', code)
  const dwk = requireString(claims, 'dwk', code)
  const iat = claims.iat
  const exp = claims.exp
  if (typeof iat !== 'number') throw new AAuthTokenError(code, 'Missing required claim: iat')
  if (typeof exp !== 'number') throw new AAuthTokenError(code, 'Missing required claim: exp')

  const expectedDwk = kind === 'agent'
    ? DWK.agent
    : kind === 'person'
      ? DWK.person
      : undefined // auth tokens: aauth-person.json (PS) or aauth-access.json (AS)

  if (expectedDwk && dwk !== expectedDwk) {
    throw new AAuthTokenError(code, `Expected dwk "${expectedDwk}", got "${dwk}"`)
  }
  if (kind === 'auth' && dwk !== DWK.person && dwk !== DWK.access) {
    throw new AAuthTokenError(
      code,
      `Auth token dwk must be "${DWK.person}" or "${DWK.access}", got "${dwk}"`,
    )
  }

  const cnf = claims.cnf as { jwk?: unknown } | undefined
  assertUsableConfirmationKey(cnf?.jwk, code)
  const confirmationJwk = cnf!.jwk as JWK

  // REQUIRED on all three: the agent identifier, or the directed person identifier.
  const sub = requireString(claims, 'sub', code)

  if (kind === 'person') {
    requireString(claims, 'aud', code)
    requireString(claims, 'jti', code)
  }
  if (kind === 'auth') {
    if (!claims.aud) throw new AAuthTokenError(code, 'Missing required claim: aud')
    requireString(claims, 'ps', code)
  }

  // 3. Expiry and issuance time.
  const now = options.now ?? nowSeconds()
  if (exp < now - clockToleranceSeconds) {
    throw new AAuthTokenError('token_expired', 'Token has expired')
  }
  if (iat > now + clockToleranceSeconds) {
    throw new AAuthTokenError(code, 'Token iat is in the future')
  }

  // 4. Key binding: cnf.jwk MUST be the key that signed the HTTP request.
  const cnfThumbprint = await calculateJwkThumbprint(confirmationJwk, 'sha256')
  if (!timingSafeEqualString(cnfThumbprint, httpSignatureThumbprint)) {
    throw new AAuthTokenError(
      'key_binding_failed',
      'cnf.jwk thumbprint does not match HTTP signature key',
    )
  }

  // 5. Issuer identity, then signature over the issuer's discovered key.
  if (!isServerIdentifier(iss)) {
    throw new AAuthTokenError(code, `iss is not a valid HTTPS server identifier: ${iss}`)
  }

  const jwks = await discoverJwks({ iss, dwk, fetch: options.fetch, errorCode: code })
  const signingKey = selectKey(jwks, header.kid, code)
  if (typeof signingKey.alg === 'string' && signingKey.alg !== header.alg) {
    throw new AAuthTokenError(
      code,
      `JWKS key alg "${signingKey.alg}" disagrees with JWT header alg "${header.alg}"`,
    )
  }

  try {
    const key = await importJWK(signingKey, header.alg as string)
    await jwtVerify(rawJwt, key, {
      algorithms: [header.alg as string],
      clockTolerance: clockToleranceSeconds,
      typ: typ as string,
    })
  } catch (err) {
    if (err instanceof AAuthTokenError) throw err
    throw new AAuthTokenError(
      code,
      `JWT signature verification failed: ${(err as Error).message}`,
    )
  }

  // 6. Audience. An agent token has none; a person or auth token names us.
  if (kind === 'person' || kind === 'auth') {
    if (!audMatches(claims.aud, resource)) {
      throw new AAuthTokenError(
        'aud_mismatch',
        `Token aud does not match this resource (${resource})`,
      )
    }
  }

  const base = {
    iss,
    dwk,
    cnf: { jwk: confirmationJwk },
    iat,
    exp,
    claims,
    ...(optionalString(claims, 'jti') ? { jti: optionalString(claims, 'jti') } : {}),
  }

  if (kind === 'agent') {
    const ps = optionalString(claims, 'ps')
    if (ps !== undefined && !isServerIdentifier(ps)) {
      throw new AAuthTokenError(code, `ps is not a valid HTTPS server identifier: ${ps}`)
    }
    const result: VerifiedAgentToken = { type: 'agent', ...base, sub }
    if (ps) result.ps = ps
    const parent = optionalString(claims, 'parent_agent')
    if (parent) result.parent_agent = parent
    return result
  }

  if (kind === 'person') {
    const result: VerifiedPersonToken = {
      type: 'person',
      ...base,
      aud: claims.aud as string,
      sub,
      jti: claims.jti as string,
    }
    const mission = optionalString(claims, 'mission_s256')
    if (mission) result.mission_s256 = mission
    const tenant = optionalString(claims, 'tenant')
    if (tenant) result.tenant = tenant
    if (claims.scope !== undefined || claims.account !== undefined) {
      throw new AAuthTokenError(code, 'A person token MUST NOT carry scope or account')
    }
    return result
  }

  const ps = claims.ps as string
  if (!isServerIdentifier(ps)) {
    throw new AAuthTokenError(code, `ps is not a valid HTTPS server identifier: ${ps}`)
  }
  const result: VerifiedAuthToken = {
    type: 'auth',
    ...base,
    aud: claims.aud as string | string[],
    ps,
    sub,
  }
  const scope = optionalString(claims, 'scope')
  if (scope) result.scope = scope
  const account = optionalString(claims, 'account')
  if (account) result.account = account
  const mission = optionalString(claims, 'mission_s256')
  if (mission) result.mission_s256 = mission
  const tenant = optionalString(claims, 'tenant')
  if (tenant) result.tenant = tenant
  const r3Uri = optionalString(claims, 'r3_uri')
  if (r3Uri) result.r3_uri = r3Uri
  const r3Hash = optionalString(claims, 'r3_s256')
  if (r3Hash) result.r3_s256 = r3Hash
  if (claims.r3_granted) result.r3_granted = claims.r3_granted as R3OperationSet
  if (claims.r3_per_call) result.r3_per_call = claims.r3_per_call as R3OperationSet
  return result
}
