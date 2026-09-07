/**
 * Token revocation (AAuth Protocol §Token Revocation).
 *
 * A resource verifies tokens statelessly — the issuer's JWKS, the signature,
 * the claims — and nothing in that path reports that a token was withdrawn.
 * Revocation is the one piece of state a resource keeps: the `(iss, jti)`
 * pairs an issuer has told it about, each held until the token's own `exp`.
 *
 *   - The revocation endpoint takes a signed POST from a server signing as
 *     itself (`Signature-Key: sig=jwks_uri;id="…";dwk="…"`), carrying `jti`
 *     and `exp`. The issuer is NOT a request parameter: it is the verified
 *     caller, so a caller can only ever revoke its own tokens.
 *   - `verifyToken({ revocation })` refuses a token whose `(iss, jti)` is on
 *     the list with the `revoked_jwt` code; the resource answers `401` with
 *     `Signature-Error: error=revoked_jwt` (HTTP Signature Keys draft).
 *
 * The HTTP signature itself is verified by the resource (with
 * `@hellocoop/httpsig` or its own step); this module takes the verified
 * caller and the request, and is otherwise transport-agnostic. No `node:*`
 * imports — the KV store shape is Cloudflare's, and the memory store is for a
 * single Node process.
 */

import { DWK } from '@aauth/protocol'
import { isServerIdentifier, nowSeconds } from './util.js'

// --- The store ---

export interface RevocationStore {
  /**
   * Record that `iss` revoked the token `jti`, whose expiry is `exp` (seconds
   * since the epoch). The entry only has to outlive the token.
   */
  revoke(iss: string, jti: string, exp: number): Promise<void>
  /** Is `(iss, jti)` on the list? Expired entries count as absent. */
  isRevoked(iss: string, jti: string): Promise<boolean>
}

/** Clock skew tolerated when deciding an entry has outlived its token. */
export const REVOCATION_CLOCK_SKEW_SECONDS = 60

/** A revocation list for one process. Entries age out at `exp` plus skew. */
export class MemoryRevocationStore implements RevocationStore {
  private readonly entries = new Map<string, number>()
  constructor(private readonly options: { now?: () => number } = {}) {}
  private now(): number {
    return this.options.now?.() ?? nowSeconds()
  }
  async revoke(iss: string, jti: string, exp: number): Promise<void> {
    this.entries.set(`${iss}\n${jti}`, exp + REVOCATION_CLOCK_SKEW_SECONDS)
  }
  async isRevoked(iss: string, jti: string): Promise<boolean> {
    const key = `${iss}\n${jti}`
    const until = this.entries.get(key)
    if (until === undefined) return false
    if (until < this.now()) {
      this.entries.delete(key)
      return false
    }
    return true
  }
  /** Entries currently held (for tests and diagnostics). */
  get size(): number {
    return this.entries.size
  }
}

/** The subset of a Cloudflare KV namespace this store uses. */
export interface RevocationKV {
  get(key: string): Promise<string | null>
  put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void>
}

/** KV refuses an expirationTtl below 60 s; a token's last minute rounds up. */
const KV_MIN_TTL_SECONDS = 60

/**
 * A revocation list in a KV namespace, shared by every worker that reads it:
 * a revocation presented at one host is honoured fleet-wide. Rows are
 * plaintext markers — no credential material — under `{prefix}{iss}:{jti}`,
 * with a TTL of the token's remaining lifetime plus skew.
 */
export class KVRevocationStore implements RevocationStore {
  private readonly prefix: string
  private readonly nowFn: (() => number) | undefined
  constructor(
    private readonly kv: RevocationKV,
    options: { prefix?: string; now?: () => number } = {},
  ) {
    this.prefix = options.prefix ?? 'revoked:'
    this.nowFn = options.now
  }
  private key(iss: string, jti: string): string {
    return `${this.prefix}${iss}:${jti}`
  }
  async revoke(iss: string, jti: string, exp: number): Promise<void> {
    const now = this.nowFn?.() ?? nowSeconds()
    const ttl = Math.max(exp + REVOCATION_CLOCK_SKEW_SECONDS - now, KV_MIN_TTL_SECONDS)
    await this.kv.put(this.key(iss, jti), '1', { expirationTtl: ttl })
  }
  async isRevoked(iss: string, jti: string): Promise<boolean> {
    return (await this.kv.get(this.key(iss, jti))) !== null
  }
}

// --- The endpoint ---

/**
 * The server that signed the revocation request, as the resource verified it
 * from `Signature-Key: sig=jwks_uri;id="…";dwk="…"`. `id` is that server's
 * `issuer` — the `iss` of every token it mints — and `dwk` the metadata
 * document its key was found through.
 */
export interface RevocationCaller {
  id: string
  dwk: string
}

export interface RevocationEndpointOptions {
  store: RevocationStore
  /**
   * Server identifiers whose revocations this resource honours — the person
   * servers and access servers it exchanges tokens with. Any other caller is
   * `unsupported_iss`.
   */
  issuers: readonly string[]
  /**
   * Metadata documents a caller may sign through. Default: `aauth-person.json`
   * and `aauth-access.json` — a PS or an AS, the two parties that issue the
   * tokens a resource verifies.
   */
  dwks?: readonly string[]
  /**
   * The longest lifetime this resource accepts for any token, in seconds. A
   * revocation whose `exp` is further out than that is `invalid_request`: the
   * resource would refuse such a token on presentation anyway (§Token
   * Revocation). Default 24 hours, the ceiling an agent token SHOULD NOT exceed.
   */
  maxLifetimeSeconds?: number
  /** Seconds of clock skew tolerated on `exp`. Default 60. */
  clockToleranceSeconds?: number
  /** Override "now", in seconds since the epoch. For tests. */
  now?: number
}

export type RevocationOutcome =
  | {
      /** Recorded (or already past its exp, which needs no record). */
      ok: true
      iss: string
      jti: string
      exp: number
      /** `exp` had already passed: nothing was written, 200 all the same. */
      expired: boolean
    }
  | {
      ok: false
      status: 400 | 403
      error: 'invalid_request' | 'unsupported_iss'
      detail: string
    }

/** Longest token lifetime accepted by default: the agent-token ceiling. */
export const DEFAULT_MAX_TOKEN_LIFETIME_SECONDS = 24 * 3600

/**
 * Apply a revocation request whose signature the resource has already
 * verified. `body` is the request body: the raw JSON text, or the parsed
 * value. Returns the outcome; `revocationResponse` turns it into the HTTP
 * response the endpoint owes.
 */
export async function applyRevocation(
  caller: RevocationCaller,
  body: unknown,
  options: RevocationEndpointOptions,
): Promise<RevocationOutcome> {
  const dwks = options.dwks ?? [DWK.person, DWK.access]
  const refuse = (status: 400 | 403, error: 'invalid_request' | 'unsupported_iss', detail: string): RevocationOutcome => ({
    ok: false,
    status,
    error,
    detail,
  })

  // The caller's identity is established before the body is examined.
  if (!isServerIdentifier(caller.id) || !dwks.includes(caller.dwk) || !options.issuers.includes(caller.id)) {
    return refuse(403, 'unsupported_iss', `revocations are not accepted from ${caller.id} (${caller.dwk})`)
  }

  let parsed: unknown = body
  if (typeof body === 'string') {
    try {
      parsed = JSON.parse(body)
    } catch {
      return refuse(400, 'invalid_request', 'body is not JSON')
    }
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return refuse(400, 'invalid_request', 'body must be a JSON object with jti and exp')
  }
  const { jti, exp } = parsed as { jti?: unknown; exp?: unknown }
  if (typeof jti !== 'string' || jti.length === 0) return refuse(400, 'invalid_request', 'jti is required')
  if (typeof exp !== 'number' || !Number.isInteger(exp) || exp < 0) {
    return refuse(400, 'invalid_request', 'exp is required and must be an integer (seconds since the epoch)')
  }

  const now = options.now ?? nowSeconds()
  const skew = options.clockToleranceSeconds ?? REVOCATION_CLOCK_SKEW_SECONDS
  const maxLifetime = options.maxLifetimeSeconds ?? DEFAULT_MAX_TOKEN_LIFETIME_SECONDS
  if (exp > now + maxLifetime + skew) {
    return refuse(400, 'invalid_request', `exp is further out than the ${maxLifetime}s lifetime this resource accepts for any token`)
  }

  // A token past its exp is refused on expiry alone; the entry would be dead
  // weight. Still 200: the goal state — the token will not be accepted — holds.
  if (exp + skew < now) return { ok: true, iss: caller.id, jti, exp, expired: true }

  await options.store.revoke(caller.id, jti, exp)
  return { ok: true, iss: caller.id, jti, exp, expired: false }
}

/**
 * The response the revocation endpoint returns: `200 OK` with an empty body
 * once recorded, whether or not the resource ever saw the token — there is no
 * "not found" (§Token Revocation) — or a problem-details error.
 */
export function revocationResponse(outcome: RevocationOutcome): Response {
  if (outcome.ok) return new Response(null, { status: 200, headers: { 'Cache-Control': 'no-store' } })
  return new Response(JSON.stringify({ error: outcome.error, detail: outcome.detail }), {
    status: outcome.status,
    headers: { 'Content-Type': 'application/problem+json', 'Cache-Control': 'no-store' },
  })
}

/**
 * Verify-then-record in one call: the revocation endpoint's body, given the
 * verified caller and the request.
 */
export async function handleRevocation(
  request: Request,
  caller: RevocationCaller,
  options: RevocationEndpointOptions,
): Promise<Response> {
  const body = await request.text()
  return revocationResponse(await applyRevocation(caller, body, options))
}

/**
 * The `Signature-Error` value a resource returns with `401` when the token in
 * `Signature-Key` verifies, is unexpired, and is on the revocation list. The
 * same code `verifyToken` throws as `AAuthTokenError.code`.
 */
export const REVOKED_JWT = 'revoked_jwt'
