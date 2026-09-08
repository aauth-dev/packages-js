import { TOKEN_TYP, DWK, SIGNING_ALG } from '@aauth/protocol'
import { AAuthTokenError } from './errors.js'
import { isServerIdentifier, nowSeconds, randomId } from './util.js'
import type { VerifiedPersonToken, VerifiedAuthToken } from './verify-token.js'

/**
 * Resource token minting (AAuth Protocol §Resource Token Structure).
 *
 * A resource MUST have verified a person token before it issues a resource
 * token, and MUST challenge with `requirement=person-token` when it has not.
 * Only a person server can act on a resource token, so one issued to an agent
 * that cannot name a person is one nobody can redeem — hence `personToken` is
 * required here rather than a loose set of claims.
 */

/** Default lifetime. The spec says SHOULD NOT exceed 5 minutes. */
export const DEFAULT_RESOURCE_TOKEN_LIFETIME = 300

/**
 * The claims a resource token copies out of the token the request carried —
 * the person token on the first challenge of a grant, or the auth token on a
 * step-up or per-call challenge (AAuth -11, issue #152).
 */
export interface PresentedTokenReference {
  /** The PS whose namespace `sub` belongs to: a person token's `iss`, an auth
   *  token's `ps`. Give either; `ps` wins when both are present. */
  ps?: string
  iss?: string
  /** `sub` of the presented token — directed, opaque, meaningful only with the PS. */
  sub: string
  /** `jti` of the presented token — binds this resource token to that one.
   *  Emitted as `presented_jti` (and its pre-rename alias `person_token_jti`). */
  jti: string
  /** Copied unchanged when present. A resource MUST NOT omit it. */
  mission_s256?: string
  tenant?: string
}

/** @deprecated pre-#152 name for {@link PresentedTokenReference}. */
export type PersonTokenReference = PresentedTokenReference

export type PresentedToken = VerifiedPersonToken | VerifiedAuthToken | PresentedTokenReference

export interface ResourceTokenOptions {
  /** `iss` — the resource's own server identifier. */
  resource: string
  /** `aud` — the PS in three-party access, the AS in four-party. */
  audience: string
  /** The token this resource verified on the request: the person token on the
   *  first challenge, or the auth token on a step-up / per-call challenge.
   *  `ps`, `sub`, `presented_jti`, `mission_s256` and `tenant` are copied from
   *  it, and the agent presents the same token to its PS as `presented_token`. */
  presentedToken?: PresentedToken
  /** @deprecated pre-#152 name for `presentedToken`. */
  personToken?: PresentedToken
  /** JWK thumbprint (RFC 7638) of the agent's current signing key. For a
   *  parent-mediated sub-agent authorization this is the sub-agent's key. */
  agentJkt: string
  /** REQUIRED. Space-separated scope values. Pass the scopes the request needs;
   *  an R3-only resource that expresses everything through `r3_uri` still
   *  states a scope, because the claim is REQUIRED in the token. */
  scope: string
  /** Echoes the `account` parameter of the request that produced this token. */
  account?: string
  /** Overrides the `tenant` copied from the person token. */
  tenant?: string
  /** The resource's own user-facing flow, needed before the PS can issue. */
  interaction?: { url: string; code: string }
  /** R3: both are REQUIRED together when either is present. */
  r3?: { uri: string; s256: string }
  /** Seconds. Default 300. */
  lifetime?: number
  /**
   * The mission's `expires_at`, in Unix seconds. When the person token carries
   * `mission_s256`, no token may outlive the mission — `exp` is clamped to it.
   */
  missionExpiresAt?: number
  /** JWT header `kid`. Include it; verifiers select the key by `kid`. */
  kid?: string
  /** Override "now", in seconds. For tests. */
  now?: number
}

/**
 * Caller-supplied signer. Decouples this package from any particular key
 * management — a Workers `crypto.subtle` key, a KMS, a service binding.
 *
 * The header is handed over complete: `{ alg: 'Ed25519', typ:
 * 'aa-resource+jwt', kid? }`. Sign it as given. `alg` is the fully-specified
 * RFC 9864 identifier; the polymorphic `EdDSA` MUST NOT be used.
 */
export type SignFn = (
  payload: Record<string, unknown>,
  header: Record<string, unknown>,
) => Promise<string>

/**
 * Clamp an expiry to a mission's `expires_at`.
 *
 * No token carrying `mission_s256` may outlive the mission it was issued
 * under. Applies to resource tokens here, and to anything else a resource
 * derives from a mission-scoped person token.
 */
export function clampToMission(exp: number, missionExpiresAt?: number): number {
  if (missionExpiresAt === undefined) return exp
  return Math.min(exp, missionExpiresAt)
}

function presentedRef(token: PresentedToken | undefined): Required<Pick<PresentedTokenReference, 'ps' | 'sub' | 'jti'>> & Pick<PresentedTokenReference, 'mission_s256' | 'tenant'> {
  if (!token || typeof token !== 'object') {
    throw new AAuthTokenError(
      'presented_token_required',
      'createResourceToken requires the person token or auth token this resource verified on the request',
    )
  }
  const t = token as PresentedTokenReference & { type?: string }
  // An auth token names the PS as `ps` (its `iss` may be an AS); a person
  // token's PS is its `iss`.
  const ps = t.ps ?? t.iss
  const { sub, jti } = t
  if (!ps || !sub || !jti) {
    throw new AAuthTokenError(
      'presented_token_required',
      'The presented token needs a PS (ps or iss), sub and jti — an auth token without a jti cannot be named by a resource token',
    )
  }
  const ref: Required<Pick<PresentedTokenReference, 'ps' | 'sub' | 'jti'>> & Pick<PresentedTokenReference, 'mission_s256' | 'tenant'> = { ps, sub, jti }
  if (t.mission_s256) ref.mission_s256 = t.mission_s256
  if (t.tenant) ref.tenant = t.tenant
  return ref
}

/**
 * Mint a resource token (`typ: aa-resource+jwt`).
 *
 * The resource signs it and hands it to the agent in a
 * `requirement=auth-token` challenge; the agent forwards it to its PS (or the
 * resource's AS) to obtain an auth token.
 */
export async function createResourceToken(
  options: ResourceTokenOptions,
  sign: SignFn,
): Promise<string> {
  const {
    resource,
    audience,
    agentJkt,
    scope,
    account,
    interaction,
    r3,
    lifetime = DEFAULT_RESOURCE_TOKEN_LIFETIME,
    missionExpiresAt,
    kid,
  } = options

  if (!isServerIdentifier(resource)) {
    throw new AAuthTokenError(
      'invalid_resource_identifier',
      `Resource token iss must be a valid HTTPS server identifier, got: ${resource}`,
    )
  }
  if (!isServerIdentifier(audience)) {
    throw new AAuthTokenError(
      'invalid_audience',
      `Resource token aud must be a valid HTTPS server identifier, got: ${audience}`,
    )
  }
  if (typeof agentJkt !== 'string' || !agentJkt) {
    throw new AAuthTokenError('invalid_agent_jkt', 'agentJkt is REQUIRED')
  }
  if (typeof scope !== 'string' || !scope) {
    throw new AAuthTokenError('invalid_scope', 'scope is a REQUIRED resource token claim')
  }
  if (r3 && (!r3.uri || !r3.s256)) {
    throw new AAuthTokenError(
      'invalid_r3_reference',
      'r3_uri and r3_s256 are REQUIRED together — a resource including R3 information MUST include both',
    )
  }

  const person = presentedRef(options.presentedToken ?? options.personToken)

  const now = options.now ?? nowSeconds()
  const exp = clampToMission(now + lifetime, missionExpiresAt)
  if (exp <= now) {
    throw new AAuthTokenError(
      'mission_expired',
      'The mission expires_at is in the past — no token may outlive the mission',
    )
  }

  const payload: Record<string, unknown> = {
    iss: resource,
    dwk: DWK.resource,
    aud: audience,
    jti: randomId(),
    ps: person.ps,
    sub: person.sub,
    // `presented_jti` is the -11 name (spec issue #95); `person_token_jti` is
    // its pre-rename alias, emitted alongside until every PS reads the new
    // name. Same value: the jti of the token this resource verified on the
    // request — the person token, or on a step-up the auth token (#152).
    presented_jti: person.jti,
    person_token_jti: person.jti, // deprecated alias of presented_jti
    agent_jkt: agentJkt,
    iat: now,
    exp,
    scope,
  }

  if (account !== undefined) payload.account = account

  // REQUIRED when the person token carried one, copied unchanged. A resource
  // MUST NOT omit it: the PS resolves the person token by `presented_jti`
  // and compares, so dropping it is detected as mission stripping.
  if (person.mission_s256) payload.mission_s256 = person.mission_s256

  const tenant = options.tenant ?? person.tenant
  if (tenant) payload.tenant = tenant

  if (interaction) payload.interaction = { url: interaction.url, code: interaction.code }

  if (r3) {
    payload.r3_uri = r3.uri
    payload.r3_s256 = r3.s256
  }

  const header: Record<string, unknown> = {
    alg: SIGNING_ALG,
    typ: TOKEN_TYP.resource,
  }
  if (kid) header.kid = kid

  return sign(payload, header)
}
