import { TOKEN_TYP, DWK, SIGNING_ALG } from '@aauth/protocol'
import { AAuthTokenError } from './errors.js'
import { isServerIdentifier, nowSeconds, randomId } from './util.js'
import type { VerifiedPersonToken } from './verify-token.js'

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

/** The claims a resource token copies out of the person token it verified. */
export interface PersonTokenReference {
  /** `iss` of the person token — the PS whose namespace `sub` belongs to. */
  iss: string
  /** `sub` of the person token — directed, opaque, meaningful only with `iss`. */
  sub: string
  /** `jti` of the person token — binds this resource token to that one. */
  jti: string
  /** Copied unchanged when present. A resource MUST NOT omit it. */
  mission_s256?: string
  tenant?: string
}

export interface ResourceTokenOptions {
  /** `iss` — the resource's own server identifier. */
  resource: string
  /** `aud` — the PS in three-party access, the AS in four-party. */
  audience: string
  /** The person token this resource verified. `ps`, `sub`, `person_token_jti`,
   *  `mission_s256` and `tenant` are copied from it. */
  personToken: VerifiedPersonToken | PersonTokenReference
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

function personRef(
  token: VerifiedPersonToken | PersonTokenReference,
): PersonTokenReference {
  if (!token || typeof token !== 'object') {
    throw new AAuthTokenError(
      'person_token_required',
      'createResourceToken requires the person token this resource verified',
    )
  }
  const { iss, sub, jti } = token as PersonTokenReference
  if (!iss || !sub || !jti) {
    throw new AAuthTokenError(
      'person_token_required',
      'The person token reference needs iss, sub and jti',
    )
  }
  const ref: PersonTokenReference = { iss, sub, jti }
  if (token.mission_s256) ref.mission_s256 = token.mission_s256
  if (token.tenant) ref.tenant = token.tenant
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

  const person = personRef(options.personToken)

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
    ps: person.iss,
    sub: person.sub,
    person_token_jti: person.jti,
    agent_jkt: agentJkt,
    iat: now,
    exp,
    scope,
  }

  if (account !== undefined) payload.account = account

  // REQUIRED when the person token carried one, copied unchanged. A resource
  // MUST NOT omit it: the PS resolves the person token by `person_token_jti`
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
