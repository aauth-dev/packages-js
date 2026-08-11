import { parseRequirementHeader } from '@aauth/protocol'
import { pollDeferred } from './deferred.js'
import type { AAuthError } from './deferred.js'
import { resolveAuthServerMetadata, resolveUrl } from './token-exchange.js'
import type { AuthServerMetadata } from './token-exchange.js'
import {
  summarizeResponseHeaders,
  decodeSignatureKey,
  peekResponseBody,
  decodeJwtPayloadSafe,
} from './log-helpers.js'
import type { FetchLike, GetKeyMaterial, OnEvent, CapturedSent } from './types.js'

export class PersonTokenError extends Error {
  constructor(
    public readonly status: number,
    public readonly aauthError?: AAuthError,
  ) {
    const msg = aauthError?.error_description
      || aauthError?.error
      || `Person token request failed with status ${status}`
    super(msg)
    this.name = 'PersonTokenError'
  }
}

export interface PersonTokenOptions {
  /**
   * Signed fetch that presents the agent token via `Signature-Key`. It MUST be
   * a PS-flavoured fetch (`createSignedFetch(..., { signBody: true })`) so the
   * JSON body is covered by `content-digest` and `content-type`.
   */
  signedFetch: FetchLike
  /** Person server URL — the `ps` claim of the agent token. */
  personServerUrl: string
  /** Cached PS metadata; when provided, skips the /.well-known fetch. */
  personServerMetadata?: AuthServerMetadata
  /** Called with freshly-fetched metadata so callers can persist it. */
  onMetadata?: (metadata: AuthServerMetadata) => void
  /** REQUIRED. HTTPS URL of the resource the token is for; becomes its `aud`. */
  resource: string
  /** OPTIONAL. The mission the agent is operating under; becomes `mission_s256`. */
  missionS256?: string
  /**
   * OPTIONAL. A sub-agent's agent token, when a parent obtains a person token
   * on its behalf. The issued token's `cnf` is then the sub-agent's key.
   */
  subagentToken?: string
  onInteraction?: (url: string, code: string) => void
  onClarification?: (question: string) => Promise<string>
  onEvent?: OnEvent
  /** Total interaction-poll timeout in seconds (default 900) — see pollDeferred. */
  maxPollDuration?: number
  /** Optional: lets the agent token be decoded into :start events under --log. */
  getKeyMaterial?: GetKeyMaterial
  /** Shared sent-request tracker; see TokenExchangeOptions. */
  sentTracker?: { latest?: CapturedSent }
}

export interface PersonTokenResult {
  personToken: string
  expiresIn: number
}

const PREFER_WAIT = 45

/**
 * Request a person token from the PS's `person_token_endpoint`.
 *
 * A person token identifies the person the agent acts for to one resource. A
 * resource MUST have verified one before it issues a resource token, and the
 * agent MUST present one on every authorization endpoint request — so this is
 * the first PS call of a flow, not an optional extra.
 *
 * The request is a signed POST presenting the agent token via
 * `Signature-Key: sig=jwt;jwt="…"`, with body `{resource, mission_s256?,
 * subagent_token?}`. `upstream_token` (call chaining) is deliberately not
 * implemented.
 *
 * A `202` with `requirement=interaction` is polled at its `Location` like any
 * other deferred response — the PS may ask the person whether this agent may
 * act at the resource as them before it will name them.
 */
export async function requestPersonToken(options: PersonTokenOptions): Promise<PersonTokenResult> {
  const {
    signedFetch,
    personServerUrl,
    resource,
    missionS256,
    subagentToken,
    onInteraction,
    onClarification,
    onEvent,
    getKeyMaterial,
    sentTracker,
  } = options

  const metadata = await resolveAuthServerMetadata({
    signedFetch,
    authServerUrl: personServerUrl,
    authServerMetadata: options.personServerMetadata,
    onMetadata: options.onMetadata,
    onEvent,
    getKeyMaterial,
    sentTracker,
  })

  const body: Record<string, unknown> = { resource }
  if (missionS256) body.mission_s256 = missionS256
  if (subagentToken) body.subagent_token = subagentToken

  if (onEvent) {
    const agentToken = getKeyMaterial
      ? decodeSignatureKey((await getKeyMaterial()).signatureKey)
      : undefined
    onEvent({
      step: 'ps_person_token_request',
      phase: 'start',
      url: metadata.person_token_endpoint,
      resource,
      mission_s256: missionS256,
      agent_token: agentToken,
    })
  }

  const requestBody = JSON.stringify(body)
  const response = await signedFetch(metadata.person_token_endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Prefer: `wait=${PREFER_WAIT}`,
    },
    body: requestBody,
  })
  const responseBody = onEvent ? await peekResponseBody(response) : undefined
  onEvent?.({
    step: 'ps_person_token_request',
    phase: 'done',
    status: response.status,
    request_headers: sentTracker?.latest?.headers,
    request_body: sentTracker?.latest?.body ?? requestBody,
    response: {
      headers: summarizeResponseHeaders(response.headers),
      ...(responseBody !== undefined ? { body: responseBody } : {}),
    },
  })

  if (response.status === 200) {
    return emitReceived(parsePersonTokenResponse(await response.json() as Record<string, unknown>), onEvent)
  }

  if (response.status === 202) {
    const locationUrl = response.headers.get('location')
    if (!locationUrl) {
      throw new Error('202 response missing Location header')
    }

    let interactionUrl: string | undefined
    let interactionCode: string | undefined
    const requirementHeader = response.headers.get('aauth-requirement')
    if (requirementHeader) {
      const challenge = parseRequirementHeader(requirementHeader)
      if (challenge.requirement === 'interaction' && challenge.url && challenge.code) {
        interactionUrl = challenge.url
        interactionCode = challenge.code
      }
    }

    const result = await pollDeferred({
      signedFetch,
      locationUrl: resolveUrl(personServerUrl, locationUrl),
      interactionUrl,
      interactionCode,
      onInteraction,
      onClarification,
      onEvent,
      maxPollDuration: options.maxPollDuration,
      sentTracker,
    })

    if (result.response.status === 200) {
      return emitReceived(
        parsePersonTokenResponse(await result.response.json() as Record<string, unknown>),
        onEvent,
      )
    }

    throw new PersonTokenError(result.response.status, result.error)
  }

  throw new PersonTokenError(response.status)
}

function emitReceived(parsed: PersonTokenResult, onEvent?: OnEvent): PersonTokenResult {
  onEvent?.({
    step: 'person_token_received',
    phase: 'info',
    expiresIn: parsed.expiresIn,
    personToken: decodeJwtPayloadSafe(parsed.personToken),
  })
  return parsed
}

function parsePersonTokenResponse(body: Record<string, unknown>): PersonTokenResult {
  if (!body.person_token || typeof body.person_token !== 'string') {
    throw new Error('Person token response missing person_token')
  }
  if (!body.expires_in || typeof body.expires_in !== 'number') {
    throw new Error('Person token response missing expires_in')
  }
  return {
    personToken: body.person_token,
    expiresIn: body.expires_in,
  }
}

// ---------------------------------------------------------------------------
// Cache
// ---------------------------------------------------------------------------

/** Refresh this many ms before `exp` so a token is not spent on the wire. */
const EXPIRY_BUFFER_MS = 60_000

export type PersonTokenCacheOptions = Omit<
  PersonTokenOptions,
  'resource' | 'missionS256' | 'subagentToken'
>

export interface PersonTokenCache {
  /**
   * The person token for this `(resource, missionS256)`, from cache when one is
   * live and from the PS otherwise. Concurrent calls for the same key share one
   * request.
   */
  get(resource: string, missionS256?: string, subagentToken?: string): Promise<string>
  /** The cached token for this key, without minting one. */
  peek(resource: string, missionS256?: string): string | undefined
  /** Seed a token obtained elsewhere — e.g. the `person_tokens` map a PS returns with a mission approval. */
  set(resource: string, missionS256: string | undefined, personToken: string, expiresIn: number): void
  /** Drop one entry, e.g. after a resource rejected the token. */
  delete(resource: string, missionS256?: string): void
  /**
   * Drop every entry. Call this when the agent's signing key rotates: each
   * cached person token binds that key through `cnf`, so one rotation
   * invalidates all of them at once. Entries are re-requested lazily, on next
   * use of each resource, rather than re-minted as a set.
   */
  clear(): void
  /** Number of live entries — for tests and diagnostics. */
  readonly size: number
}

interface CachedPersonToken {
  personToken: string
  expiresAt: number
}

/**
 * Cache person tokens per `(resource, mission_s256)`.
 *
 * A person token is scoped to one resource and, when it carries `mission_s256`,
 * to one mission, so an agent working across several resources or several
 * concurrent missions holds one per combination.
 */
export function createPersonTokenCache(options: PersonTokenCacheOptions): PersonTokenCache {
  const cache = new Map<string, CachedPersonToken>()
  const inFlight = new Map<string, Promise<string>>()

  const key = (resource: string, missionS256?: string): string =>
    `${resource}|${missionS256 ?? ''}`

  const live = (k: string): string | undefined => {
    const entry = cache.get(k)
    if (!entry) return undefined
    if (entry.expiresAt > Date.now() + EXPIRY_BUFFER_MS) return entry.personToken
    cache.delete(k)
    return undefined
  }

  return {
    async get(resource, missionS256, subagentToken) {
      const k = key(resource, missionS256)
      const cached = live(k)
      if (cached) return cached

      const pending = inFlight.get(k)
      if (pending) return pending

      const request = requestPersonToken({
        ...options,
        resource,
        missionS256,
        subagentToken,
      }).then((result) => {
        cache.set(k, {
          personToken: result.personToken,
          expiresAt: Date.now() + result.expiresIn * 1000,
        })
        return result.personToken
      }).finally(() => {
        inFlight.delete(k)
      })

      inFlight.set(k, request)
      return request
    },

    peek(resource, missionS256) {
      return live(key(resource, missionS256))
    },

    set(resource, missionS256, personToken, expiresIn) {
      cache.set(key(resource, missionS256), {
        personToken,
        expiresAt: Date.now() + expiresIn * 1000,
      })
    },

    delete(resource, missionS256) {
      cache.delete(key(resource, missionS256))
    },

    clear() {
      cache.clear()
    },

    get size() {
      return cache.size
    },
  }
}
