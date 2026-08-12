import type { FetchLike, GetKeyMaterial, OnEvent, CapturedSent } from './types.js'
import { pollDeferred, parseErrorBody, describeAAuthError } from './deferred.js'
import type { AAuthError } from './deferred.js'
import { parseRequirementHeader } from '@aauth/protocol'
import { summarizeResponseHeaders, decodeSignatureKey, peekResponseBody, decodeJwtPayloadSafe } from './log-helpers.js'

export class TokenExchangeError extends Error {
  /** The server's error code (§Error Response Format `error`), when it sent one. */
  readonly error?: string
  /** The server's human-readable explanation — RFC 9457 `detail`, or the pre-11
   *  `error_description` when that is what arrived. */
  readonly detail?: string

  constructor(
    public readonly status: number,
    public readonly aauthError?: AAuthError,
  ) {
    super(
      describeAAuthError(aauthError)
      ?? `Token exchange failed with status ${status}`,
    )
    this.name = 'TokenExchangeError'
    this.error = aauthError?.error
    this.detail = aauthError?.detail ?? aauthError?.error_description
  }
}

export interface TokenExchangeOptions {
  signedFetch: FetchLike
  authServerUrl: string
  /** Cached auth-server metadata; when provided, skips the /.well-known fetch. */
  authServerMetadata?: PersonServerMetadata
  /** Called with freshly-fetched metadata (only when authServerMetadata wasn't provided) so callers can persist it. */
  onMetadata?: (metadata: PersonServerMetadata) => void
  resourceToken: string
  justification?: string
  localhostCallback?: string
  loginHint?: string
  tenant?: string
  domainHint?: string
  capabilities?: string[]
  prompt?: string
  /** The platform the agent runs on, for the PS's connected-agents entry. */
  platform?: string
  /** The device the agent runs on. Same purpose as `platform`. */
  device?: string
  onInteraction?: (url: string, code: string) => void
  onClarification?: (question: string) => Promise<string>
  onEvent?: OnEvent
  /** Total consent-poll timeout in seconds (default 900) — see pollDeferred. */
  maxPollDuration?: number
  /**
   * Optional: when provided, agent_token is decoded and included in
   * ps_token_request:start and ps_metadata_request:start events for full
   * outgoing-token visibility under --log.
   */
  getKeyMaterial?: GetKeyMaterial
  /**
   * Optional: mutable holder that signed-fetch's onSigned callback updates
   * after each signed request. exchangeToken reads `.latest` after its own
   * signedFetch calls to attach request_headers to :done events.
   */
  sentTracker?: { latest?: CapturedSent }
}

export interface TokenExchangeResult {
  authToken: string
  expiresIn: number
}

/**
 * Person-server metadata, from `/.well-known/aauth-person.json`.
 *
 * Named for what it is. Under -11 the PS has *two* token endpoints, so a name
 * containing "auth" says the wrong thing about which one — see
 * `AuthServerMetadata` below for the retained alias.
 *
 * `auth_token_endpoint` was named `token_endpoint` before protocol -11, and
 * `person_token_endpoint` is new in -11. Both are REQUIRED: a PS that does not
 * publish `person_token_endpoint` cannot issue the person token a resource now
 * demands before it will issue a resource token, so it is non-conformant and
 * the whole flow is dead at that server.
 */
export interface PersonServerMetadata {
  auth_token_endpoint: string
  person_token_endpoint: string
  mission_endpoint?: string
  permission_endpoint?: string
  audit_endpoint?: string
  interaction_endpoint?: string
  mission_control_endpoint?: string
  revocation_endpoint?: string
  jwks_uri?: string
}

/**
 * @deprecated The pre-11 name for {@link PersonServerMetadata}. Retained so a
 * consumer written against `@aauth/mcp-agent` 2.0.0 still compiles.
 */
export type AuthServerMetadata = PersonServerMetadata

const PREFER_WAIT = 45

/**
 * Exchange a resource token for an auth token via the auth server.
 *
 * 1. Fetches auth server metadata (/.well-known/aauth-person.json)
 * 2. POSTs to auth_token_endpoint with resource_token + hints, Prefer: wait=45
 * 3. If 200: returns tokens directly
 * 4. If 202: polls via pollDeferred until terminal response
 *
 * `mission_s256` is not a parameter here: the mission reaches the PS inside the
 * resource token, which copied it from the person token the agent presented
 * (#person-token-endpoint). The agent names the mission once, when it requests
 * the person token.
 */
export async function exchangeToken(options: TokenExchangeOptions): Promise<TokenExchangeResult> {
  const {
    signedFetch,
    authServerUrl,
    resourceToken,
    justification,
    localhostCallback,
    loginHint,
    tenant,
    domainHint,
    onInteraction,
    onClarification,
    onEvent,
    getKeyMaterial,
    sentTracker,
  } = options

  // 1. Auth server metadata — use the cached copy if provided, else fetch it
  // (and hand the fresh copy back via onMetadata so the caller can persist it).
  const metadata = await resolveAuthServerMetadata({
    signedFetch,
    authServerUrl,
    authServerMetadata: options.authServerMetadata,
    onMetadata: options.onMetadata,
    onEvent,
    getKeyMaterial,
    sentTracker,
  })

  const { capabilities, prompt } = options

  // 2. Build token request body
  const body: Record<string, unknown> = {
    resource_token: resourceToken,
  }
  if (justification) body.justification = justification
  if (localhostCallback) body.localhost_callback = localhostCallback
  if (loginHint) body.login_hint = loginHint
  if (tenant) body.tenant = tenant
  if (domainHint) body.domain_hint = domainHint
  if (capabilities?.length) body.capabilities = capabilities
  if (prompt) body.prompt = prompt
  if (options.platform) body.platform = options.platform
  if (options.device) body.device = options.device

  // 3. POST to token endpoint
  if (onEvent) {
    const agentToken = getKeyMaterial
      ? decodeSignatureKey((await getKeyMaterial()).signatureKey)
      : undefined
    onEvent({
      step: 'ps_token_request',
      phase: 'start',
      url: metadata.auth_token_endpoint,
      agent_token: agentToken,
    })
  }
  const tokenBody = JSON.stringify(body)
  const response = await signedFetch(metadata.auth_token_endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Prefer: `wait=${PREFER_WAIT}`,
    },
    body: tokenBody,
  })
  const tokenResponseBody = onEvent ? await peekResponseBody(response) : undefined
  onEvent?.({
    step: 'ps_token_request',
    phase: 'done',
    status: response.status,
    request_headers: sentTracker?.latest?.headers,
    request_body: sentTracker?.latest?.body ?? tokenBody,
    response: {
      headers: summarizeResponseHeaders(response.headers),
      ...(tokenResponseBody !== undefined ? { body: tokenResponseBody } : {}),
    },
  })

  // 4. Handle response
  if (response.status === 200) {
    const parsed = parseTokenResponse(await response.json() as Record<string, unknown>)
    onEvent?.({
      step: 'auth_token_received',
      phase: 'info',
      expiresIn: parsed.expiresIn,
      authToken: decodeJwtPayloadSafe(parsed.authToken),
    })
    return parsed
  }

  if (response.status === 202) {
    // The 202's res description ("User interaction required before an auth
    // token is issued.") and the interaction_required event that follows from
    // pollDeferred together carry this beat — no separate ps_consent_pending
    // info needed.
    const locationUrl = response.headers.get('location')
    if (!locationUrl) {
      throw new Error('202 response missing Location header')
    }

    // Check for interaction url and code in AAuth-Requirement header
    let interactionUrl: string | undefined
    let interactionCode: string | undefined
    const aauthHeader = response.headers.get('aauth-requirement')
    if (aauthHeader) {
      const challenge = parseRequirementHeader(aauthHeader)
      if (challenge.requirement === 'interaction' && challenge.url && challenge.code) {
        interactionUrl = challenge.url
        interactionCode = challenge.code
      }
    }

    const result = await pollDeferred({
      signedFetch,
      locationUrl: resolveUrl(authServerUrl, locationUrl),
      interactionUrl,
      interactionCode,
      onInteraction,
      onClarification,
      onEvent,
      maxPollDuration: options.maxPollDuration,
      sentTracker,
    })

    if (result.response.status === 200) {
      const parsed = parseTokenResponse(await result.response.json() as Record<string, unknown>)
      onEvent?.({
        step: 'auth_token_received',
        phase: 'info',
        expiresIn: parsed.expiresIn,
        authToken: decodeJwtPayloadSafe(parsed.authToken),
      })
      return parsed
    }

    throw new TokenExchangeError(result.response.status, result.error)
  }

  // §Resource Token Verification rejections all land here — mission_s256 or
  // tenant mismatch, an unknown person_token_jti, a prohibited alg. The server
  // names which one; report it rather than the status alone.
  throw new TokenExchangeError(response.status, await parseErrorBody(response))
}

export interface AuthServerMetadataOptions {
  signedFetch: FetchLike
  authServerUrl: string
  /** Cached metadata; when provided, the /.well-known fetch is skipped. */
  authServerMetadata?: PersonServerMetadata
  /** Called with freshly-fetched metadata so callers can persist it. */
  onMetadata?: (metadata: PersonServerMetadata) => void
  onEvent?: OnEvent
  getKeyMaterial?: GetKeyMaterial
  sentTracker?: { latest?: CapturedSent }
}

/**
 * Return the person server's metadata, from the caller's cache when it has one
 * and from `/.well-known/aauth-person.json` otherwise. Shared by the auth-token
 * exchange and the person-token client so one flow fetches the document once.
 */
export async function resolveAuthServerMetadata(
  options: AuthServerMetadataOptions,
): Promise<PersonServerMetadata> {
  if (options.authServerMetadata) {
    options.onEvent?.({ step: 'ps_metadata_cached', phase: 'info' })
    return options.authServerMetadata
  }
  const metadata = await fetchAuthServerMetadata(options)
  options.onMetadata?.(metadata)
  return metadata
}

/**
 * Fetch and validate `/.well-known/aauth-person.json`.
 *
 * Both `auth_token_endpoint` and `person_token_endpoint` are REQUIRED in -11;
 * a document missing either is rejected here rather than half-way through a
 * flow that cannot complete.
 */
export async function fetchAuthServerMetadata({
  signedFetch,
  authServerUrl,
  onEvent,
  getKeyMaterial,
  sentTracker,
}: AuthServerMetadataOptions): Promise<PersonServerMetadata> {
  const metadataUrl = `${authServerUrl.replace(/\/$/, '')}/.well-known/aauth-person.json`
  if (onEvent) {
    const agentToken = getKeyMaterial
      ? decodeSignatureKey((await getKeyMaterial()).signatureKey)
      : undefined
    onEvent({ step: 'ps_metadata_request', phase: 'start', url: metadataUrl, agent_token: agentToken })
  }
  const response = await signedFetch(metadataUrl, { method: 'GET' })
  const responseBody = onEvent ? await peekResponseBody(response) : undefined
  onEvent?.({
    step: 'ps_metadata_request',
    phase: 'done',
    status: response.status,
    request_headers: sentTracker?.latest?.headers,
    request_body: sentTracker?.latest?.body,
    response: {
      headers: summarizeResponseHeaders(response.headers),
      ...(responseBody !== undefined ? { body: responseBody } : {}),
    },
  })

  if (!response.ok) {
    throw new Error(`Failed to fetch auth server metadata: ${response.status}`)
  }

  const metadata = await response.json() as Record<string, unknown>
  if (!metadata.auth_token_endpoint) {
    throw new Error('Auth server metadata missing auth_token_endpoint')
  }
  if (!metadata.person_token_endpoint) {
    // A PS with no person token endpoint cannot mint the person token a
    // resource requires before it issues a resource token — nothing downstream
    // of this document can succeed.
    throw new Error('Auth server metadata missing person_token_endpoint — person server is not AAuth -11 conformant')
  }

  return metadata as unknown as PersonServerMetadata
}

function parseTokenResponse(body: Record<string, unknown>): TokenExchangeResult {
  if (!body.auth_token || typeof body.auth_token !== 'string') {
    throw new Error('Token response missing auth_token')
  }
  if (!body.expires_in || typeof body.expires_in !== 'number') {
    throw new Error('Token response missing expires_in')
  }
  return {
    authToken: body.auth_token,
    expiresIn: body.expires_in,
  }
}

/** Resolve a possibly-relative `Location` against the server it came from. */
export function resolveUrl(base: string, url: string): string {
  if (url.startsWith('http://') || url.startsWith('https://')) {
    return url
  }
  return new URL(url, base).href
}
