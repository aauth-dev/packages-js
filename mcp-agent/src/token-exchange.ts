import type { FetchLike, GetKeyMaterial, OnEvent, CapturedSent } from './types.js'
import { pollDeferred } from './deferred.js'
import type { AAuthError } from './deferred.js'
import { parseAAuthHeader } from './aauth-header.js'
import { decodeJwtPayload } from './decode-jwt.js'
import { summarizeResponseHeaders, decodeSignatureKey, peekResponseBody } from './log-helpers.js'

export class TokenExchangeError extends Error {
  constructor(
    public readonly status: number,
    public readonly aauthError?: AAuthError,
  ) {
    const msg = aauthError?.error_description
      || aauthError?.error
      || `Token exchange failed with status ${status}`
    super(msg)
    this.name = 'TokenExchangeError'
  }
}

export interface TokenExchangeOptions {
  signedFetch: FetchLike
  authServerUrl: string
  /** Cached auth-server metadata; when provided, skips the /.well-known fetch. */
  authServerMetadata?: AuthServerMetadata
  resourceToken: string
  justification?: string
  localhostCallback?: string
  loginHint?: string
  tenant?: string
  domainHint?: string
  capabilities?: string[]
  prompt?: string
  onInteraction?: (url: string, code: string) => void
  onClarification?: (question: string) => Promise<string>
  onEvent?: OnEvent
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

export interface AuthServerMetadata {
  token_endpoint: string
  jwks_uri?: string
}

const PREFER_WAIT = 45

/**
 * Exchange a resource token for an auth token via the auth server.
 *
 * 1. Fetches auth server metadata (/.well-known/aauth-person.json)
 * 2. POSTs to token_endpoint with resource_token + hints, Prefer: wait=45
 * 3. If 200: returns tokens directly
 * 4. If 202: polls via pollDeferred until terminal response
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

  // 1. Auth server metadata — use the cached copy if provided, else fetch it.
  const metadata = options.authServerMetadata
    ?? await fetchMetadata(signedFetch, authServerUrl, onEvent, getKeyMaterial, sentTracker)

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

  // 3. POST to token endpoint
  if (onEvent) {
    const agentToken = getKeyMaterial
      ? decodeSignatureKey((await getKeyMaterial()).signatureKey)
      : undefined
    onEvent({
      step: 'ps_token_request',
      phase: 'start',
      url: metadata.token_endpoint,
      agent_token: agentToken,
    })
  }
  const tokenBody = JSON.stringify(body)
  const response = await signedFetch(metadata.token_endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Prefer: `wait=${PREFER_WAIT}`,
    },
    body: tokenBody,
  })
  // Peek body for 202 (deferred) responses where downstream code only reads headers.
  const tokenResponseBody = response.status === 202 ? await peekResponseBody(response) : undefined
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
      authToken: decodeJwtPayload(parsed.authToken),
    })
    return parsed
  }

  if (response.status === 202) {
    onEvent?.({ step: 'ps_consent_pending', phase: 'info' })
    const locationUrl = response.headers.get('location')
    if (!locationUrl) {
      throw new Error('202 response missing Location header')
    }

    // Check for interaction url and code in AAuth-Requirement header
    let interactionUrl: string | undefined
    let interactionCode: string | undefined
    const aauthHeader = response.headers.get('aauth-requirement')
    if (aauthHeader) {
      const challenge = parseAAuthHeader(aauthHeader)
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
      sentTracker,
    })

    if (result.response.status === 200) {
      const parsed = parseTokenResponse(await result.response.json() as Record<string, unknown>)
      onEvent?.({
        step: 'auth_token_received',
        phase: 'info',
        expiresIn: parsed.expiresIn,
        authToken: decodeJwtPayload(parsed.authToken),
      })
      return parsed
    }

    throw new TokenExchangeError(result.response.status, result.error)
  }

  throw new TokenExchangeError(response.status)
}

async function fetchMetadata(
  signedFetch: FetchLike,
  authServerUrl: string,
  onEvent?: OnEvent,
  getKeyMaterial?: GetKeyMaterial,
  sentTracker?: { latest?: CapturedSent },
): Promise<AuthServerMetadata> {
  const metadataUrl = `${authServerUrl.replace(/\/$/, '')}/.well-known/aauth-person.json`
  if (onEvent) {
    const agentToken = getKeyMaterial
      ? decodeSignatureKey((await getKeyMaterial()).signatureKey)
      : undefined
    onEvent({ step: 'ps_metadata_request', phase: 'start', url: metadataUrl, agent_token: agentToken })
  }
  const response = await signedFetch(metadataUrl, { method: 'GET' })
  // Peek body so the rendered card can show the discovered endpoints.
  const responseBody = response.ok ? await peekResponseBody(response) : undefined
  onEvent?.({
    step: 'ps_metadata_request',
    phase: 'done',
    status: response.status,
    request_headers: sentTracker?.latest?.headers,
    response: {
      headers: summarizeResponseHeaders(response.headers),
      ...(responseBody !== undefined ? { body: responseBody } : {}),
    },
  })

  if (!response.ok) {
    throw new Error(`Failed to fetch auth server metadata: ${response.status}`)
  }

  const metadata = await response.json() as Record<string, unknown>
  if (!metadata.token_endpoint) {
    throw new Error('Auth server metadata missing token_endpoint')
  }

  return metadata as unknown as AuthServerMetadata
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

function resolveUrl(base: string, url: string): string {
  if (url.startsWith('http://') || url.startsWith('https://')) {
    return url
  }
  return new URL(url, base).href
}
