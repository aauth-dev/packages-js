import type { FetchLike } from './types.js'
import { pollDeferred } from './deferred.js'
import type { AAuthError } from './deferred.js'
import { parseAAuthHeader } from './aauth-header.js'

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
}

export interface TokenExchangeResult {
  authToken: string
  expiresIn: number
}

interface AuthServerMetadata {
  token_endpoint: string
  jwks_uri: string
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
  } = options

  // 1. Fetch auth server metadata
  const metadata = await fetchMetadata(signedFetch, authServerUrl)

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
  const response = await signedFetch(metadata.token_endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Prefer: `wait=${PREFER_WAIT}`,
    },
    body: JSON.stringify(body),
  })

  // 4. Handle response
  if (response.status === 200) {
    return parseTokenResponse(await response.json() as Record<string, unknown>)
  }

  if (response.status === 202) {
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
    })

    if (result.response.status === 200) {
      return parseTokenResponse(await result.response.json() as Record<string, unknown>)
    }

    throw new TokenExchangeError(result.response.status, result.error)
  }

  throw new TokenExchangeError(response.status)
}

async function fetchMetadata(signedFetch: FetchLike, authServerUrl: string): Promise<AuthServerMetadata> {
  const metadataUrl = `${authServerUrl.replace(/\/$/, '')}/.well-known/aauth-person.json`
  const response = await signedFetch(metadataUrl, { method: 'GET' })

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
