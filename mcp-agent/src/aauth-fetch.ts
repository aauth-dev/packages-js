import { fetch as httpSigFetch } from '@hellocoop/httpsig'
import { createSignedFetch } from './signed-fetch.js'
import { parseAAuthHeader, buildCapabilitiesHeader, buildMissionHeader } from './aauth-header.js'
import { exchangeToken } from './token-exchange.js'
import { pollDeferred } from './deferred.js'
import type { GetKeyMaterial, FetchLike } from './types.js'
import type { Capability, AAuthMission } from './aauth-header.js'

export interface AAuthFetchOptions {
  getKeyMaterial: GetKeyMaterial
  authServerUrl?: string
  onInteraction?: (url: string, code: string) => void
  onClarification?: (question: string) => Promise<string>
  justification?: string
  loginHint?: string
  tenant?: string
  domainHint?: string
  capabilities?: Capability[]
  mission?: AAuthMission
}

interface CachedToken {
  authToken: string
  expiresAt: number
  authServer: string
}

interface CachedAccess {
  token: string
}

/**
 * Create a protocol-aware fetch that handles the full AAuth challenge-response flow.
 *
 * Wraps createSignedFetch with:
 * 1. 401 AAuth-Requirement challenge handling (token exchange + retry)
 * 2. 202 resource interaction (polling)
 * 3. Auth token caching by {resource origin, authServer}
 */
export function createAAuthFetch(options: AAuthFetchOptions): FetchLike {
  const {
    getKeyMaterial,
    authServerUrl: configuredAuthServer,
    onInteraction,
    onClarification,
    justification,
    loginHint,
    tenant,
    domainHint,
    capabilities,
    mission,
  } = options

  const signedFetch = createSignedFetch(getKeyMaterial, { capabilities, mission })
  const tokenCache = new Map<string, CachedToken>()
  const accessCache = new Map<string, CachedAccess>()

  return async (url: string | URL, init?: RequestInit): Promise<Response> => {
    const urlStr = typeof url === 'string' ? url : url.toString()
    const resourceOrigin = new URL(urlStr).origin

    // Check cache for a valid auth token for this resource
    const cached = findCachedToken(tokenCache, resourceOrigin)
    if (cached) {
      // Use cached auth token — sign with auth token instead of agent token
      const response = await fetchWithAuthToken(url, init, cached.authToken, getKeyMaterial)
      // If the cached token is rejected, fall through to challenge flow
      if (response.status !== 401) {
        cacheAccessToken(accessCache, resourceOrigin, response)
        return handleResourceInteraction(response, signedFetch, onInteraction, onClarification)
      }
      // Cached token rejected — remove and proceed with fresh exchange
      tokenCache.delete(cacheKey(resourceOrigin, cached.authServer))
    }

    // Check cache for an opaque AAuth-Access token (two-party mode)
    const cachedAccess = accessCache.get(resourceOrigin)
    if (cachedAccess) {
      const response = await fetchWithAccessToken(url, init, cachedAccess.token, getKeyMaterial)
      if (response.status !== 401) {
        cacheAccessToken(accessCache, resourceOrigin, response)
        return handleResourceInteraction(response, signedFetch, onInteraction, onClarification)
      }
      // Access token rejected — remove and proceed
      accessCache.delete(resourceOrigin)
    }

    // Send signed request (no auth token)
    const response = await signedFetch(url, init)

    // 200: success — check for AAuth-Access token
    if (response.status === 200) {
      cacheAccessToken(accessCache, resourceOrigin, response)
      return response
    }

    // 401 with AAuth-Requirement challenge: token exchange flow
    if (response.status === 401) {
      const aauthHeader = response.headers.get('aauth-requirement')
      if (!aauthHeader) {
        return response // Not an AAuth challenge
      }

      const challenge = parseAAuthHeader(aauthHeader)

      if (challenge.requirement === 'auth-token' && challenge.resourceToken) {
        // The agent sends the resource token to its own auth server
        const authServerUrl = configuredAuthServer
        if (!authServerUrl) {
          throw new Error('auth-token challenge received but no authServerUrl configured')
        }

        const result = await exchangeToken({
          signedFetch,
          authServerUrl,
          resourceToken: challenge.resourceToken,
          justification,
          loginHint,
          tenant,
          domainHint,
          capabilities,
          onInteraction,
          onClarification,
        })

        // Cache the auth token
        const key = cacheKey(resourceOrigin, authServerUrl)
        tokenCache.set(key, {
          authToken: result.authToken,
          expiresAt: Date.now() + result.expiresIn * 1000,
          authServer: authServerUrl,
        })

        // Retry with auth token
        const retryResponse = await fetchWithAuthToken(
          url, init, result.authToken, getKeyMaterial,
        )
        cacheAccessToken(accessCache, resourceOrigin, retryResponse)
        return handleResourceInteraction(retryResponse, signedFetch, onInteraction, onClarification)
      }

      // non-auth-token challenges (approval, clarification, claims) don't require token exchange
      return response
    }

    // 202 with interaction: resource-level interaction (two-party mode)
    const terminalResponse = await handleResourceInteraction(response, signedFetch, onInteraction, onClarification)
    cacheAccessToken(accessCache, resourceOrigin, terminalResponse)
    return terminalResponse
  }
}

/**
 * Handle 202 resource-level interaction by polling.
 */
async function handleResourceInteraction(
  response: Response,
  signedFetch: FetchLike,
  onInteraction?: (url: string, code: string) => void,
  onClarification?: (question: string) => Promise<string>,
): Promise<Response> {
  if (response.status !== 202) {
    return response
  }

  const locationUrl = response.headers.get('location')
  if (!locationUrl) {
    return response // No Location → return as-is
  }

  let interactionUrl: string | undefined
  let interactionCode: string | undefined
  const aauthHeader = response.headers.get('aauth-requirement')
  if (aauthHeader) {
    try {
      const challenge = parseAAuthHeader(aauthHeader)
      if (challenge.requirement === 'interaction' && challenge.url && challenge.code) {
        interactionUrl = challenge.url
        interactionCode = challenge.code
      }
    } catch {
      // Not a valid AAuth-Requirement header — ignore
    }
  }

  const result = await pollDeferred({
    signedFetch,
    locationUrl,
    interactionUrl,
    interactionCode,
    onInteraction,
    onClarification,
  })

  return result.response
}

/**
 * Send a signed request using the auth token as the signature key.
 * The auth token replaces the agent token in the Signature-Key header.
 */
async function fetchWithAuthToken(
  url: string | URL,
  init: RequestInit | undefined,
  authToken: string,
  getKeyMaterial: GetKeyMaterial,
): Promise<Response> {
  const { signingKey } = await getKeyMaterial()
  const response = await httpSigFetch(url, {
    ...init,
    signingKey,
    signatureKey: { type: 'jwt', jwt: authToken },
  })
  return response as Response
}

/**
 * Send a signed request with an opaque AAuth-Access token in the Authorization header.
 * The agent signs the request (including the authorization header) with its agent token.
 */
async function fetchWithAccessToken(
  url: string | URL,
  init: RequestInit | undefined,
  accessToken: string,
  getKeyMaterial: GetKeyMaterial,
): Promise<Response> {
  const { signingKey, signatureKey } = await getKeyMaterial()
  const headers = new Headers(init?.headers)
  headers.set('authorization', `Bearer ${accessToken}`)
  const httpSigKey = signatureKey.type === 'jkt-jwt'
    ? { type: 'jwt' as const, jwt: signatureKey.jwt }
    : signatureKey
  const response = await httpSigFetch(url, {
    ...init,
    headers,
    signingKey,
    signatureKey: httpSigKey,
  })
  return response as Response
}

/**
 * Cache an AAuth-Access token from a response if present.
 * A new AAuth-Access header replaces any previously cached token.
 */
function cacheAccessToken(cache: Map<string, CachedAccess>, resourceOrigin: string, response: Response): void {
  const accessToken = response.headers.get('aauth-access')
  if (accessToken) {
    cache.set(resourceOrigin, { token: accessToken })
  }
}

function cacheKey(resourceOrigin: string, authServer: string): string {
  return `${resourceOrigin}|${authServer}`
}

function findCachedToken(cache: Map<string, CachedToken>, resourceOrigin: string): CachedToken | undefined {
  for (const [key, cached] of cache) {
    if (key.startsWith(`${resourceOrigin}|`)) {
      // Check if still valid (with 60s buffer)
      if (cached.expiresAt > Date.now() + 60_000) {
        return cached
      }
      // Expired — remove
      cache.delete(key)
    }
  }
  return undefined
}
