import { fetch as httpSigFetch, DEFAULT_COMPONENTS_GET, DEFAULT_COMPONENTS_BODY } from '@hellocoop/httpsig'
import { createSignedFetch } from './signed-fetch.js'
import { parseRequirementHeader } from '@aauth/protocol'
import type { Capability } from '@aauth/protocol'
import { exchangeToken } from './token-exchange.js'
import type { PersonServerMetadata } from './token-exchange.js'
import { createPersonTokenCache } from './person-token.js'
import type { PersonTokenCache } from './person-token.js'
import { pollDeferred } from './deferred.js'
import {
  summarizeResponseHeaders,
  decodeSignatureKey,
  captureSentFromHttpsig,
  peekResponseBody,
  decodeJwtPayloadSafe,
} from './log-helpers.js'
import type { GetKeyMaterial, FetchLike, OnEvent, CapturedSent } from './types.js'

export interface AAuthFetchOptions {
  getKeyMaterial: GetKeyMaterial
  /**
   * The agent's person server — the `ps` claim of its agent token. Both the
   * person-token hop (`person_token_endpoint`) and the auth-token hop
   * (`auth_token_endpoint`) go here, which is why the name says "person" and
   * not "auth": under -11 the PS has two token endpoints and "auth" would name
   * the wrong one.
   */
  personServerUrl?: string
  /** Cached PS metadata; when provided, both hops skip the /.well-known fetch. */
  personServerMetadata?: PersonServerMetadata
  /** Called with freshly-fetched metadata so the caller can persist it. */
  onMetadata?: (metadata: PersonServerMetadata) => void
  /** Called with the auth token minted during a challenge exchange, so the caller
   * can surface it as a reusable credential (e.g. `fetch --with-token`). */
  onAuthToken?: (authToken: string, expiresIn: number) => void
  /** Called with each person token minted for a resource. */
  onPersonToken?: (personToken: string, resource: string) => void
  /** Called with an opaque AAuth-Access token received from a resource (two-party
   * mode), including rolling-refresh replacements, so the caller can surface it
   * for reuse. */
  onOpaqueToken?: (opaqueToken: string) => void
  /** Seed an opaque AAuth-Access token (two-party mode) to send on the first
   * request to a resource — the reuse counterpart of `onOpaqueToken`. */
  opaqueToken?: string
  onInteraction?: (url: string, code: string) => void
  onClarification?: (question: string) => Promise<string>
  onEvent?: OnEvent
  justification?: string
  loginHint?: string
  tenant?: string
  domainHint?: string
  capabilities?: Capability[]
  /**
   * The mission the agent is operating under — the base64url SHA-256 of the
   * approved mission blob. Forwarded to the PS when a person token is
   * requested; from there the PS stamps it into the person token, the resource
   * copies it into the resource token, and the PS or AS copies it into the auth
   * token. There is no `AAuth-Mission` header in -11; a mission only ever
   * reaches a resource inside a token.
   */
  missionS256?: string
  prompt?: string
  /** Total consent-poll timeout in seconds (default 900) — see pollDeferred. */
  maxPollDuration?: number
}

interface CachedToken {
  authToken: string
  expiresAt: number
  authServer: string
}

interface CachedOpaque {
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
    personServerUrl: configuredPersonServer,
    personServerMetadata,
    onMetadata,
    onAuthToken,
    onPersonToken,
    onOpaqueToken,
    opaqueToken: seedOpaqueToken,
    onInteraction,
    onClarification,
    onEvent,
    justification,
    loginHint,
    tenant,
    domainHint,
    capabilities,
    missionS256,
    prompt,
    maxPollDuration,
  } = options

  // Shared mutable holder for the latest signed-request capture. signed-fetch
  // and the fetchWith* helpers populate `.latest` via onSigned; the next
  // emitted :done event (here, in token-exchange, or in deferred) reads it.
  // Wide explicit type so TS doesn't narrow `.latest` to never after we set
  // it to undefined before an awaited call that mutates it via callback.
  const sentTracker: { latest: CapturedSent | undefined } = { latest: undefined }
  const onSigned = onEvent ? (sent: CapturedSent) => { sentTracker.latest = sent } : undefined

  // Two flavours of signed fetch. Resource-facing requests sign the base
  // components only — a resource states any extra it needs through
  // `additional_signature_components`. PS/AS-facing requests additionally sign
  // `content-digest` and `content-type` on any request with a body, which -11
  // makes unconditional at those endpoints.
  const signedFetch = createSignedFetch(getKeyMaterial, { capabilities, onSigned })
  const psSignedFetch = createSignedFetch(getKeyMaterial, { capabilities, signBody: true, onSigned })

  const personTokens: PersonTokenCache | undefined = configuredPersonServer
    ? createPersonTokenCache({
      signedFetch: psSignedFetch,
      personServerUrl: configuredPersonServer,
      personServerMetadata,
      onMetadata,
      onInteraction,
      onClarification,
      onEvent,
      maxPollDuration,
      getKeyMaterial,
      sentTracker,
    })
    : undefined

  const tokenCache = new Map<string, CachedToken>()
  const opaqueCache = new Map<string, CachedOpaque>()

  return async (url: string | URL, init?: RequestInit): Promise<Response> => {
    const urlStr = typeof url === 'string' ? url : url.toString()
    const resourceOrigin = new URL(urlStr).origin

    // Seed a provided AAuth-Access token (two-party reuse) so the first request
    // to this resource sends it. A token the resource later returns replaces it.
    if (seedOpaqueToken && !opaqueCache.has(resourceOrigin)) {
      opaqueCache.set(resourceOrigin, { token: seedOpaqueToken })
    }

    // Check cache for a valid auth token for this resource
    const cached = findCachedToken(tokenCache, resourceOrigin)
    if (cached) {
      // Use cached auth token — sign with auth token instead of agent token
      const response = await fetchWithToken(url, init, cached.authToken, getKeyMaterial, onSigned)
      // If the cached token is rejected, fall through to challenge flow
      if (response.status !== 401) {
        cacheOpaqueToken(opaqueCache, resourceOrigin, response, onOpaqueToken)
        return handleResourceInteraction(response, signedFetch, onInteraction, onClarification)
      }
      // Cached token rejected — remove and proceed with fresh exchange
      tokenCache.delete(cacheKey(resourceOrigin, cached.authServer))
    }

    // Check cache for an opaque AAuth-Access token (two-party mode)
    const cachedOpaque = opaqueCache.get(resourceOrigin)
    if (cachedOpaque) {
      const response = await fetchWithOpaqueToken(url, init, cachedOpaque.token, getKeyMaterial, onSigned)
      if (response.status !== 401) {
        cacheOpaqueToken(opaqueCache, resourceOrigin, response, onOpaqueToken)
        return handleResourceInteraction(response, signedFetch, onInteraction, onClarification)
      }
      // Access token rejected — remove and proceed
      opaqueCache.delete(resourceOrigin)
    }

    // Send signed request (no auth token)
    if (onEvent) {
      const km = await getKeyMaterial()
      onEvent({
        step: 'signed_request',
        phase: 'start',
        url: urlStr,
        method: (init?.method as string) ?? 'GET',
        agent_token: decodeSignatureKey(km.signatureKey),
      })
    }
    let response = await signedFetch(url, init)
    const responseBody = onEvent ? await peekResponseBody(response) : undefined
    onEvent?.({
      step: 'signed_request',
      phase: 'done',
      status: response.status,
      request_headers: sentTracker.latest?.headers,
      request_body: sentTracker.latest?.body,
      response: {
        headers: summarizeResponseHeaders(response.headers),
        ...(responseBody !== undefined ? { body: responseBody } : {}),
      },
    })

    // 401 requirement=person-token: the resource wants the person's identity
    // before it will serve or issue anything. Get one from the PS for this
    // resource and retry with it in place of the agent token. An agent with no
    // person server cannot satisfy this and returns the 401 to its caller.
    if (response.status === 401 && personTokens) {
      const requirementHeader = response.headers.get('aauth-requirement')
      if (requirementHeader && parseRequirementHeader(requirementHeader).requirement === 'person-token') {
        onEvent?.({ step: 'challenge_received', phase: 'info', requirement: 'person-token' })
        const personToken = await personTokens.get(resourceOrigin, missionS256)
        onPersonToken?.(personToken, resourceOrigin)
        onEvent?.({
          step: 'retry_with_person_token',
          phase: 'start',
          url: urlStr,
          person_token: decodeJwtPayloadSafe(personToken),
        })
        response = await fetchWithToken(url, init, personToken, getKeyMaterial, onSigned)
        const retryBody = onEvent ? await peekResponseBody(response) : undefined
        onEvent?.({
          step: 'retry_with_person_token',
          phase: 'done',
          status: response.status,
          request_headers: sentTracker.latest?.headers,
          request_body: sentTracker.latest?.body,
          response: {
            headers: summarizeResponseHeaders(response.headers),
            ...(retryBody !== undefined ? { body: retryBody } : {}),
          },
        })
      }
    }

    // 200: success — check for AAuth-Access token
    if (response.status === 200) {
      cacheOpaqueToken(opaqueCache, resourceOrigin, response, onOpaqueToken)
      return response
    }

    // 401 with AAuth-Requirement challenge: token exchange flow
    if (response.status === 401) {
      const aauthHeader = response.headers.get('aauth-requirement')
      if (!aauthHeader) {
        return response // Not an AAuth challenge
      }

      const challenge = parseRequirementHeader(aauthHeader)

      if (challenge.requirement === 'auth-token' && challenge.resourceToken) {
        onEvent?.({
          step: 'challenge_received',
          phase: 'info',
          requirement: 'auth-token',
          resourceToken: decodeJwtPayloadSafe(challenge.resourceToken),
        })
        // The agent sends the resource token to its own auth server
        const authServerUrl = configuredPersonServer
        if (!authServerUrl) {
          throw new Error('auth-token challenge received but no personServerUrl configured')
        }

        const result = await exchangeToken({
          signedFetch: psSignedFetch,
          authServerUrl,
          authServerMetadata: personServerMetadata,
          onMetadata,
          resourceToken: challenge.resourceToken,
          justification,
          loginHint,
          tenant,
          domainHint,
          capabilities,
          prompt,
          onInteraction,
          onClarification,
          onEvent,
          maxPollDuration,
          getKeyMaterial,
          sentTracker,
        })

        // Cache the auth token
        const key = cacheKey(resourceOrigin, authServerUrl)
        tokenCache.set(key, {
          authToken: result.authToken,
          expiresAt: Date.now() + result.expiresIn * 1000,
          authServer: authServerUrl,
        })
        // Surface it as a reusable credential (e.g. `fetch --with-token`).
        onAuthToken?.(result.authToken, result.expiresIn)

        // Retry with auth token
        onEvent?.({
          step: 'retry_with_auth_token',
          phase: 'start',
          url: urlStr,
          auth_token: decodeJwtPayloadSafe(result.authToken),
        })
        const retryResponse = await fetchWithToken(
          url, init, result.authToken, getKeyMaterial, onSigned,
        )
        const retryBody = onEvent ? await peekResponseBody(retryResponse) : undefined
        onEvent?.({
          step: 'retry_with_auth_token',
          phase: 'done',
          status: retryResponse.status,
          request_headers: sentTracker.latest?.headers,
          request_body: sentTracker.latest?.body,
          response: {
            headers: summarizeResponseHeaders(retryResponse.headers),
            ...(retryBody !== undefined ? { body: retryBody } : {}),
          },
        })
        cacheOpaqueToken(opaqueCache, resourceOrigin, retryResponse, onOpaqueToken)
        return handleResourceInteraction(retryResponse, signedFetch, onInteraction, onClarification)
      }

      // non-auth-token challenges (approval, clarification, claims) don't require token exchange
      return response
    }

    // 202 with interaction: resource-level interaction (two-party mode)
    const terminalResponse = await handleResourceInteraction(response, signedFetch, onInteraction, onClarification)
    cacheOpaqueToken(opaqueCache, resourceOrigin, terminalResponse, onOpaqueToken)
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
      const challenge = parseRequirementHeader(aauthHeader)
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
 * Send a signed request presenting `token` as the signature key — a person
 * token or an auth token, in place of the agent token. Both are presented the
 * same way (`Signature-Key: sig=jwt;jwt="…"`) and both carry the request's
 * signing key in `cnf.jwk`, so verification proceeds identically.
 */
async function fetchWithToken(
  url: string | URL,
  init: RequestInit | undefined,
  token: string,
  getKeyMaterial: GetKeyMaterial,
  onSigned?: (sent: CapturedSent) => void,
): Promise<Response> {
  const { signingKey } = await getKeyMaterial()
  if (onSigned) {
    const { response, sent } = await httpSigFetch(url, {
      ...init,
      signingKey,
      signatureKey: { type: 'jwt', jwt: token },
      returnSent: true,
    })
    onSigned(captureSentFromHttpsig(sent))
    return response
  }
  return await httpSigFetch(url, {
    ...init,
    signingKey,
    signatureKey: { type: 'jwt', jwt: token },
  })
}

/**
 * Send a signed request with an opaque AAuth-Access token in the Authorization header.
 * The agent signs the request (including the authorization header) with its agent token.
 */
async function fetchWithOpaqueToken(
  url: string | URL,
  init: RequestInit | undefined,
  opaqueToken: string,
  getKeyMaterial: GetKeyMaterial,
  onSigned?: (sent: CapturedSent) => void,
): Promise<Response> {
  const { signingKey, signatureKey } = await getKeyMaterial()
  const headers = new Headers(init?.headers)
  // Spec (#aauth-access): the opaque token goes back under the "AAuth" auth
  // scheme, and `authorization` MUST be in the signature's covered components so
  // the token is bound to this signature — not replayable as a bearer token.
  headers.set('authorization', `AAuth ${opaqueToken}`)
  const base = init?.body != null ? DEFAULT_COMPONENTS_BODY : DEFAULT_COMPONENTS_GET
  const components = [...base.filter((c) => c !== 'signature-key'), 'authorization', 'signature-key']
  const httpSigKey = signatureKey.type === 'jkt-jwt'
    ? { type: 'jwt' as const, jwt: signatureKey.jwt }
    : signatureKey
  if (onSigned) {
    const { response, sent } = await httpSigFetch(url, {
      ...init,
      headers,
      signingKey,
      signatureKey: httpSigKey,
      components,
      returnSent: true,
    })
    onSigned(captureSentFromHttpsig(sent))
    return response
  }
  return await httpSigFetch(url, {
    ...init,
    headers,
    signingKey,
    signatureKey: httpSigKey,
    components,
  })
}

/**
 * Cache an AAuth-Access token from a response if present, and surface it via
 * onOpaqueToken. A new AAuth-Access header replaces any previously cached token.
 */
function cacheOpaqueToken(
  cache: Map<string, CachedOpaque>,
  resourceOrigin: string,
  response: Response,
  onOpaqueToken?: (opaqueToken: string) => void,
): void {
  const opaqueToken = response.headers.get('aauth-access')
  if (opaqueToken) {
    cache.set(resourceOrigin, { token: opaqueToken })
    onOpaqueToken?.(opaqueToken)
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
