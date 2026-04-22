import {
  generateKeyPair,
  exportJWK,
  SignJWT,
  calculateJwkThumbprint,
} from 'jose'
import type { JWK, KeyLike } from 'jose'
import {
  verifyToken,
  buildAAuthHeader,
  createResourceToken,
  InteractionManager,
  clearMetadataCache,
} from '@aauth/mcp-server'
import type { VerifiedToken } from '@aauth/mcp-server'
import type { GetKeyMaterial } from '@aauth/mcp-agent'

// --- Key Material ---

export interface TestKeys {
  agentRoot: { privateKey: KeyLike; publicKey: KeyLike; pubJwk: JWK }
  agentEphemeral: { privateKey: KeyLike; publicKey: KeyLike; pubJwk: JWK; privJwk: JsonWebKey; thumbprint: string }
  authServer: { privateKey: KeyLike; publicKey: KeyLike; pubJwk: JWK }
  resource: { privateKey: KeyLike; publicKey: KeyLike; pubJwk: JWK }
}

export async function createTestKeys(): Promise<TestKeys> {
  const [agentRootPair, ephPair, authPair, resourcePair] = await Promise.all([
    generateKeyPair('EdDSA', { crv: 'Ed25519' }),
    generateKeyPair('EdDSA', { crv: 'Ed25519' }),
    generateKeyPair('EdDSA', { crv: 'Ed25519' }),
    generateKeyPair('EdDSA', { crv: 'Ed25519' }),
  ])

  const agentRootPubJwk = { ...await exportJWK(agentRootPair.publicKey), kid: 'agent-root-1' }
  const ephPubJwk = await exportJWK(ephPair.publicKey)
  const ephPrivJwk = await exportJWK(ephPair.privateKey)
  const ephThumbprint = await calculateJwkThumbprint(ephPubJwk, 'sha256')
  const authPubJwk = { ...await exportJWK(authPair.publicKey), kid: 'auth-1' }
  const resourcePubJwk = { ...await exportJWK(resourcePair.publicKey), kid: 'resource-1' }

  return {
    agentRoot: { privateKey: agentRootPair.privateKey, publicKey: agentRootPair.publicKey, pubJwk: agentRootPubJwk },
    agentEphemeral: { privateKey: ephPair.privateKey, publicKey: ephPair.publicKey, pubJwk: ephPubJwk, privJwk: ephPrivJwk, thumbprint: ephThumbprint },
    authServer: { privateKey: authPair.privateKey, publicKey: authPair.publicKey, pubJwk: authPubJwk },
    resource: { privateKey: resourcePair.privateKey, publicKey: resourcePair.publicKey, pubJwk: resourcePubJwk },
  }
}

// --- Token Factories ---

export async function createAgentJwt(keys: TestKeys, agentUrl: string, sub: string): Promise<string> {
  const now = Math.floor(Date.now() / 1000)
  return new SignJWT({
    iss: agentUrl,
    dwk: 'aauth-agent.json',
    sub,
    cnf: { jwk: keys.agentEphemeral.pubJwk },
    iat: now,
    exp: now + 3600,
  })
    .setProtectedHeader({ alg: 'EdDSA', typ: 'aa-agent+jwt', kid: 'agent-root-1' })
    .sign(keys.agentRoot.privateKey)
}

export async function createAuthJwt(
  keys: TestKeys,
  opts: { iss: string; aud: string; agent: string; sub?: string; scope?: string },
): Promise<string> {
  const now = Math.floor(Date.now() / 1000)
  const claims: Record<string, unknown> = {
    iss: opts.iss,
    dwk: 'aauth-person.json',
    aud: opts.aud,
    agent: opts.agent,
    cnf: { jwk: keys.agentEphemeral.pubJwk },
    iat: now,
    exp: now + 3600,
  }
  if (opts.sub) claims.sub = opts.sub
  if (opts.scope) claims.scope = opts.scope

  return new SignJWT(claims)
    .setProtectedHeader({ alg: 'EdDSA', typ: 'aa-auth+jwt', kid: 'auth-1' })
    .sign(keys.authServer.privateKey)
}

// --- GetKeyMaterial factory ---

export function createGetKeyMaterial(keys: TestKeys, agentJwt: string): GetKeyMaterial {
  return async () => ({
    signingKey: keys.agentEphemeral.privJwk,
    signatureKey: { type: 'jwt' as const, jwt: agentJwt },
  })
}

// --- Mock Server ---

export interface MockServerConfig {
  keys: TestKeys
  resourceUrl: string
  authServerUrl: string
  agentUrl: string
  sub: string
  requireAuthToken?: boolean
  deferredMode?: boolean
  interactionManager?: InteractionManager
  onTokenRequest?: (body: Record<string, string>) => void
}

export interface MockServer {
  httpSigFetch: (url: string | URL, init?: Record<string, unknown>) => Promise<Response>
  globalFetch: (url: string | URL, init?: RequestInit) => Promise<Response>
}

export function createMockServer(config: MockServerConfig): MockServer {
  const {
    keys,
    resourceUrl,
    authServerUrl,
    agentUrl,
    sub,
    requireAuthToken = true,
    deferredMode = false,
    onTokenRequest,
  } = config

  const interactionManager = config.interactionManager ?? (
    deferredMode ? new InteractionManager({ baseUrl: authServerUrl, interactionUrl: `${authServerUrl}/interact` }) : undefined
  )

  // Resource server sign function for createResourceToken
  const resourceSign = async (payload: Record<string, unknown>, header: Record<string, unknown>): Promise<string> => {
    return new SignJWT(payload)
      .setProtectedHeader(header as { alg: string; typ: string })
      .sign(keys.resource.privateKey)
  }

  // httpSigFetch: replaces @hellocoop/httpsig.fetch
  // Receives signingKey + signatureKey in init, routes by URL
  const httpSigFetch = async (url: string | URL, init?: Record<string, unknown>): Promise<Response> => {
    const urlStr = typeof url === 'string' ? url : url.toString()

    // Extract httpsig key material from init
    const signingKey = init?.signingKey as JsonWebKey | undefined
    const signatureKey = init?.signatureKey as { type: string; jwt?: string } | undefined

    // --- Resource server routes ---
    if (urlStr.startsWith(resourceUrl)) {
      if (!signingKey || !signatureKey?.jwt) {
        return new Response('Missing signature', { status: 400 })
      }

      const thumbprint = await calculateJwkThumbprint(signingKey, 'sha256')

      try {
        const verified = await verifyToken({
          jwt: signatureKey.jwt,
          httpSignatureThumbprint: thumbprint,
        })

        if (verified.type === 'auth') {
          // Auth token verified -> 200
          return new Response(JSON.stringify({ status: 'ok', user: verified.sub }), {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          })
        }

        if (verified.type === 'agent' && requireAuthToken) {
          // Agent token only, but resource requires auth token -> 401 challenge
          const resourceToken = await createResourceToken(
            {
              resource: resourceUrl,
              authServer: authServerUrl,
              agent: verified.iss,
              agentJkt: thumbprint,
            },
            resourceSign,
          )
          const aauthHeader = buildAAuthHeader('auth-token', {
            resourceToken,
          })
          return new Response('Auth token required', {
            status: 401,
            headers: { 'AAuth-Requirement': aauthHeader },
          })
        }

        // Agent token accepted (requireAuthToken = false)
        return new Response(JSON.stringify({ status: 'ok', agent: verified.iss }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        })
      } catch (err) {
        return new Response(`Token verification failed: ${(err as Error).message}`, {
          status: 401,
        })
      }
    }

    // --- Auth server metadata ---
    if (urlStr === `${authServerUrl}/.well-known/aauth-person.json`) {
      return new Response(JSON.stringify({
        token_endpoint: `${authServerUrl}/aauth/token`,
        jwks_uri: `${authServerUrl}/jwks`,
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      })
    }

    // --- Auth server token endpoint ---
    if (urlStr === `${authServerUrl}/aauth/token`) {
      const bodyStr = init?.body as string | undefined
      const body = bodyStr ? JSON.parse(bodyStr) as Record<string, string> : {}

      if (onTokenRequest) {
        onTokenRequest(body)
      }

      if (deferredMode && interactionManager) {
        // Deferred: return 202 with pending
        const { headers } = interactionManager.createPending()
        return new Response(null, {
          status: 202,
          headers,
        })
      }

      // Direct mode: create real aa-auth+jwt and return it
      const authJwt = await createAuthJwt(keys, {
        iss: authServerUrl,
        aud: resourceUrl,
        agent: agentUrl,
        sub: 'user-123',
      })

      return new Response(JSON.stringify({
        auth_token: authJwt,
        expires_in: 3600,
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      })
    }

    // --- Auth server pending endpoint (for deferred polling) ---
    if (urlStr.startsWith(`${authServerUrl}/pending/`) && interactionManager) {
      const id = urlStr.split('/pending/')[1]
      const pending = interactionManager.getPending(id)

      if (!pending) {
        return new Response('Not found', { status: 410 })
      }

      // Check if already resolved
      try {
        const result = await Promise.race([
          pending.promise,
          new Promise((_, reject) => setTimeout(() => reject(new Error('still_pending')), 50)),
        ]) as { auth_token: string; expires_in: number }

        // Resolved!
        return new Response(JSON.stringify(result), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        })
      } catch {
        // Still pending -> 202
        return new Response(null, {
          status: 202,
          headers: {
            'Retry-After': '0',
            'Cache-Control': 'no-store',
          },
        })
      }
    }

    return new Response('Not Found', { status: 404 })
  }

  // globalFetch: for verifyToken's internal JWKS/metadata lookups
  const globalFetch = async (url: string | URL, _init?: RequestInit): Promise<Response> => {
    const urlStr = typeof url === 'string' ? url : url.toString()

    // Agent metadata
    if (urlStr === `${agentUrl}/.well-known/aauth-agent.json`) {
      return new Response(JSON.stringify({ jwks_uri: `${agentUrl}/jwks` }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      })
    }

    // Agent JWKS
    if (urlStr === `${agentUrl}/jwks`) {
      return new Response(JSON.stringify({ keys: [keys.agentRoot.pubJwk] }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      })
    }

    // Auth server metadata
    if (urlStr === `${authServerUrl}/.well-known/aauth-person.json`) {
      return new Response(JSON.stringify({
        jwks_uri: `${authServerUrl}/jwks`,
        token_endpoint: `${authServerUrl}/aauth/token`,
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      })
    }

    // Auth server JWKS
    if (urlStr === `${authServerUrl}/jwks`) {
      return new Response(JSON.stringify({ keys: [keys.authServer.pubJwk] }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      })
    }

    return new Response('Not Found', { status: 404 })
  }

  return { httpSigFetch, globalFetch }
}
