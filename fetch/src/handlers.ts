import { createHash } from 'node:crypto'
import { createAgentToken, readConfig, getAgentConfig } from '@aauth/local-keys'
import {
  createAAuthFetch,
  createSignedFetch,
  parseAAuthHeader,
  exchangeToken,
  decodeJwtPayload,
} from '@aauth/mcp-agent'
import type { GetKeyMaterial, KeyMaterial, FetchLike, Capability, OnEvent } from '@aauth/mcp-agent'
import open from 'open'
import { buildLogEmitter, type LogMode } from './log.js'

// --log → pretty narrative; --jsonl → NDJSON; neither → silent. The args
// parser already enforces mutual exclusion between the two.
function pickLogMode(args: { log?: boolean; jsonl?: boolean }): LogMode | undefined {
  if (args.log) return 'pretty'
  if (args.jsonl) return 'jsonl'
  return undefined
}

/**
 * Filter response headers to AAuth-relevant set for --log events. Mirrors the
 * helper in @aauth/mcp-agent so fetch CLI events have consistent shape.
 */
const AAUTH_RELEVANT_RESPONSE_HEADERS = [
  'www-authenticate',
  'aauth-requirement',
  'aauth-access',
  'content-type',
  'location',
]
function summarizeResponseHeaders(headers: Headers): Record<string, string> {
  const out: Record<string, string> = {}
  for (const k of AAUTH_RELEVANT_RESPONSE_HEADERS) {
    const v = headers.get(k)
    if (v) out[k] = v
  }
  return out
}

function decodeSignatureJwt(km: KeyMaterial): Record<string, unknown> | undefined {
  if (km.signatureKey.type === 'hwk') return undefined
  return decodeJwtPayload(km.signatureKey.jwt)
}

/**
 * Wrap a fetch function to log all requests and responses to stderr.
 */
function debugFetch(innerFetch: FetchLike): FetchLike {
  let seq = 0
  return async (url, init) => {
    const id = ++seq
    const method = (init as RequestInit)?.method ?? 'GET'
    const headers = init?.headers ? headersToObject(new Headers(init.headers as HeadersInit)) : {}
    console.error(JSON.stringify({ debug: 'request', id, method, url, headers }))

    const response = await innerFetch(url, init)

    const respHeaders = headersToObject(response.headers)
    console.error(JSON.stringify({ debug: 'response', id, status: response.status, headers: respHeaders }))
    return response
  }
}

export function resolvePersonServer(agentUrl: string | undefined, override: string | undefined): string | undefined {
  if (override) return override
  if (!agentUrl) {
    const config = readConfig()
    const providers = Object.entries(config.agentProviders)
    if (providers.length === 1) {
      return providers[0][1].personServerUrl
    }
    return undefined
  }
  const agentConfig = getAgentConfig(agentUrl)
  return agentConfig?.personServerUrl
}

export function buildGetKeyMaterial(args: { agentUrl?: string; local?: string }): GetKeyMaterial {
  return () => createAgentToken({
    agentUrl: args.agentUrl,
    local: args.local,
  })
}

export function buildRequestInit(args: { method: string; data?: string; headers: string[] }): RequestInit {
  const headers = new Headers()
  for (const h of args.headers) {
    const colon = h.indexOf(':')
    if (colon === -1) continue
    headers.set(h.slice(0, colon).trim(), h.slice(colon + 1).trim())
  }

  if (args.data && !headers.has('content-type')) {
    headers.set('content-type', 'application/json')
  }

  const init: RequestInit = {
    method: args.method,
    headers,
  }
  if (args.data) {
    init.body = args.data
  }
  return init
}

/**
 * --authorize mode: manually drive the auth flow using low-level primitives
 * so we can capture and return the auth token + ephemeral signing key.
 */
export async function handleAuthorize(
  args: {
    url: string; agentUrl?: string; operations?: string; scope?: string;
    browser?: boolean; nonInteractive: boolean; verbose: boolean; debug?: boolean; log?: boolean; jsonl?: boolean;
    loginHint?: string; domainHint?: string; tenant?: string; justification?: string;
    capabilities?: string[]; forceConsent?: boolean;
  },
  getKeyMaterial: GetKeyMaterial,
  personServer: string | undefined,
): Promise<void> {
  const shouldOpenBrowser = args.browser ?? true
  const capabilities = args.capabilities as Capability[] | undefined
  const log = buildLogEmitter(pickLogMode(args), { url: args.url, agentUrl: args.agentUrl, personServer })
  const onEvent: OnEvent | undefined = log?.onEvent

  const keyMaterial = await getKeyMaterial()
  if (args.debug) {
    logKeyMaterial('authorize', keyMaterial)
  }
  const pinnedGetKeyMaterial: GetKeyMaterial = async () => keyMaterial

  let signedFetch = createSignedFetch(pinnedGetKeyMaterial, { capabilities })
  if (args.debug) signedFetch = debugFetch(signedFetch)

  // Get resource token: either via R3 authorize endpoint or 401 challenge
  let resourceToken: string | undefined

  if (args.operations) {
    // R3 flow: POST to authorize endpoint with operations body
    const operationIds = args.operations.split(',').map(s => s.trim())
    const r3Body = {
      r3_operations: {
        vocabulary: 'urn:aauth:vocabulary:openapi',
        operations: operationIds.map(id => ({ operationId: id })),
      },
    }

    onEvent?.({
      step: 'r3_authorize_request',
      phase: 'start',
      url: args.url,
      operations: operationIds,
      agent_token: decodeSignatureJwt(keyMaterial),
    })
    const response = await signedFetch(args.url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(r3Body),
    })
    onEvent?.({
      step: 'r3_authorize_request',
      phase: 'done',
      status: response.status,
      response: { headers: summarizeResponseHeaders(response.headers) },
    })

    if (args.verbose) {
      console.error(JSON.stringify({ status: response.status, headers: headersToObject(response.headers) }))
    }

    if (response.status !== 200) {
      const body = await response.text()
      console.error(JSON.stringify({ error: `Authorize endpoint returned status ${response.status}`, body: tryParseJson(body) }))
      process.exitCode = 1
      return
    }

    const respBody = await response.json() as Record<string, unknown>
    resourceToken = respBody.resource_token as string
    if (!resourceToken) {
      console.error(JSON.stringify({ error: 'Authorize response missing resource_token' }))
      process.exitCode = 1
      return
    }
  } else {
    // Standard flow: GET the resource, expect 401 challenge or 200
    const url = new URL(args.url)
    if (args.scope) {
      url.searchParams.set('scope', args.scope)
    }

    onEvent?.({
      step: 'signed_request',
      phase: 'start',
      url: url.toString(),
      method: 'GET',
      agent_token: decodeSignatureJwt(keyMaterial),
    })
    const response = await signedFetch(url.toString(), { method: 'GET' })
    onEvent?.({
      step: 'signed_request',
      phase: 'done',
      status: response.status,
      response: { headers: summarizeResponseHeaders(response.headers) },
    })

    if (args.verbose) {
      console.error(JSON.stringify({ status: response.status, headers: headersToObject(response.headers) }))
    }

    if (response.status === 200) {
      const body = await response.text()
      console.log(JSON.stringify({
        signingKey: keyMaterial.signingKey,
        signatureKey: keyMaterial.signatureKey,
        response: { status: 200, body: tryParseJson(body) },
      }, null, 2))
      return
    }

    if (response.status !== 401) {
      const body = await response.text()
      console.error(JSON.stringify({ error: `Unexpected response status: ${response.status}`, body: tryParseJson(body) }))
      process.exitCode = 1
      return
    }

    const aauthHeader = response.headers.get('aauth-requirement')
    if (!aauthHeader) {
      console.error(JSON.stringify({ error: '401 response without AAuth-Requirement header' }))
      process.exitCode = 1
      return
    }

    const challenge = parseAAuthHeader(aauthHeader)
    if (challenge.requirement !== 'auth-token' || !challenge.resourceToken) {
      console.error(JSON.stringify({ error: `Unexpected challenge requirement: ${challenge.requirement}` }))
      process.exitCode = 1
      return
    }

    onEvent?.({
      step: 'challenge_received',
      phase: 'info',
      requirement: challenge.requirement,
      resourceToken: decodeJwtPayload(challenge.resourceToken),
    })
    resourceToken = challenge.resourceToken
  }

  // Exchange resource token for auth token at person server
  if (!personServer) {
    console.error(JSON.stringify({ error: 'Person server URL required for token exchange. Set in config or use --person-server.' }))
    process.exitCode = 1
    return
  }

  const result = await exchangeToken({
    signedFetch,
    authServerUrl: personServer,
    resourceToken,
    justification: args.justification,
    loginHint: args.loginHint,
    tenant: args.tenant,
    domainHint: args.domainHint,
    capabilities: (capabilities as string[]) ?? ['interaction'],
    prompt: args.forceConsent ? 'consent' : undefined,
    onEvent,
    getKeyMaterial: pinnedGetKeyMaterial,
    onInteraction: (interactionEndpoint, code) => {
      if (args.nonInteractive) {
        throw new Error(`Consent required but --non-interactive set. URL: ${interactionEndpoint}?code=${code}`)
      }
      const interactionUrl = `${interactionEndpoint}?code=${code}`
      if (!onEvent) {
        console.error(`Open ${interactionUrl} in your browser to approve (code: ${code}).`)
      }
      // With --log: consent_prompt event already carries this info
      if (shouldOpenBrowser) {
        open(interactionUrl)
      }
    },
  })

  log?.finish()
  console.log(JSON.stringify({
    authToken: result.authToken,
    expiresIn: result.expiresIn,
    signingKey: keyMaterial.signingKey,
    response: { status: 200 },
  }, null, 2))
}

/**
 * Pre-authed mode: use provided auth token + signing key.
 */
export async function handlePreAuthed(
  args: { url: string; method: string; authToken: string; signingKey: string; verbose: boolean; log?: boolean; jsonl?: boolean; data?: string; headers: string[] },
  init: RequestInit,
): Promise<void> {
  let signingKey: JsonWebKey
  try {
    signingKey = JSON.parse(args.signingKey!) as JsonWebKey
  } catch {
    console.error(JSON.stringify({ error: 'Invalid --signing-key: must be valid JSON (JWK)' }))
    process.exitCode = 1
    return
  }

  const log = buildLogEmitter(pickLogMode(args), { url: args.url })
  const onEvent: OnEvent | undefined = log?.onEvent
  const getKeyMaterial: GetKeyMaterial = async () => ({
    signingKey,
    signatureKey: { type: 'jwt' as const, jwt: args.authToken! },
  })

  const signedFetch = createSignedFetch(getKeyMaterial)

  onEvent?.({
    step: 'signed_request',
    phase: 'start',
    url: args.url,
    method: (init.method as string) ?? 'GET',
    auth_token: decodeJwtPayload(args.authToken),
  })
  const response = await signedFetch(args.url!, init)
  onEvent?.({
    step: 'signed_request',
    phase: 'done',
    status: response.status,
    response: { headers: summarizeResponseHeaders(response.headers) },
  })

  log?.finish()
  await outputResponse(response, args.verbose)
}

/**
 * --agent-only mode: sign with agent token, don't handle 401.
 */
export async function handleAgentOnly(
  args: { url: string; verbose: boolean; log?: boolean; jsonl?: boolean },
  init: RequestInit,
  getKeyMaterial: GetKeyMaterial,
): Promise<void> {
  const log = buildLogEmitter(pickLogMode(args), { url: args.url })
  const onEvent: OnEvent | undefined = log?.onEvent
  const signedFetch = createSignedFetch(getKeyMaterial)

  if (onEvent) {
    const km = await getKeyMaterial()
    onEvent({
      step: 'signed_request',
      phase: 'start',
      url: args.url,
      method: (init.method as string) ?? 'GET',
      agent_token: decodeSignatureJwt(km),
    })
  }
  const response = await signedFetch(args.url!, init)
  onEvent?.({
    step: 'signed_request',
    phase: 'done',
    status: response.status,
    response: { headers: summarizeResponseHeaders(response.headers) },
  })

  log?.finish()
  await outputResponse(response, args.verbose)
}

/**
 * Default mode: full AAuth protocol flow.
 */
export async function handleFullFlow(
  args: {
    url: string; agentUrl?: string; browser?: boolean; nonInteractive: boolean; verbose: boolean; debug?: boolean; log?: boolean; jsonl?: boolean;
    loginHint?: string; domainHint?: string; tenant?: string; justification?: string;
    capabilities?: string[]; forceConsent?: boolean;
  },
  init: RequestInit,
  getKeyMaterial: GetKeyMaterial,
  personServer: string | undefined,
): Promise<void> {
  const shouldOpenBrowser = args.browser ?? true
  const log = buildLogEmitter(pickLogMode(args), { url: args.url, agentUrl: args.agentUrl, personServer })
  const onEvent: OnEvent | undefined = log?.onEvent

  // Pin key material so the same ephemeral key is used for the initial request,
  // token exchange, and retry. The resource token's agent_jkt must match.
  const keyMaterial = await getKeyMaterial()
  if (args.debug) {
    logKeyMaterial('fullFlow', keyMaterial)
  }
  const pinnedGetKeyMaterial: GetKeyMaterial = async () => keyMaterial

  const aAuthFetch = createAAuthFetch({
    getKeyMaterial: pinnedGetKeyMaterial,
    authServerUrl: personServer,
    justification: args.justification,
    loginHint: args.loginHint,
    tenant: args.tenant,
    domainHint: args.domainHint,
    capabilities: (args.capabilities as Capability[]) ?? (args.nonInteractive ? [] : ['interaction']),
    prompt: args.forceConsent ? 'consent' : undefined,
    onEvent,
    onInteraction: (interactionEndpoint, code) => {
      if (args.nonInteractive) {
        throw new Error(`Consent required but --non-interactive set. URL: ${interactionEndpoint}?code=${code}`)
      }
      const url = `${interactionEndpoint}?code=${code}`
      if (!onEvent) {
        console.error(`Open ${url} in your browser to approve (code: ${code}).`)
      }
      // With --log: consent_prompt event already carries this info
      if (shouldOpenBrowser) {
        open(url)
      }
    },
  })

  const response = await aAuthFetch(args.url!, init)
  log?.finish()
  await outputResponse(response, args.verbose)
}

export async function outputResponse(response: Response, verbose: boolean): Promise<void> {
  if (verbose) {
    console.error(JSON.stringify({
      status: response.status,
      headers: headersToObject(response.headers),
    }))
  }

  const body = await response.text()
  const parsed = tryParseJson(body)
  if (parsed !== undefined) {
    console.log(JSON.stringify(parsed, null, 2))
  } else {
    console.log(body)
  }
}

function logKeyMaterial(context: string, km: KeyMaterial): void {
  // Decode agent token to get cnf.jwk
  const [, payloadB64] = km.signatureKey.type === 'jwt' ? km.signatureKey.jwt.split('.') : ['', '']
  let cnfJkt = 'unknown'
  let sub = 'unknown'
  if (payloadB64) {
    try {
      const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString())
      sub = payload.sub
      if (payload.cnf?.jwk) {
        const { kty, crv, x, y } = payload.cnf.jwk
        const input = kty === 'EC' ? { crv, kty, x, y } : { crv, kty, x }
        cnfJkt = createHash('sha256').update(JSON.stringify(input)).digest().toString('base64url')
      }
    } catch { /* ignore */ }
  }
  // Compute signing key thumbprint
  const { kty, crv, x, y } = km.signingKey as Record<string, string>
  const skInput = kty === 'EC' ? { crv, kty, x, y } : { crv, kty, x }
  const skJkt = createHash('sha256').update(JSON.stringify(skInput)).digest().toString('base64url')

  console.error(JSON.stringify({
    debug: 'keyMaterial',
    context,
    sub,
    signingKey_jkt: skJkt,
    agentToken_cnf_jkt: cnfJkt,
    match: skJkt === cnfJkt,
    signatureKeyType: km.signatureKey.type,
  }))
}

export function headersToObject(headers: Headers): Record<string, string> {
  const obj: Record<string, string> = {}
  headers.forEach((value, key) => { obj[key] = value })
  return obj
}

export function tryParseJson(text: string): unknown {
  try {
    return JSON.parse(text)
  } catch {
    return undefined
  }
}

