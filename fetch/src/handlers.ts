import {
  createAgentToken,
  readConfig,
  getAgentConfig,
  readCachedMetadata,
  writeCachedMetadata,
  evictCachedMetadata,
} from '@aauth/local-keys'
import {
  createAAuthFetch,
  createSignedFetch,
  parseAAuthHeader,
  exchangeToken,
  TokenExchangeError,
} from '@aauth/mcp-agent'
import type { GetKeyMaterial, Capability, OnEvent, CapturedSent, AuthServerMetadata } from '@aauth/mcp-agent'
import { createRequire } from 'node:module'
import open from 'open'
import { makeVerboseRenderer, prettyJson } from './render.js'

// qrcode-terminal is CommonJS — load it via require to get module.exports reliably.
const require = createRequire(import.meta.url)
type QrModule = { generate: (input: string, opts: { small?: boolean }, cb: (out: string) => void) => void }

const STDOUT_TTY = process.stdout.isTTY === true
const STDERR_TTY = process.stderr.isTTY === true

/** Build the `-v` event renderer (pretty JSON events → stderr), or undefined. */
function verboseRenderer(verbose: boolean): OnEvent | undefined {
  if (!verbose) return undefined
  return makeVerboseRenderer((line) => process.stderr.write(line + '\n'), STDERR_TTY)
}

/** Response headers surfaced in `-v` — the AAuth-relevant set. */
const AAUTH_RESPONSE_HEADERS = ['www-authenticate', 'aauth-requirement', 'aauth-access', 'content-type', 'location']
function respHeaders(headers: Headers): Record<string, string> {
  const out: Record<string, string> = {}
  for (const k of AAUTH_RESPONSE_HEADERS) {
    const v = headers.get(k)
    if (v) out[k] = v
  }
  return out
}

export function resolvePersonServer(agentProvider: string | undefined, override: string | undefined): string | undefined {
  if (override) return override
  if (!agentProvider) {
    const config = readConfig()
    const providers = Object.entries(config.agents)
    if (providers.length === 1) return providers[0][1].personServerUrl
    return undefined
  }
  return getAgentConfig(agentProvider)?.personServerUrl
}

/** Cache-key host for a resolved person-server URL, or undefined if unusable. */
function personServerHost(personServer: string | undefined): string | undefined {
  if (!personServer) return undefined
  try { return new URL(personServer).hostname } catch { return undefined }
}

/**
 * Cached PS metadata (keyed by person-server host) so the token exchange can skip
 * the runtime /.well-known/aauth-person.json fetch. Saved at bootstrap and
 * refreshed by {@link savePersonServerMetadata}. Returns undefined when nothing's
 * cached or the cached entry has expired.
 */
export function resolvePersonServerMetadata(
  personServer: string | undefined,
): AuthServerMetadata | undefined {
  const host = personServerHost(personServer)
  if (!host) return undefined
  return (readCachedMetadata(host) as AuthServerMetadata | null) ?? undefined
}

/**
 * Persist freshly-fetched PS metadata to the on-disk cache (keyed by PS host) so
 * the next call skips the fetch. This is the token exchange's onMetadata
 * callback; no Cache-Control is available here, so the cache applies its default
 * TTL. No-op when the PS host can't be derived.
 */
export function savePersonServerMetadata(
  personServer: string | undefined,
  metadata: AuthServerMetadata,
): void {
  const host = personServerHost(personServer)
  if (!host) return
  writeCachedMetadata(host, metadata)
}

/**
 * A failure that suggests the cached PS endpoint is stale (moved or gone): a
 * 404/410 from the token endpoint, or a network/DNS error reaching it. NOT a 401
 * (the normal auth-token challenge) or a 5xx (transient server error).
 */
function isStaleEndpointError(err: unknown): boolean {
  if (err instanceof TokenExchangeError) return err.status === 404 || err.status === 410
  // fetch() rejects with a TypeError on DNS/connection failures.
  return err instanceof TypeError
}

/**
 * Run a metadata-dependent flow, self-healing a stale PS-metadata cache. If the
 * call fails because the cached endpoint is gone (see {@link isStaleEndpointError})
 * AND we were using cached metadata, evict it and retry ONCE with no cached
 * metadata — which forces a fresh /.well-known fetch and re-save. Bounded to a
 * single retry, so it never loops; all other errors propagate unchanged.
 */
export async function runWithMetadataSelfHeal(
  personServer: string | undefined,
  cachedMetadata: AuthServerMetadata | undefined,
  run: (metadata: AuthServerMetadata | undefined) => Promise<void>,
): Promise<void> {
  try {
    await run(cachedMetadata)
  } catch (err) {
    if (!cachedMetadata || !isStaleEndpointError(err)) throw err
    const host = personServerHost(personServer)
    if (host) evictCachedMetadata(host)
    await run(undefined)
  }
}

export function buildGetKeyMaterial(args: { agentProvider?: string; local?: string }): GetKeyMaterial {
  return () => createAgentToken({ agentUrl: args.agentProvider, local: args.local })
}

export function buildRequestInit(args: { method: string; data?: string; headers: string[] }): RequestInit {
  const headers = new Headers()
  for (const h of args.headers) {
    const colon = h.indexOf(':')
    if (colon === -1) continue
    headers.set(h.slice(0, colon).trim(), h.slice(colon + 1).trim())
  }
  if (args.data && !headers.has('content-type')) headers.set('content-type', 'application/json')

  const init: RequestInit = { method: args.method, headers }
  if (args.data) init.body = args.data
  return init
}

// === output ===

/** Print the resource response on stdout: pretty JSON when JSON, raw otherwise. */
export async function outputResponse(response: Response): Promise<void> {
  const body = await response.text()
  const parsed = tryParseJson(body)
  if (parsed !== undefined) {
    console.log(prettyJson(parsed, STDOUT_TTY))
  } else {
    console.log(body)
  }
}

function printResult(value: unknown): void {
  console.log(prettyJson(value, STDOUT_TTY))
}

function fail(message: string, extra?: Record<string, unknown>): void {
  console.error(JSON.stringify(extra ? { error: message, ...extra } : { error: message }))
  process.exitCode = 1
}

// === interaction (consent) ===

function makeOnInteraction(args: { browser?: boolean; nonInteractive: boolean; verbose: boolean }) {
  const shouldOpenBrowser = args.browser ?? true
  return (interactionEndpoint: string, code: string) => {
    const url = `${interactionEndpoint}?code=${code}`
    if (args.nonInteractive) {
      throw new Error(`Consent required but --non-interactive set. URL: ${url}`)
    }
    if (shouldOpenBrowser) {
      if (!args.verbose) process.stderr.write(`Opening ${url} to approve (code: ${code}).\n`)
      open(url)
      return
    }
    // --no-browser: surface the URL and a scannable QR (open the link, or scan it).
    process.stderr.write(`Approve at: ${url}\n`)
    const qrcode = require('qrcode-terminal') as QrModule
    qrcode.generate(url, { small: true }, (qr) => process.stderr.write(`${qr}\n`))
  }
}

// === authorize ===

/**
 * `authorize`: drive the auth flow and return { auth_token, signingKey } for
 * reuse. With --operations, uses the R3 authorize endpoint; otherwise the 401
 * challenge flow.
 */
export async function handleAuthorize(
  args: {
    url: string; agentProvider?: string; operations?: string; scope?: string;
    browser?: boolean; nonInteractive: boolean; verbose: boolean;
    loginHint?: string; domainHint?: string; tenant?: string; justification?: string;
    capabilities?: string[];
  },
  getKeyMaterial: GetKeyMaterial,
  personServer: string | undefined,
  personServerMetadata?: AuthServerMetadata,
  onMetadata?: (m: AuthServerMetadata) => void,
): Promise<void> {
  const onEvent = verboseRenderer(args.verbose)
  const capabilities = args.capabilities as Capability[] | undefined

  const keyMaterial = await getKeyMaterial()
  const pinnedGetKeyMaterial: GetKeyMaterial = async () => keyMaterial
  const sent: { latest?: CapturedSent } = {}
  const signedFetch = createSignedFetch(pinnedGetKeyMaterial, {
    capabilities,
    ...(onEvent ? { onSigned: (s: CapturedSent) => { sent.latest = s } } : {}),
  })

  let resourceToken: string | undefined

  if (args.operations) {
    const operationIds = args.operations.split(',').map(s => s.trim())
    const r3Body = {
      r3_operations: {
        vocabulary: 'urn:aauth:vocabulary:openapi',
        operations: operationIds.map(id => ({ operationId: id })),
      },
    }
    onEvent?.({ step: 'r3_authorize_request', phase: 'start', url: args.url, method: 'POST' })
    const response = await signedFetch(args.url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(r3Body),
    })
    onEvent?.({ step: 'r3_authorize_request', phase: 'done', status: response.status, request_headers: sent.latest?.headers, response: { headers: respHeaders(response.headers) } })
    if (response.status !== 200) {
      const b = await response.text()
      return fail(`Authorize endpoint returned status ${response.status}`, { body: tryParseJson(b) })
    }
    const respBody = await response.json() as Record<string, unknown>
    resourceToken = respBody.resource_token as string
    if (!resourceToken) return fail('Authorize response missing resource_token')
  } else {
    const url = new URL(args.url)
    if (args.scope) url.searchParams.set('scope', args.scope)
    onEvent?.({ step: 'signed_request', phase: 'start', url: url.toString(), method: 'GET' })
    const response = await signedFetch(url.toString(), { method: 'GET' })
    onEvent?.({ step: 'signed_request', phase: 'done', status: response.status, request_headers: sent.latest?.headers, response: { headers: respHeaders(response.headers) } })

    if (response.status === 200) {
      const b = await response.text()
      // Two-party: the resource may hand back an opaque AAuth-Access token to
      // reuse (via --opaque-token) on subsequent calls.
      const opaqueToken = response.headers.get('aauth-access') ?? undefined
      return printResult({
        ...(opaqueToken ? { opaque_token: opaqueToken } : {}),
        signingKey: keyMaterial.signingKey,
        signatureKey: keyMaterial.signatureKey,
        response: { status: 200, body: tryParseJson(b) },
      })
    }
    if (response.status !== 401) {
      const b = await response.text()
      return fail(`Unexpected response status: ${response.status}`, { body: tryParseJson(b) })
    }
    const aauthHeader = response.headers.get('aauth-requirement')
    if (!aauthHeader) return fail('401 response without AAuth-Requirement header')
    const challenge = parseAAuthHeader(aauthHeader)
    if (challenge.requirement !== 'auth-token' || !challenge.resourceToken) {
      return fail(`Unexpected challenge requirement: ${challenge.requirement}`)
    }
    onEvent?.({ step: 'challenge_received', phase: 'info', requirement: challenge.requirement })
    resourceToken = challenge.resourceToken
  }

  if (!personServer) {
    return fail('Person server URL required for token exchange. Set in config or use --person-server.')
  }

  const result = await exchangeToken({
    signedFetch,
    authServerUrl: personServer,
    authServerMetadata: personServerMetadata,
    onMetadata,
    resourceToken,
    justification: args.justification,
    loginHint: args.loginHint,
    tenant: args.tenant,
    domainHint: args.domainHint,
    capabilities: (capabilities as string[]) ?? ['interaction'],
    onEvent,
    getKeyMaterial: pinnedGetKeyMaterial,
    onInteraction: makeOnInteraction(args),
    sentTracker: sent,
  })

  printResult({
    auth_token: result.authToken,
    expires_in: result.expiresIn,
    signingKey: keyMaterial.signingKey,
    response: { status: 200 },
  })
}

// === pre-authed ===

export async function handlePreAuthed(
  args: { url: string; authToken: string; signingKey: string; verbose: boolean },
  init: RequestInit,
): Promise<void> {
  let signingKey: JsonWebKey
  try {
    signingKey = JSON.parse(args.signingKey) as JsonWebKey
  } catch {
    return fail('Invalid --signing-key: must be valid JSON (JWK)')
  }
  const onEvent = verboseRenderer(args.verbose)
  const getKeyMaterial: GetKeyMaterial = async () => ({
    signingKey,
    signatureKey: { type: 'jwt' as const, jwt: args.authToken },
  })
  const sent: { latest?: CapturedSent } = {}
  const signedFetch = createSignedFetch(getKeyMaterial, onEvent ? { onSigned: (s) => { sent.latest = s } } : undefined)
  // Carries the auth token, not the agent token — emit the auth-token step.
  onEvent?.({ step: 'auth_token_request', phase: 'start', url: args.url, method: (init.method as string) ?? 'GET' })
  const response = await signedFetch(args.url, init)
  onEvent?.({ step: 'auth_token_request', phase: 'done', status: response.status, request_headers: sent.latest?.headers, response: { headers: respHeaders(response.headers) } })
  await outputResponse(response)
}

// === agent-only ===

export async function handleAgentOnly(
  args: { url: string; verbose: boolean },
  init: RequestInit,
  getKeyMaterial: GetKeyMaterial,
): Promise<void> {
  const onEvent = verboseRenderer(args.verbose)
  const sent: { latest?: CapturedSent } = {}
  const signedFetch = createSignedFetch(getKeyMaterial, onEvent ? { onSigned: (s) => { sent.latest = s } } : undefined)
  onEvent?.({ step: 'signed_request', phase: 'start', url: args.url, method: (init.method as string) ?? 'GET' })
  const response = await signedFetch(args.url, init)
  onEvent?.({ step: 'signed_request', phase: 'done', status: response.status, request_headers: sent.latest?.headers, response: { headers: respHeaders(response.headers) } })
  await outputResponse(response)
}

// === default full flow ===

export async function handleFullFlow(
  args: {
    url: string; agentProvider?: string; browser?: boolean; nonInteractive: boolean; verbose: boolean;
    loginHint?: string; domainHint?: string; tenant?: string; justification?: string;
    capabilities?: string[]; withToken?: boolean; opaqueToken?: string;
  },
  init: RequestInit,
  getKeyMaterial: GetKeyMaterial,
  personServer: string | undefined,
  personServerMetadata?: AuthServerMetadata,
  onMetadata?: (m: AuthServerMetadata) => void,
): Promise<void> {
  const onEvent = verboseRenderer(args.verbose)
  const keyMaterial = await getKeyMaterial()
  const pinnedGetKeyMaterial: GetKeyMaterial = async () => keyMaterial

  // --with-token: capture the credentials surfaced during the flow so we can
  // return them (alongside the response) for reuse — the three-party auth token,
  // and/or a two-party opaque AAuth-Access token.
  let minted: { authToken: string; expiresIn: number } | undefined
  let opaqueToken: string | undefined = args.opaqueToken

  const aAuthFetch = createAAuthFetch({
    getKeyMaterial: pinnedGetKeyMaterial,
    authServerUrl: personServer,
    authServerMetadata: personServerMetadata,
    onMetadata,
    // --opaque-token: reuse a previously-issued opaque token on this call.
    opaqueToken: args.opaqueToken,
    onAuthToken: args.withToken
      ? (authToken, expiresIn) => { minted = { authToken, expiresIn } }
      : undefined,
    onOpaqueToken: args.withToken
      ? (token) => { opaqueToken = token }
      : undefined,
    justification: args.justification,
    loginHint: args.loginHint,
    tenant: args.tenant,
    domainHint: args.domainHint,
    capabilities: (args.capabilities as Capability[]) ?? (args.nonInteractive ? [] : ['interaction']),
    onEvent,
    onInteraction: makeOnInteraction(args),
  })

  const response = await aAuthFetch(args.url, init)

  if (args.withToken) {
    // Combined object: the reusable credential(s) + the resource response in one
    // call. auth_token/expires_in appear only when an auth token was minted (the
    // resource issued a three-party challenge); opaque_token appears in two-party
    // mode; an agent-token-only 200 has neither.
    const body = await response.text()
    const parsed = tryParseJson(body)
    printResult({
      ...(minted ? { auth_token: minted.authToken, expires_in: minted.expiresIn } : {}),
      ...(opaqueToken ? { opaque_token: opaqueToken } : {}),
      signingKey: keyMaterial.signingKey,
      response: { status: response.status, body: parsed === undefined ? body : parsed },
    })
    return
  }

  await outputResponse(response)
}

export function tryParseJson(text: string): unknown {
  try { return JSON.parse(text) } catch { return undefined }
}
