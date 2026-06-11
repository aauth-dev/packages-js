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
import { mkdirSync, openSync, writeSync, closeSync } from 'node:fs'
import { homedir } from 'node:os'
import { join, dirname } from 'node:path'
import open from 'open'
import { makeExplainRenderer, makeDebugRenderer, prettyJson, qrAscii } from './render.js'
import { promptValue } from './args.js'

const STDOUT_TTY = process.stdout.isTTY === true
const STDERR_TTY = process.stderr.isTTY === true

/**
 * JSONL sink for `--explain` events: when set, each event object is serialized
 * compactly (one JSON object per line) and appended to
 * `~/.aauth/fetch/logs/<ISO-timestamp>.jsonl`. Lets agentic renderers (and humans)
 * read the event stream from a stable file path instead of capturing stderr —
 * which would otherwise trigger permission prompts when the capture file lands
 * somewhere like /tmp/.
 *
 * The log holds ONLY event JSONL: no QR ASCII, no prose lines, no startup
 * banner. Anything that would render as plain text (the consent prompt's
 * scannable QR, "Approve at: …") goes to stderr only.
 *
 * Initialised by {@link initExplainLog} at CLI startup; remains undefined if the
 * caller didn't pass --explain, or if the log directory couldn't be created
 * (don't fail the fetch because a side-channel log can't open).
 */
let logWriter: ((obj: Record<string, unknown>) => void) | undefined

/**
 * Set up the `--explain` log file. When `enabled`, opens `path` (from
 * `--explain-log`, parent dirs created) — or, by default, creates
 * `~/.aauth/fetch/logs/` if missing and opens
 * `~/.aauth/fetch/logs/<ISO-timestamp>.jsonl` for appending. Stores a JSONL
 * writer in {@link logWriter} so the event renderer can serialize each event
 * object as one compact line.
 *
 * Best-effort: any filesystem error (no home, read-only FS) leaves the writer
 * undefined and the fetch proceeds with stderr-only output.
 *
 * Returns the resolved log path so the CLI can print it once for the user.
 */
export function initExplainLog(enabled: boolean, path?: string): string | undefined {
  if (!enabled) return undefined
  try {
    let file: string
    if (path) {
      mkdirSync(dirname(path), { recursive: true })
      file = path
    } else {
      const dir = join(homedir(), '.aauth', 'fetch', 'logs')
      mkdirSync(dir, { recursive: true })
      // Filesystem-safe timestamp: ISO with colons replaced (Windows compat) and
      // sub-second precision dropped (collisions within the same second on a
      // single invocation are not a concern — one process opens one file).
      const stamp = new Date().toISOString().replace(/[:.]/g, '-').replace(/-\d{3}Z$/, 'Z')
      // .jsonl — the file is one compact JSON object per line, nothing else.
      file = join(dir, `${stamp}.jsonl`)
    }
    const fd = openSync(file, 'a')
    logWriter = (obj: Record<string, unknown>) => {
      try { writeSync(fd, JSON.stringify(obj) + '\n') } catch { /* best-effort */ }
    }
    process.on('exit', () => { try { closeSync(fd) } catch { /* best-effort */ } })
    return file
  } catch {
    logWriter = undefined
    return undefined
  }
}

/**
 * Build the event renderer for the active output mode. Each event object is
 * fanned out to two sinks:
 *   - stderr: pretty-printed JSON (colorized at a TTY) for direct human use.
 *   - log file (when --explain is set): one compact JSON object per line (JSONL)
 *     for agentic consumers.
 *
 *   --explain → teaching view (per-step request/response + descriptions + bodies)
 *   --debug / -v / --verbose → raw view (every hop's request/response + bodies)
 * Returns undefined when neither is set.
 */
function eventRenderer(args: { explain?: boolean; debug?: boolean }): OnEvent | undefined {
  const emit = (obj: Record<string, unknown>) => {
    // At a TTY: pretty-printed + colorized for direct human reading. Piped or
    // captured (agent task output, CI log): one compact JSON object per line,
    // so the captured stream is itself parseable JSONL — same shape as the log
    // file, no separate file discovery needed.
    process.stderr.write(STDERR_TTY ? prettyJson(obj, true) + '\n' : JSON.stringify(obj) + '\n')
    logWriter?.(obj)
  }
  if (args.explain) return makeExplainRenderer(emit)
  if (args.debug) return makeDebugRenderer(emit)
  return undefined
}

/** Response headers surfaced in --explain/--debug — the AAuth-relevant set. */
const AAUTH_RESPONSE_HEADERS = ['www-authenticate', 'aauth-requirement', 'aauth-access', 'content-type', 'location']
function respHeaders(headers: Headers): Record<string, string> {
  const out: Record<string, string> = {}
  for (const k of AAUTH_RESPONSE_HEADERS) {
    const v = headers.get(k)
    if (v) out[k] = v
  }
  return out
}

/** Read a response body without consuming it (for --explain/--debug events). */
async function peekBodyText(response: Response): Promise<string | undefined> {
  try { return await response.clone().text() } catch { return undefined }
}

/**
 * Build a :done event's `response` payload — AAuth-relevant headers plus the raw
 * body string (renderers parse it for display). The body is peeked via clone(),
 * so the caller can still read the response afterwards.
 */
async function doneResponse(response: Response): Promise<{ headers: Record<string, string>; body?: string }> {
  const body = await peekBodyText(response)
  const out: { headers: Record<string, string>; body?: string } = { headers: respHeaders(response.headers) }
  if (body !== undefined) out.body = body
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

function makeOnInteraction(args: { browser?: boolean; nonInteractive: boolean; explain?: boolean; debug?: boolean }) {
  // Default: don't assume a browser exists (agents, CI, containers, SSH-to-headless
  // all have a TTY but no GUI). Print the URL + a scannable QR instead. --browser
  // opts into auto-open on a machine that actually has a browser.
  const shouldOpenBrowser = args.browser === true
  // When an event renderer is active it already surfaces the approval URL (and
  // QR) inside the interaction_required event, so skip the plain one-liner.
  const quiet = args.explain || args.debug
  return (interactionEndpoint: string, code: string) => {
    const url = `${interactionEndpoint}?code=${code}`
    if (args.nonInteractive) {
      throw new Error(`Consent required but --non-interactive set. URL: ${url}`)
    }
    if (shouldOpenBrowser) {
      if (!quiet) process.stderr.write(`Opening ${url} to approve (code: ${code}).\n`)
      open(url)
      return
    }
    // Default: surface the URL and a scannable QR on stderr for the human. The
    // --explain log file never sees these — the event JSON already carries
    // them in the interaction_required event (`approval_url`, `qr`). When a
    // renderer is active AND stderr is captured (not a TTY), skip the plain
    // text too: the consumer is parsing JSONL, and prose lines would corrupt
    // the stream.
    if (quiet && !STDERR_TTY) return
    process.stderr.write(`Approve at: ${url}\n`)
    const qr = qrAscii(url)
    if (qr) process.stderr.write(`${qr}\n`)
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
    browser?: boolean; nonInteractive: boolean; explain: boolean; debug: boolean;
    loginHint?: string; domainHint?: string; tenant?: string; justification?: string;
    promptLogin?: boolean; promptConsent?: boolean;
  },
  getKeyMaterial: GetKeyMaterial,
  personServer: string | undefined,
  personServerMetadata?: AuthServerMetadata,
  onMetadata?: (m: AuthServerMetadata) => void,
): Promise<void> {
  const onEvent = eventRenderer(args)
  // We support exactly one capability: interaction — declared unless the caller
  // opted out with --non-interactive. (No payment; clarification isn't wired here.)
  const capabilities: Capability[] = args.nonInteractive ? [] : ['interaction']

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
    if (onEvent) onEvent({ step: 'r3_authorize_request', phase: 'done', status: response.status, request_headers: sent.latest?.headers, request_body: sent.latest?.body, response: await doneResponse(response) })
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
    if (onEvent) onEvent({ step: 'signed_request', phase: 'done', status: response.status, request_headers: sent.latest?.headers, request_body: sent.latest?.body, response: await doneResponse(response) })

    if (response.status === 200) {
      const b = await response.text()
      const parsed = tryParseJson(b)
      // Two-party: the resource may hand back an AAuth-Access token to
      // reuse (via --aauth-access-token) on subsequent calls.
      const opaqueToken = response.headers.get('aauth-access') ?? undefined
      if (opaqueToken) {
        // Two-party reuse needs only the opaque token (binds per-request to the
        // agent identity); no signing key to carry.
        return printResult({
          aauth_access_token: opaqueToken,
          response: parsed === undefined ? b : parsed,
        })
      }
      // Agent-token-only 200: surface the agent token + its ephemeral signing key
      // so the caller can reuse them on the next call without re-minting.
      return printResult({
        signingKey: keyMaterial.signingKey,
        signatureKey: keyMaterial.signatureKey,
        response: parsed === undefined ? b : parsed,
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
    prompt: promptValue(args),
    capabilities: capabilities as string[],
    onEvent,
    getKeyMaterial: pinnedGetKeyMaterial,
    onInteraction: makeOnInteraction(args),
    sentTracker: sent,
  })

  // No final resource call in this path — just the reusable credential.
  printResult({
    auth_token: result.authToken,
    expires_in: result.expiresIn,
    signingKey: keyMaterial.signingKey,
  })
}

// === pre-authed ===

export async function handlePreAuthed(
  args: { url: string; authToken: string; signingKey: string; explain: boolean; debug: boolean },
  init: RequestInit,
): Promise<void> {
  let signingKey: JsonWebKey
  try {
    signingKey = JSON.parse(args.signingKey) as JsonWebKey
  } catch {
    return fail('Invalid --signing-key: must be valid JSON (JWK)')
  }
  const onEvent = eventRenderer(args)
  const getKeyMaterial: GetKeyMaterial = async () => ({
    signingKey,
    signatureKey: { type: 'jwt' as const, jwt: args.authToken },
  })
  const sent: { latest?: CapturedSent } = {}
  const signedFetch = createSignedFetch(getKeyMaterial, onEvent ? { onSigned: (s) => { sent.latest = s } } : undefined)
  // Carries the auth token, not the agent token — emit the auth-token step.
  onEvent?.({ step: 'auth_token_request', phase: 'start', url: args.url, method: (init.method as string) ?? 'GET' })
  const response = await signedFetch(args.url, init)
  if (onEvent) onEvent({ step: 'auth_token_request', phase: 'done', status: response.status, request_headers: sent.latest?.headers, request_body: sent.latest?.body, response: await doneResponse(response) })
  await outputResponse(response)
}

// === agent-only ===

export async function handleAgentOnly(
  args: { url: string; explain: boolean; debug: boolean },
  init: RequestInit,
  getKeyMaterial: GetKeyMaterial,
): Promise<void> {
  const onEvent = eventRenderer(args)
  const sent: { latest?: CapturedSent } = {}
  const signedFetch = createSignedFetch(getKeyMaterial, onEvent ? { onSigned: (s) => { sent.latest = s } } : undefined)
  onEvent?.({ step: 'signed_request', phase: 'start', url: args.url, method: (init.method as string) ?? 'GET' })
  const response = await signedFetch(args.url, init)
  if (onEvent) onEvent({ step: 'signed_request', phase: 'done', status: response.status, request_headers: sent.latest?.headers, request_body: sent.latest?.body, response: await doneResponse(response) })
  await outputResponse(response)
}

// === default full flow ===

export async function handleFullFlow(
  args: {
    url: string; agentProvider?: string; browser?: boolean; nonInteractive: boolean; explain: boolean; debug: boolean;
    loginHint?: string; domainHint?: string; tenant?: string; justification?: string;
    promptLogin?: boolean; promptConsent?: boolean;
    emit?: boolean; opaqueToken?: string;
  },
  init: RequestInit,
  getKeyMaterial: GetKeyMaterial,
  personServer: string | undefined,
  personServerMetadata?: AuthServerMetadata,
  onMetadata?: (m: AuthServerMetadata) => void,
): Promise<void> {
  const onEvent = eventRenderer(args)
  const keyMaterial = await getKeyMaterial()
  const pinnedGetKeyMaterial: GetKeyMaterial = async () => keyMaterial

  // --emit: capture the credentials surfaced during the flow so we can
  // emit them (alongside the response) for reuse — the three-party auth token,
  // and/or a two-party AAuth-Access token.
  let minted: { authToken: string; expiresIn: number } | undefined
  let opaqueToken: string | undefined = args.opaqueToken

  const aAuthFetch = createAAuthFetch({
    getKeyMaterial: pinnedGetKeyMaterial,
    authServerUrl: personServer,
    authServerMetadata: personServerMetadata,
    onMetadata,
    // --aauth-access-token: reuse a previously-issued AAuth-Access token on this call.
    opaqueToken: args.opaqueToken,
    onAuthToken: args.emit
      ? (authToken, expiresIn) => { minted = { authToken, expiresIn } }
      : undefined,
    onOpaqueToken: args.emit
      ? (token) => { opaqueToken = token }
      : undefined,
    justification: args.justification,
    loginHint: args.loginHint,
    tenant: args.tenant,
    domainHint: args.domainHint,
    prompt: promptValue(args),
    capabilities: args.nonInteractive ? [] : ['interaction'],
    onEvent,
    onInteraction: makeOnInteraction(args),
  })

  const response = await aAuthFetch(args.url, init)

  if (args.emit) {
    // Combined object: the reusable credential(s) + the resource response in one
    // call. `response` is the body directly (same shape as bare fetch). Fields
    // appear only when relevant:
    //   - auth_token/expires_in: only when an auth token was minted (three-party).
    //   - aauth_access_token: only in two-party mode.
    //   - signingKey: only with auth_token (cnf-bound — required for three-party
    //     reuse). Two-party reuse needs only the aauth_access_token (binds per-request
    //     to the agent identity), so no signingKey is emitted there.
    const body = await response.text()
    const parsed = tryParseJson(body)
    printResult({
      ...(minted ? { auth_token: minted.authToken, expires_in: minted.expiresIn } : {}),
      ...(opaqueToken ? { aauth_access_token: opaqueToken } : {}),
      ...(minted ? { signingKey: keyMaterial.signingKey } : {}),
      response: parsed === undefined ? body : parsed,
    })
    return
  }

  await outputResponse(response)
}

export function tryParseJson(text: string): unknown {
  try { return JSON.parse(text) } catch { return undefined }
}
