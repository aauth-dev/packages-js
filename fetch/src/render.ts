import { createRequire } from 'node:module'
import type { AAuthEvent, OnEvent } from '@aauth/mcp-agent'

/** A JWK / arbitrary JSON value — only passed through to output. */
type Json = unknown

// qrcode-terminal is CommonJS — load it via require to get module.exports reliably.
const require = createRequire(import.meta.url)
type QrModule = { generate: (input: string, opts: { small?: boolean }, cb: (out: string) => void) => void }

/**
 * Render `url` as a small ASCII QR. qrcode-terminal's callback is sync in
 * practice, so we capture the result and return it. Returns an empty string on
 * any failure — a missing QR shouldn't break the event stream.
 */
export function qrAscii(url: string): string {
  try {
    const qrcode = require('qrcode-terminal') as QrModule
    let out = ''
    qrcode.generate(url, { small: true }, (qr) => { out = qr })
    return out
  } catch { return '' }
}

/**
 * Add ANSI syntax colors to a pretty-printed JSON string: keys blue, strings
 * green, numbers cyan, booleans/null yellow. Caller decides whether to apply it
 * (TTY only) — colors must never reach a pipe, or `jq` would choke.
 */
export function colorizeJson(json: string): string {
  const RESET = '\x1b[0m'
  return json.replace(
    /("(?:\\.|[^"\\])*")(\s*:)?|\b(true|false|null)\b|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/g,
    (match, str, colon, keyword, num) => {
      if (str !== undefined) {
        if (colon !== undefined) return `\x1b[34m${str}${RESET}${colon}` // key
        return `\x1b[32m${str}${RESET}` // string value
      }
      if (keyword !== undefined) return `\x1b[33m${keyword}${RESET}` // bool / null
      if (num !== undefined) return `\x1b[36m${num}${RESET}` // number
      return match
    },
  )
}

/** Pretty-print a value; colorize only at a TTY (caller passes the stream). */
export function prettyJson(value: Json, isTty: boolean): string {
  const json = JSON.stringify(value, null, 2)
  const useColor = isTty && !process.env.NO_COLOR
  return useColor ? colorizeJson(json) : json
}

// === verbose (-v) event rendering ===

/**
 * Presentation for each protocol step. The mcp-agent (and the fetch handlers)
 * emit internal step names; here we map them to the `step` shown in `-v` and the
 * `description` for each kind of event.
 *
 * Display names track the AAuth spec's vocabulary (#requirement-auth-token,
 * #ps-token-endpoint, #user-interaction). Both `req` and `res` may be a
 * function of status so the same internal step renders the right teaching
 * line for the branch the protocol actually took (e.g. `signed_request`
 * teaches identity-based access on 200, the auth-token dance on 401).
 *
 * - `display` — the step label shown to the user. Named by target + purpose, not
 *   "signed" (every request is signed). Two internal steps can share a display
 *   name when they're the same logical operation (e.g. the pre-authed
 *   auth_token_request and the retry_with_auth_token).
 * - `summary` — one-line gist of the whole exchange in `actor → target ·
 *   token → outcome` form. Emitted on the request (and some info) events so a
 *   renderer can lead each section with it; status-aware because the request
 *   event is emitted once the response is known.
 * - `req` / `info` — the description for a request / info event; may be a
 *   function of the response status.
 * - `res` — the description for a response; a function when it varies by status.
 *   Never the bare status code (that's already in `status`); it states what came
 *   back and what it sets up next. This is where the flow branch is taught
 *   (identity-based access vs. entering the three-party flow) — the response is
 *   the moment the branch becomes fact.
 */
interface StepSpec {
  display: string
  summary?: string | ((status?: number) => string)
  req?: string | ((status?: number) => string)
  info?: string
  res?: string | ((status?: number) => string)
}

/** True for a 2xx status (identity/authorized success branches). */
const ok = (s?: number): boolean => s !== undefined && s >= 200 && s < 300

const STEPS: Record<string, StepSpec> = {
  // The two resource calls are named by the token they carry (not by position):
  // the agent-token call may get a 401; the auth-token call is the authorized one.
  signed_request: {
    display: 'agent_token_request',
    summary: (s) =>
      s === 401
        ? 'agent → resource · agent-token → 401 + resource-token'
        : ok(s)
          ? `agent → resource · agent-token → ${s} (identity-based access)`
          : `agent → resource · agent-token → ${s ?? '…'}`,
    req: 'Call the resource with your agent token.',
    res: (s) =>
      s === 401
        ? 'The resource requires a person-issued auth token — this begins the three-party flow (agent ↔ person server ↔ resource). The `AAuth-Requirement` header carries a resource token: the agent presents it to the person server to get authorized.'
        : ok(s)
          ? 'Identity-based access: the resource accepted the signature alone as proof of the agent identity — no person server round-trip, no consent.'
          : "Received the resource's response.",
  },
  retry_with_auth_token: {
    display: 'auth_token_request',
    summary: (s) =>
      ok(s)
        ? `agent → resource · auth-token → ${s} + person claims`
        : `agent → resource · auth-token → ${s ?? '…'}`,
    req: 'Call the resource — `Signature-Key` now carries the person-issued auth token, not the agent token.',
    res: (s) =>
      ok(s)
        ? 'The resource verified the person-issued auth token — it now knows who is calling (`agent`) and on whose behalf (`sub`, plus claims the person server vouched for).'
        : "Received the resource's response.",
  },
  // Pre-authed reuse (--auth-token/--signing-key): also an auth-token call.
  auth_token_request: {
    display: 'auth_token_request',
    summary: (s) =>
      ok(s)
        ? `agent → resource · auth-token → ${s} + person claims`
        : `agent → resource · auth-token → ${s ?? '…'}`,
    req: 'Call the resource — `Signature-Key` carries a person-issued auth token.',
    res: (s) =>
      ok(s)
        ? 'The resource verified the person-issued auth token — it now knows who is calling (`agent`) and on whose behalf (`sub`, plus claims the person server vouched for).'
        : "Received the resource's response.",
  },
  r3_authorize_request: {
    display: 'authorize_request',
    summary: 'agent → resource · operations request (agent-token) → resource-token',
    req: "POST the requested operations to the resource's authorize endpoint, signed with your agent token.",
    res: 'Received a resource token scoped to those operations.',
  },
  challenge_received: {
    display: 'requirement_parsed',
    info: 'Parsed `AAuth-Requirement` — must exchange the resource token for an auth token at the person server.',
  },
  ps_metadata_request: {
    display: 'ps_metadata',
    summary: 'agent → person server · metadata discovery',
    req: "Fetch the person server's metadata at `/.well-known/aauth-person.json`.",
    res: "Received the person server's endpoints.",
  },
  ps_metadata_cached: {
    display: 'ps_metadata',
    info: 'Person server endpoints come from its `/.well-known/aauth-person.json` metadata — using a locally cached copy.',
  },
  ps_token_request: {
    display: 'ps_token_request',
    summary: (s) =>
      s === 202
        ? 'agent → person server · resource-token → 202 pending + approval code'
        : ok(s)
          ? `agent → person server · resource-token → ${s} + auth-token (consent on file)`
          : `agent → person server · resource-token → ${s ?? '…'}`,
    req: 'POST the resource token to the person server `token_endpoint` to mint an auth token. `Prefer: wait=45` long-polls — the server may hold the connection up to 45s before returning.',
    res: (s) =>
      s === 202
        ? 'User interaction required before the auth token is issued (`AAuth-Requirement: requirement=interaction`) — the person must approve in a browser; the agent polls the pending `location` until they do.'
        : 'Received the auth token — consent was already on file.',
  },
  interaction_required: {
    display: 'interaction_required',
    summary: 'person → person server · approve in browser',
    info: 'Direct the person to the approval URL — show them the QR or open the link.',
  },
  consent_poll: {
    display: 'consent_poll',
    // 202 = still pending; any other 2xx (the final 200) = approved.
    summary: (s) =>
      s === 202
        ? 'agent → person server · poll → 202 still pending'
        : ok(s)
          ? `agent → person server · poll → ${s} + auth-token (person approved)`
          : `agent → person server · poll → ${s ?? '…'}`,
    req: 'Poll the pending URL — checking whether the person has acted. `Prefer: wait=45` long-polls so the response returns immediately on consent rather than burning round-trips.',
    res: (s) =>
      s === 202
        ? 'Still pending — the person has not acted yet.'
        : ok(s)
          ? 'The person approved — the body carries the freshly issued auth token, bound (`cnf`) to the same ephemeral key the agent has been signing with.'
          : 'Received the polling response.',
  },
  consent_resolved: {
    display: 'consent_resolved',
    info: 'Polling terminated.',
  },
  auth_token_received: {
    display: 'auth_token_received',
    info: 'The person approved — auth token issued.',
  },
}

/** The step label shown in `-v` (mapped from the internal name). */
function displayStep(step: string): string {
  return STEPS[step]?.display ?? step
}

/** The one-line gist of a step's exchange (undefined for steps without one). */
function summarize(step: string, status?: number): string | undefined {
  const s = STEPS[step]?.summary
  if (typeof s === 'function') return s(status)
  return s
}

/** Description for an event, by its kind. Falls back gracefully for unknown steps. */
function describe(step: string, kind: 'request' | 'response' | 'info', status?: number): string {
  const spec = STEPS[step]
  if (kind === 'request') {
    const r = spec?.req
    if (typeof r === 'function') return r(status)
    if (typeof r === 'string') return r
    return `Request: ${displayStep(step)}.`
  }
  if (kind === 'info') return spec?.info ?? `${displayStep(step)}.`
  // response
  const r = spec?.res
  if (typeof r === 'function') return r(status)
  if (typeof r === 'string') return r
  return status ? `Response: ${status}.` : 'Response.'
}

/** Fields worth surfacing from an info event (besides type/step/description). */
function infoFields(e: AAuthEvent): Record<string, unknown> {
  const out: Record<string, unknown> = {}
  if (typeof e.requirement === 'string') out.requirement = e.requirement
  if (typeof e.interaction_url === 'string') out.interaction_url = e.interaction_url
  // interaction_required: surface the pieces (url, code), the assembled approval_url,
  // and a scannable QR — so a log-only consumer can render the CTA without
  // assembling anything itself or scraping stderr.
  const url = typeof e.url === 'string' ? e.url : undefined
  const code = typeof e.code === 'string' ? e.code : undefined
  if (url) out.url = url
  if (code) out.code = code
  if (e.step === 'interaction_required' && url && code) {
    const approvalUrl = `${url}?code=${code}`
    out.approval_url = approvalUrl
    const qr = qrAscii(approvalUrl)
    if (qr) out.qr = qr
  }
  return out
}

/**
 * Bodies travel through the event stream as strings (raw on-the-wire form). For
 * display, parse JSON bodies back into objects so they pretty-print; leave
 * non-JSON (or absent) bodies as-is.
 */
function bodyForDisplay(body: unknown): unknown {
  if (typeof body !== 'string') return body
  try { return JSON.parse(body) } catch { return body }
}

/** The request body carried on a :done event, parsed for display (or undefined). */
function requestBody(e: AAuthEvent): unknown {
  return e.request_body !== undefined ? bodyForDisplay(e.request_body) : undefined
}

/** The response body carried on a :done event, parsed for display (or undefined). */
function responseBody(e: AAuthEvent): unknown {
  const response = e.response as { body?: unknown } | undefined
  return response?.body !== undefined ? bodyForDisplay(response.body) : undefined
}

/**
 * `--explain`: the teaching view. Render each mcp-agent event as a pretty JSON
 * object on stderr, keyed by `step`:
 *   - phase 'start' is buffered (the real signed headers aren't known until the
 *     response arrives) and emitted as part of the request event once 'done' fires;
 *   - phase 'done' emits a request event `{ step, summary?, description?,
 *     request: { method, url, headers, body } }` then a response event
 *     `{ step, description?, response: { status, headers, body } }`;
 *   - phase 'info' emits `{ step, summary?, description?, ... }`.
 *
 * A response pairs with the immediately preceding request by `step`. The
 * request's `summary` is the one-line gist of the whole exchange (status-aware —
 * the request is emitted once the response is known); the response's
 * `description` teaches the branch the flow actually took. Each distinct
 * summary/description prints once per step — repeats (the consent_poll
 * heartbeat) carry only their payload. No top-level `type` field — presence of
 * `request` / `response` discriminates.
 */
// Info steps whose `description` is pure recap of the preceding response —
// emitting them adds prose between code blocks without new data. The next
// request's description already says "Signature-Key now carries the auth token,"
// which subsumes "the person approved" and "polling terminated."
const SUPPRESSED_INFO_STEPS = new Set(['auth_token_received', 'consent_resolved'])

export function makeExplainRenderer(emit: (obj: Record<string, unknown>) => void): OnEvent {
  const started = new Map<string, { method?: string; url?: string }>()
  // Track which (step, line) pairs we've already emitted so repeated events
  // (notably consent_poll's heartbeat) don't redundantly print the same
  // summary / teaching line over and over — each distinct line fires once, then
  // the request/response payloads alone tell the heartbeat story.
  const seen = new Set<string>()
  const out = (obj: Record<string, unknown>) => emit(obj)
  const once = (obj: Record<string, unknown>, field: 'summary' | 'description', key: string, text: string | undefined) => {
    if (!text || seen.has(key)) return
    obj[field] = text
    seen.add(key)
  }

  return (e: AAuthEvent) => {
    const step = e.step
    if (e.phase === 'start') {
      started.set(step, { method: e.method as string | undefined, url: e.url as string | undefined })
      return
    }
    if (e.phase === 'info') {
      if (SUPPRESSED_INFO_STEPS.has(step)) return
      const obj: Record<string, unknown> = { step: displayStep(step) }
      const sum = summarize(step)
      once(obj, 'summary', `sum:${step}:${sum}`, sum)
      const desc = describe(step, 'info')
      once(obj, 'description', `info:${step}:${desc}`, desc)
      Object.assign(obj, infoFields(e))
      out(obj)
      return
    }
    // phase 'done': emit the request (with real headers + body) then the response.
    const start = started.get(step) ?? {}
    started.delete(step)
    const status = typeof e.status === 'number' ? e.status : undefined
    const response = e.response as { headers?: Record<string, string> } | undefined
    const reqBody = requestBody(e)
    const respBody = responseBody(e)

    const request: Record<string, unknown> = {}
    if (start.method) request.method = start.method
    if (start.url) request.url = start.url
    if (e.request_headers) request.headers = e.request_headers
    if (reqBody !== undefined) request.body = reqBody
    const reqObj: Record<string, unknown> = { step: displayStep(step) }
    const sum = summarize(step, status)
    once(reqObj, 'summary', `sum:${step}:${sum}`, sum)
    const reqDesc = describe(step, 'request', status)
    once(reqObj, 'description', `req:${step}:${reqDesc}`, reqDesc)
    reqObj.request = request
    out(reqObj)

    const resp: Record<string, unknown> = {}
    if (status !== undefined) resp.status = status
    if (response?.headers) resp.headers = response.headers
    if (respBody !== undefined) resp.body = respBody
    const respObj: Record<string, unknown> = { step: displayStep(step) }
    const resDesc = describe(step, 'response', status)
    once(respObj, 'description', `res:${step}:${resDesc}`, resDesc)
    respObj.response = resp
    out(respObj)
  }
}

/**
 * `--debug`: the raw wire view. Render only the request and response of each
 * HTTP hop on stderr — no descriptions, no step vocabulary, no info events. Each
 * hop emits a `{ request }` object (method, url, headers, body) then a
 * `{ response }` object (status, headers, body) — the response nested under a
 * property rather than tagged with a `type`.
 */
export function makeDebugRenderer(emit: (obj: Record<string, unknown>) => void): OnEvent {
  const started = new Map<string, { method?: string; url?: string }>()
  const out = (obj: Record<string, unknown>) => emit(obj)

  return (e: AAuthEvent) => {
    const step = e.step
    if (e.phase === 'start') {
      started.set(step, { method: e.method as string | undefined, url: e.url as string | undefined })
      return
    }
    if (e.phase === 'info') return // debug = only requests and responses
    const start = started.get(step) ?? {}
    started.delete(step)
    const status = typeof e.status === 'number' ? e.status : undefined
    const response = e.response as { headers?: Record<string, string> } | undefined
    const reqBody = requestBody(e)
    const respBody = responseBody(e)

    const request: Record<string, unknown> = {}
    if (start.method) request.method = start.method
    if (start.url) request.url = start.url
    if (e.request_headers) request.headers = e.request_headers
    if (reqBody !== undefined) request.body = reqBody
    out({ request })

    const resp: Record<string, unknown> = {}
    if (status !== undefined) resp.status = status
    if (response?.headers) resp.headers = response.headers
    if (respBody !== undefined) resp.body = respBody
    out({ response: resp })
  }
}
