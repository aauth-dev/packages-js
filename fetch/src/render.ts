import type { AAuthEvent, OnEvent } from '@aauth/mcp-agent'

/** A JWK / arbitrary JSON value — only passed through to output. */
type Json = unknown

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
 * - `display` — the step label shown to the user. Named by target + purpose, not
 *   "signed" (every request is signed). Two internal steps can share a display
 *   name: the initial resource call and its auth-token retry are both
 *   `resource_request` (the same logical operation), distinguished by their
 *   distinct internal names so each still gets its own description.
 * - `req` / `info` — the description for a request / info event.
 * - `res` — the description for a response; a function when it varies by status.
 *   Never the bare status code (that's already in `status`); it states what came
 *   back and what it sets up next.
 */
interface StepSpec {
  display: string
  req?: string
  info?: string
  res?: string | ((status?: number) => string)
}

const STEPS: Record<string, StepSpec> = {
  // The two resource calls are named by the token they carry (not by position):
  // the agent-token call may get a 401; the auth-token call is the authorized one.
  signed_request: {
    display: 'agent_token_request',
    req: 'Call the resource with your agent token — self-asserted identity, no person authorization yet.',
    res: (s) =>
      s === 401
        ? 'The resource needs a person-authorized token — returns a challenge to exchange.'
        : "Received the resource's response.",
  },
  retry_with_auth_token: {
    display: 'auth_token_request',
    req: 'Call the resource with the person-authorized auth token.',
    res: "Received the resource's response.",
  },
  // Pre-authed reuse (--auth-token/--signing-key): also an auth-token call.
  auth_token_request: {
    display: 'auth_token_request',
    req: 'Call the resource with the person-authorized auth token.',
    res: "Received the resource's response.",
  },
  r3_authorize_request: {
    display: 'authorize_request',
    req: "POST the requested operations to the resource's authorize endpoint, signed with your agent token.",
    res: 'Received a resource token scoped to those operations.',
  },
  challenge_received: {
    display: 'challenge',
    info: 'Parsed it — exchange the resource token for an auth token.',
  },
  ps_metadata_request: {
    display: 'ps_metadata',
    req: 'Ask your person server for its endpoints.',
    res: "Received the person server's endpoints.",
  },
  ps_metadata_cached: {
    display: 'ps_metadata',
    info: "Read the person server's endpoints from config — no fetch needed.",
  },
  ps_token_request: {
    display: 'token_exchange',
    req: 'Send the resource token to the person server to mint an auth token.',
    res: (s) =>
      s === 202
        ? 'Consent required before an auth token is issued.'
        : 'Received the auth token — consent was already on file.',
  },
  ps_consent_pending: {
    display: 'consent_required',
    info: 'Consent required — opening the approval URL for the person.',
  },
  consent_prompt: {
    display: 'consent_prompt',
    info: 'Waiting for the person to approve…',
  },
  consent_poll: {
    display: 'consent_poll',
    req: 'Check whether the person has approved yet.',
    res: 'Not yet — still waiting.',
  },
  consent_resolved: {
    display: 'consent_granted',
    info: 'The person approved.',
  },
  auth_token_received: {
    display: 'auth_token',
    info: 'Auth token received.',
  },
}

/** The step label shown in `-v` (mapped from the internal name). */
function displayStep(step: string): string {
  return STEPS[step]?.display ?? step
}

/** Description for an event, by its kind. Falls back gracefully for unknown steps. */
function describe(step: string, kind: 'request' | 'response' | 'info', status?: number): string {
  const spec = STEPS[step]
  if (kind === 'request') return spec?.req ?? `Request: ${displayStep(step)}.`
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
  return out
}

/**
 * Build an OnEvent that renders each mcp-agent event as a pretty JSON object on
 * stderr (the `-v` view). Maps the agent's `phase` to `type`:
 *   - phase 'start' is buffered (the real signed headers aren't known until the
 *     response arrives) and emitted as the `request` object once 'done' fires;
 *   - phase 'done' emits the `request` (with real RFC 9421 `request_headers`)
 *     then the `response`;
 *   - phase 'info' emits an `info` object.
 * `step` is the display label; a request pairs with the response right after it.
 */
export function makeVerboseRenderer(emit: (line: string) => void, isTty: boolean): OnEvent {
  const started = new Map<string, { method?: string; url?: string }>()
  const out = (obj: Record<string, unknown>) => emit(prettyJson(obj, isTty))

  return (e: AAuthEvent) => {
    const step = e.step
    if (e.phase === 'start') {
      started.set(step, { method: e.method as string | undefined, url: e.url as string | undefined })
      return
    }
    if (e.phase === 'info') {
      out({ type: 'info', step: displayStep(step), description: describe(step, 'info'), ...infoFields(e) })
      return
    }
    // phase 'done': emit the request (with real headers) then the response.
    const start = started.get(step) ?? {}
    started.delete(step)
    const status = typeof e.status === 'number' ? e.status : undefined
    const response = e.response as { headers?: Record<string, string> } | undefined

    const reqObj: Record<string, unknown> = { type: 'request', step: displayStep(step), description: describe(step, 'request') }
    if (start.method) reqObj.method = start.method
    if (start.url) reqObj.url = start.url
    if (e.request_headers) reqObj.headers = e.request_headers
    out(reqObj)

    const respObj: Record<string, unknown> = { type: 'response', step: displayStep(step), description: describe(step, 'response', status) }
    if (status !== undefined) respObj.status = status
    if (response?.headers) respObj.headers = response.headers
    out(respObj)
  }
}
