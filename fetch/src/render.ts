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
 * Short, human/agent-readable description for each protocol step, by the kind of
 * event. `response` descriptions may refine on status.
 */
function describe(step: string, kind: 'request' | 'response' | 'info', status?: number): string {
  const req: Record<string, string> = {
    signed_request: 'Send the request, signed (RFC 9421) with the agent token.',
    retry_with_auth_token: 'Retry the request, now signed with the auth token.',
    r3_authorize_request: 'POST the requested operations to the authorize endpoint, signed with the agent token.',
    ps_metadata_request: "Fetch the person server's metadata.",
    ps_token_request: "POST the resource token to the person server's token endpoint, signed with the agent token.",
    consent_poll: 'Poll the person server for the consent result.',
  }
  const info: Record<string, string> = {
    challenge_received: 'Parsed the AAuth challenge; will exchange the resource token for an auth token.',
    ps_consent_pending: 'Person consent required; opening the interaction URL to approve.',
    consent_prompt: 'Consent prompt opened; waiting for the person to approve.',
    consent_resolved: 'Consent resolved by the person.',
    auth_token_received: 'Received the auth token from the person server.',
  }
  if (kind === 'request') return req[step] ?? `Request: ${step}.`
  if (kind === 'info') return info[step] ?? `${step}.`
  // response
  if (status === 401) return 'Resource replied 401 — an auth token is required.'
  if (status === 202) return 'Person server needs consent (interaction required).'
  if (status === 200) return 'Returned 200.'
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
 * `step` correlates a request with its response.
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
      out({ type: 'info', step, description: describe(step, 'info'), ...infoFields(e) })
      return
    }
    // phase 'done': emit the request (with real headers) then the response.
    const start = started.get(step) ?? {}
    started.delete(step)
    const status = typeof e.status === 'number' ? e.status : undefined
    const response = e.response as { headers?: Record<string, string> } | undefined

    const reqObj: Record<string, unknown> = { type: 'request', step, description: describe(step, 'request') }
    if (start.method) reqObj.method = start.method
    if (start.url) reqObj.url = start.url
    if (e.request_headers) reqObj.headers = e.request_headers
    out(reqObj)

    const respObj: Record<string, unknown> = { type: 'response', step, description: describe(step, 'response', status) }
    if (status !== undefined) respObj.status = status
    if (response?.headers) respObj.headers = response.headers
    out(respObj)
  }
}
