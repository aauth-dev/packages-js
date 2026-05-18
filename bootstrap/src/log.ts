export interface BootstrapEvent {
  step: string
  phase: 'start' | 'done' | 'info'
  [key: string]: unknown
}

export type OnBootstrapEvent = (event: BootstrapEvent) => void

// ── ANSI styling (TTY only, respects NO_COLOR) ────────────────────────────────
const IS_TTY = process.stderr.isTTY === true || process.env.AAUTH_FORCE_PRETTY === '1'
const COLOR_ENABLED = IS_TTY && !process.env.NO_COLOR
const c = {
  dim:    (s: string) => COLOR_ENABLED ? `\x1b[2m${s}\x1b[0m`  : s,
  bold:   (s: string) => COLOR_ENABLED ? `\x1b[1m${s}\x1b[0m`  : s,
  cyan:   (s: string) => COLOR_ENABLED ? `\x1b[36m${s}\x1b[0m` : s,
  magenta:(s: string) => COLOR_ENABLED ? `\x1b[35m${s}\x1b[0m` : s,
  green:  (s: string) => COLOR_ENABLED ? `\x1b[32m${s}\x1b[0m` : s,
  yellow: (s: string) => COLOR_ENABLED ? `\x1b[33m${s}\x1b[0m` : s,
  red:    (s: string) => COLOR_ENABLED ? `\x1b[31m${s}\x1b[0m` : s,
}

const RULE = '─'.repeat(80)
const section = (title: string) => `${c.dim('─── ')}${c.bold(title)} ${c.dim(RULE.slice(title.length + 5))}`

// ── Step 0 card builder (accumulates from events) ─────────────────────────────
interface Step0State {
  agentUrl?: string
  personServerUrl?: string
  agentId?: string
  kid?: string
  publicJwk?: Record<string, unknown>
  jkt?: string
  algorithm?: string
  backend?: string
  metadataUrl?: string
  metadataStatus?: number
  metadataBody?: Record<string, unknown>
}

function shortHex(s: string | undefined, n = 16): string {
  if (!s) return '…'
  return s.length <= n ? s : `${s.slice(0, n)}…`
}

function renderJwk(jwk: Record<string, unknown>): string {
  const kty = jwk.kty as string | undefined
  const crv = jwk.crv as string | undefined
  const x = jwk.x as string | undefined
  return `{ kty: ${JSON.stringify(kty)}, crv: ${JSON.stringify(crv)}, x: ${JSON.stringify(shortHex(x, 24))} }`
}

function renderStep0(state: Step0State, hasNewKey: boolean): string {
  const lines: string[] = []
  lines.push(section('0. ONE-TIME SETUP'))
  lines.push('')

  // Sub-bullet 1: keypair
  if (hasNewKey && state.publicJwk && state.kid) {
    lines.push(...bulletWrap(describe('key_generation', 'start', { algorithm: state.algorithm ?? 'Ed25519' }) ?? ''))
    lines.push('')
    if (state.agentUrl) lines.push(`      ${c.bold('agent')}       ${state.agentUrl}`)
    if (state.kid)      lines.push(`      ${c.bold('kid')}         ${state.kid}`)
    if (state.publicJwk) lines.push(`      ${c.bold('public key')}  ${renderJwk(state.publicJwk)}`)
    if (state.jkt)      lines.push(`      ${c.bold('jkt')}         ${state.jkt}`)
    lines.push('')
  } else if (state.agentUrl) {
    lines.push(...bulletWrap(describe('key_info', 'info') ?? ''))
    lines.push('')
    lines.push(`      ${c.bold('agent')}       ${state.agentUrl}`)
    if (state.kid)       lines.push(`      ${c.bold('kid')}         ${state.kid} ${c.dim('(current)')}`)
    if (state.publicJwk) lines.push(`      ${c.bold('public key')}  ${renderJwk(state.publicJwk)}`)
    if (state.jkt)       lines.push(`      ${c.bold('jkt')}         ${state.jkt}`)
    lines.push('')
  }

  // Sub-bullet 2: PS metadata
  if (state.metadataUrl) {
    lines.push(...bulletWrap(describe('ps_metadata_request', 'start') ?? ''))
    lines.push('')
    const url = new URL(state.metadataUrl)
    lines.push(`      ${c.bold('GET')} ${url.pathname}  HTTP/1.1`)
    lines.push(`      ${c.bold('Host:')} ${url.host}`)
    lines.push('')
    const statusColor = state.metadataStatus && state.metadataStatus < 300 ? c.green : c.red
    lines.push(`      ← HTTP/1.1 ${statusColor(String(state.metadataStatus ?? '?'))} ${state.metadataStatus === 200 ? 'OK' : ''}`)
    lines.push(`      ${c.bold('Content-Type:')} application/json`)
    if (state.metadataBody) {
      const body = JSON.stringify(state.metadataBody, null, 2).split('\n').map(l => `      ${l}`).join('\n')
      lines.push(body)
    }
    lines.push('')
  }

  if (state.personServerUrl) {
    const desc = describe('bootstrap_complete', 'info') ?? ''
    const wrapped = wrap(desc, 76)
    wrapped.forEach((line, i) => {
      lines.push(i === 0 ? `  ${c.green('✓')} ${line}` : `    ${line}`)
    })
    lines.push('')
  }
  return lines.join('\n')
}

// ── Public API ────────────────────────────────────────────────────────────────

type EventDescriber = (e: BootstrapEvent) => string | undefined

const narrations: Record<string, EventDescriber> = {
  backend_discovery: (e) => e.phase === 'start'
    ? 'Discovering available key backends on this machine'
    : `Found ${(e.backends as unknown[] | undefined)?.length ?? 0} backend(s)`,
  key_generation: (e) => e.phase === 'start'
    ? `Generating ${e.algorithm} key on ${e.backend} backend`
    : `Generated key — kid ${e.kid}`,
  ps_metadata_request: (e) => e.phase === 'start'
    ? `Agent → Person Server: GET ${e.url}`
    : `Person Server metadata received (${e.status})`,
  ps_metadata_validated: () => 'Person Server metadata validated',
  agent_config_persisted: (e) => `Agent configured: agentId=${e.agentId}, personServerUrl=${e.personServerUrl}`,
  bootstrap_started: (e) => `Configuring ${e.agentUrl} with person server ${e.personServerUrl}`,
  bootstrap_complete: () => 'Person server configured.',
  sign_token: (e) => e.phase === 'start' ? `Signing agent_token` : 'Agent token signed',
}

// Long-form per-step prose explaining what's happening at the protocol level.
// Single source of truth for both pretty (renderStep0) and JSON (--jsonl)
// consumers — same map approach as fetch/src/log.ts uses for the per-call flow.
const descriptions: Record<string, EventDescriber> = {
  key_info: () =>
    "Use the existing keypair on this device — no new key generated. The public key thumbprint below is this agent's identity.",
  key_generation: (e) => e.phase === 'start'
    ? `Generate ${e.algorithm ?? 'Ed25519'} keypair on this device — the private key stays in the OS keychain and never leaves. The public key thumbprint is the agent's identity.`
    : undefined,
  ps_metadata_request: (e) => e.phase === 'start'
    ? "Fetch Person Server metadata to confirm it's reachable and well-formed."
    : undefined,
  bootstrap_complete: () =>
    "Bootstrap complete. The agent will bind to a user on its first authorized request.",
}

function formatNdjson(event: BootstrapEvent): string {
  const narration = narrations[event.step]?.(event)
  const description = descriptions[event.step]?.(event)
  const line: Record<string, unknown> = { ...event }
  if (narration) line.narration = narration
  if (description) line.description = description
  return JSON.stringify(line) + '\n'
}

// Word-wrap a paragraph at `width` columns for terminal rendering.
function wrap(text: string, width = 78): string[] {
  const words = text.split(/\s+/).filter(Boolean)
  const lines: string[] = []
  let cur = ''
  for (const w of words) {
    if (cur.length === 0) cur = w
    else if (cur.length + 1 + w.length <= width) cur += ' ' + w
    else { lines.push(cur); cur = w }
  }
  if (cur) lines.push(cur)
  return lines
}

// Render a paragraph as a bullet with hanging-indent continuation lines.
//   "  • first line of paragraph..."
//   "    continuation..."
function bulletWrap(text: string, width = 76): string[] {
  return wrap(text, width).map((line, i) => i === 0 ? `  • ${line}` : `    ${line}`)
}

// Look up a description for a synthetic event shape — used by renderStep0
// so both pretty and JSON consumers read from the same map.
function describe(step: string, phase: 'start' | 'done' | 'info', extra?: Record<string, unknown>): string | undefined {
  const e: BootstrapEvent = { step, phase, ...(extra ?? {}) }
  return descriptions[step]?.(e)
}

/**
 * Build a stream-aware bootstrap event handler.
 *
 * mode='pretty':  prints Step 0 grouped card on stderr.
 * mode='jsonl':   emits each event as one JSON object per line on stderr.
 * mode=undefined: returns undefined (no logging).
 */
export type LogMode = 'pretty' | 'jsonl'

export function buildLogEmitter(mode: LogMode | undefined): OnBootstrapEvent | undefined {
  if (!mode) return undefined

  if (mode === 'jsonl') {
    return (event: BootstrapEvent) => {
      process.stderr.write(formatNdjson(event))
    }
  }

  // TTY: collect events, render Step 0 on completion.
  const state: Step0State = {}
  let hasNewKey = false
  let rendered = false

  function finalize() {
    if (rendered) return
    rendered = true
    process.stderr.write(renderStep0(state, hasNewKey))
  }

  return (event: BootstrapEvent) => {
    switch (event.step) {
      case 'bootstrap_started':
        state.agentUrl = event.agentUrl as string | undefined
        state.personServerUrl = event.personServerUrl as string | undefined
        break
      case 'key_generation':
        if (event.phase === 'start') {
          hasNewKey = true
          state.algorithm = event.algorithm as string | undefined
          state.backend = event.backend as string | undefined
        } else if (event.phase === 'done') {
          state.kid = event.kid as string | undefined
        }
        break
      case 'ps_metadata_request':
        if (event.phase === 'start') {
          state.metadataUrl = event.url as string | undefined
        } else if (event.phase === 'done') {
          state.metadataStatus = event.status as number | undefined
          // Body is not in the event — fetch it from a sibling source if needed
        }
        break
      case 'ps_metadata_body':
        // Synthetic event for the rendered metadata body — emitted from bootstrap-ps
        state.metadataBody = event.body as Record<string, unknown> | undefined
        break
      case 'agent_config_persisted':
        state.agentId = event.agentId as string | undefined
        state.personServerUrl = event.personServerUrl as string | undefined ?? state.personServerUrl
        break
      case 'key_info':
        // Synthetic event with full key details (kid, publicJwk, jkt)
        state.kid = event.kid as string | undefined ?? state.kid
        state.publicJwk = event.publicJwk as Record<string, unknown> | undefined
        state.jkt = event.jkt as string | undefined
        break
      case 'bootstrap_complete':
        finalize()
        break
    }
  }
}

export function logEvent(enabled: boolean, event: BootstrapEvent): void {
  if (!enabled) return
  buildLogEmitter('jsonl')?.(event)
}
