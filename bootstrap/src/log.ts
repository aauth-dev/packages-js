import { homedir } from 'node:os'
import { join } from 'node:path'
import { writeFileSync, mkdirSync } from 'node:fs'

export interface BootstrapEvent {
  step: string
  phase: 'start' | 'done' | 'info'
  [key: string]: unknown
}

export type OnBootstrapEvent = (event: BootstrapEvent) => void

const MARKER_PATH = join(homedir(), '.aauth', '.tldr-shown')

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

// ── TL;DR block (shown once at the top of bootstrap --ps --log) ───────────────
function renderTldr(): string {
  return [
    section('What is AAuth?'),
    '',
    'AAuth gives every agent its own cryptographic identity. The agent signs every',
    'HTTP request with a private key only it holds; resources verify the signature',
    'and decide whether to authorize. A Person Server represents the user and',
    'grants the agent permission to act on their behalf — no pre-registration, no',
    'shared secrets.',
    '',
    'Protocol parties:',
    '',
    `   ${c.cyan('AGENT')}          this CLI on your device. Identifies via an Ed25519 keypair`,
    '                  generated locally — the private key never leaves the OS keychain.',
    `   ${c.green('RESOURCE')}       the API the agent wants to call.`,
    `   ${c.magenta('PERSON SERVER')}  represents the user. Holds identity, decides authorization,`,
    '                  issues auth_tokens the resource will trust.',
    `   ${c.dim('ACCESS SERVER  (out of scope for this demo) policy engine that guards')}`,
    `                  ${c.dim('resources in federated mode.')}`,
    '',
    'The user (you) approves consent in a browser the first time the PS sees',
    'this agent.',
    '',
    'The flow:',
    '',
    `   ${c.dim('one-time')}   ${c.cyan('AGENT')}  generates keypair on this device`,
    `              ${c.cyan('AGENT')}  registers a Person Server it will delegate consent to`,
    `   ${c.dim('per call')}   ${c.cyan('AGENT')}  ─▶  ${c.green('RESOURCE')}       (401: who are you?)`,
    `              ${c.cyan('AGENT')}  ─▶  ${c.magenta('PERSON SERVER')}  (token exchange — first time needs consent)`,
    `              ${c.yellow('user')}   ─▶  ${c.magenta('PERSON SERVER')}  (approve in browser, first time only)`,
    `              ${c.cyan('AGENT')}  ─▶  ${c.green('RESOURCE')}       (200: data)`,
    '',
    `${c.dim('Key properties: agent identity without pre-registration · proof-of-possession')}`,
    `${c.dim('on every request · user consent at the Person Server, never at the resource.')}`,
    '',
    `${c.dim("You're about to run the one-time setup.")}`,
    '',
    '',
  ].join('\n')
}

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
    lines.push('  • Generate Ed25519 keypair on this device — the private key stays in the OS')
    lines.push('    keychain and never leaves. The public key thumbprint is the agent\'s identity.')
    lines.push('')
    if (state.agentUrl) lines.push(`      ${c.bold('agent')}       ${state.agentUrl}`)
    if (state.kid)      lines.push(`      ${c.bold('kid')}         ${state.kid}`)
    if (state.publicJwk) lines.push(`      ${c.bold('public key')}  ${renderJwk(state.publicJwk)}`)
    if (state.jkt)      lines.push(`      ${c.bold('jkt')}         ${state.jkt}`)
    lines.push('')
  } else if (state.agentUrl) {
    lines.push('  • Use the existing keypair on this device — no new key generated.')
    lines.push('    The public key thumbprint below is this agent\'s identity.')
    lines.push('')
    lines.push(`      ${c.bold('agent')}       ${state.agentUrl}`)
    if (state.kid)       lines.push(`      ${c.bold('kid')}         ${state.kid} ${c.dim('(current)')}`)
    if (state.publicJwk) lines.push(`      ${c.bold('public key')}  ${renderJwk(state.publicJwk)}`)
    if (state.jkt)       lines.push(`      ${c.bold('jkt')}         ${state.jkt}`)
    lines.push('')
  }

  // Sub-bullet 2: PS metadata
  if (state.metadataUrl) {
    lines.push('  • Fetch Person Server metadata to confirm it\'s reachable and well-formed.')
    lines.push('')
    const url = new URL(state.metadataUrl)
    lines.push(`      ${c.bold('GET')} ${url.pathname}  HTTP/1.1`)
    lines.push(`      ${c.bold('Host:')} ${url.host}`)
    lines.push('')
    const statusColor = state.metadataStatus && state.metadataStatus < 300 ? c.green : c.red
    lines.push(`      ${c.dim('←')} HTTP/1.1 ${statusColor(String(state.metadataStatus ?? '?'))} ${state.metadataStatus === 200 ? 'OK' : ''}`)
    lines.push(`      ${c.bold('Content-Type:')} application/json`)
    if (state.metadataBody) {
      const body = JSON.stringify(state.metadataBody, null, 2).split('\n').map(l => `      ${l}`).join('\n')
      lines.push(body)
    }
    lines.push('')
  }

  if (state.personServerUrl) {
    lines.push(`  ${c.green('✓')} Bootstrap complete. The agent will bind to a user on its first authorized request.`)
    lines.push('')
  }
  return lines.join('\n')
}

// ── Marker file ──────────────────────────────────────────────────────────────
function writeTldrMarker(): void {
  try {
    mkdirSync(join(homedir(), '.aauth'), { recursive: true })
    writeFileSync(MARKER_PATH, new Date().toISOString(), 'utf8')
  } catch {
    // Non-fatal — marker is purely a UX hint
  }
}

// ── Public API ────────────────────────────────────────────────────────────────

const narrations: Record<string, (e: BootstrapEvent) => string | undefined> = {
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

function formatNdjson(event: BootstrapEvent): string {
  const narration = narrations[event.step]?.(event)
  const line = narration ? { ...event, narration } : event
  return JSON.stringify(line) + '\n'
}

/**
 * Build a stream-aware bootstrap event handler.
 *
 * When stderr is a TTY: prints TL;DR + Step 0 grouped card, then writes a
 * marker file so a subsequent `fetch --log` can suppress its own TL;DR.
 *
 * When stderr is piped: emits NDJSON (one line per event) as before.
 */
export function buildLogEmitter(enabled: boolean): OnBootstrapEvent | undefined {
  if (!enabled) return undefined

  const pretty = IS_TTY

  if (!pretty) {
    // Piped — keep NDJSON shape for programmatic consumers.
    return (event: BootstrapEvent) => {
      process.stderr.write(formatNdjson(event))
    }
  }

  // TTY: collect events, render TL;DR once, then render Step 0 on completion.
  let printedTldr = false
  const state: Step0State = {}
  let hasNewKey = false
  let rendered = false

  function maybePrintTldr() {
    if (!printedTldr) {
      process.stderr.write(renderTldr())
      printedTldr = true
    }
  }

  function finalize() {
    if (rendered) return
    rendered = true
    process.stderr.write(renderStep0(state, hasNewKey))
    writeTldrMarker()
  }

  return (event: BootstrapEvent) => {
    maybePrintTldr()
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
  buildLogEmitter(true)?.(event)
}
