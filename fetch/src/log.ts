import type { AAuthEvent, OnEvent } from '@aauth/mcp-agent'
import { readConfig, readKeychain } from '@aauth/local-keys'
import { createHash } from 'node:crypto'

// ── ANSI styling (TTY only, respects NO_COLOR) ────────────────────────────────
const IS_TTY = process.stderr.isTTY === true || process.env.AAUTH_FORCE_PRETTY === '1'
const COLOR_ENABLED = IS_TTY && !process.env.NO_COLOR
const c = {
  dim:     (s: string) => COLOR_ENABLED ? `\x1b[2m${s}\x1b[0m`  : s,
  bold:    (s: string) => COLOR_ENABLED ? `\x1b[1m${s}\x1b[0m`  : s,
  cyan:    (s: string) => COLOR_ENABLED ? `\x1b[36m${s}\x1b[0m` : s,
  magenta: (s: string) => COLOR_ENABLED ? `\x1b[35m${s}\x1b[0m` : s,
  green:   (s: string) => COLOR_ENABLED ? `\x1b[32m${s}\x1b[0m` : s,
  yellow:  (s: string) => COLOR_ENABLED ? `\x1b[33m${s}\x1b[0m` : s,
  red:     (s: string) => COLOR_ENABLED ? `\x1b[31m${s}\x1b[0m` : s,
}

const RULE = '─'.repeat(80)
const section = (title: string) => `${c.dim('─── ')}${c.bold(title)} ${c.dim(RULE.slice(title.length + 5))}`

// ── Header / preamble blocks ──────────────────────────────────────────────────

function computeJkt(jwk: Record<string, unknown>): string {
  const kty = jwk.kty as string
  const crv = jwk.crv as string
  const x = jwk.x as string
  const y = jwk.y as string | undefined
  const canonical = kty === 'EC'
    ? JSON.stringify({ crv, kty, x, y })
    : JSON.stringify({ crv, kty, x })
  return createHash('sha256').update(canonical).digest('base64url')
}

function short(s: string | undefined, n = 24): string {
  if (!s) return '…'
  return s.length <= n ? s : `${s.slice(0, n)}…`
}

function resolveAgentUrl(agentUrl?: string): string | undefined {
  if (agentUrl) return agentUrl
  const cfg = readConfig()
  const entries = Object.entries(cfg.agentProviders)
  return entries.length > 0 ? entries[0][0] : undefined
}

function renderAlreadySetUp(agentUrl?: string): string {
  const lines: string[] = []
  lines.push(section('Already set up'))
  lines.push('')

  agentUrl = resolveAgentUrl(agentUrl)
  if (!agentUrl) {
    lines.push(`  ${c.dim('(no agent configured)')}`)
    lines.push('')
    return lines.join('\n')
  }

  const cfg = readConfig().agentProviders[agentUrl]
  const keychain = readKeychain(agentUrl)
  const currentKid = keychain?.current
  const jwk = currentKid ? keychain?.keys[currentKid] as unknown as Record<string, unknown> : undefined

  lines.push(`  ${c.green('✓')} One-time setup is already done on this device. The agent below will be`)
  lines.push(`    used for this call.`)
  lines.push('')
  lines.push(`     ${c.bold('agent')}          ${agentUrl}`)
  if (currentKid) lines.push(`     ${c.bold('kid')}            ${currentKid}  ${c.dim('(current)')}`)
  if (jwk) {
    lines.push(`     ${c.bold('public key')}     { kty: ${JSON.stringify(jwk.kty)}, crv: ${JSON.stringify(jwk.crv)}, x: ${JSON.stringify(short(jwk.x as string))} }`)
    lines.push(`     ${c.bold('jkt')}            ${computeJkt(jwk)}`)
  }
  if (cfg?.personServerUrl) lines.push(`     ${c.bold('person server')}  ${cfg.personServerUrl}`)
  lines.push('')
  lines.push('')
  return lines.join('\n')
}

function renderThisCall(url: string, agentUrl?: string, personServer?: string): string {
  const u = new URL(url)
  const resource = u.host
  const scopeStr = u.searchParams.get('scope')
  const scopes = scopeStr ? scopeStr.split(/[\s+]+/).filter(Boolean) : []
  const IDENTITY = new Set(['openid', 'profile', 'email'])
  const resourceScopes = scopes.filter(s => !IDENTITY.has(s))
  const identityScopes = scopes.filter(s => IDENTITY.has(s))

  agentUrl = resolveAgentUrl(agentUrl)
  if (!personServer && agentUrl) {
    personServer = readConfig().agentProviders[agentUrl]?.personServerUrl
  }

  const lines: string[] = []
  lines.push(section('This call'))
  lines.push('')
  if (agentUrl)      lines.push(`${c.bold('Agent')}          ${new URL(agentUrl).host}`)
  if (personServer)  lines.push(`${c.bold('Person Server')}  ${new URL(personServer).host}`)
  lines.push(`${c.bold('Resource')}       ${resource}`)
  if (scopes.length === 0) {
    lines.push(`${c.bold('Scopes')}         ${c.dim('(none in URL — resource will infer its native scope)')}`)
  } else {
    const lineParts: string[] = []
    if (resourceScopes.length > 0) {
      lineParts.push(`${c.bold('Scopes')}         ${resourceScopes.join(', ').padEnd(17)} ${c.dim('(resource scope — granted by the API)')}`)
    }
    if (identityScopes.length > 0) {
      const indent = resourceScopes.length > 0 ? '               ' : `${c.bold('Scopes')}         `
      lineParts.push(`${indent}${identityScopes.join(', ').padEnd(17)} ${c.dim('(identity scopes — granted by the Person Server)')}`)
    }
    lines.push(...lineParts)
  }
  lines.push('')
  lines.push('')
  return lines.join('\n')
}

// ── HTTP card renderers ───────────────────────────────────────────────────────

type Actor = 'AGENT' | 'RESOURCE' | 'PERSON SERVER' | 'user'

function actorTint(a: Actor): (s: string) => string {
  switch (a) {
    case 'AGENT':         return c.cyan
    case 'RESOURCE':      return c.green
    case 'PERSON SERVER': return c.magenta
    case 'user':          return c.yellow
  }
}

function stepHeader(n: number, from: Actor, to: Actor, subtitle: string): string {
  const arrow = `${actorTint(from)(from)} → ${actorTint(to)(to)}`
  const title = `${n}. ${arrow} · ${subtitle}`
  // Approximate length without ANSI codes for divider alignment
  const visible = `${n}. ${from} → ${to} · ${subtitle}`
  const dashes = Math.max(2, 80 - visible.length - 6)
  return `${c.dim('─── ')}${title} ${c.dim('─'.repeat(dashes))}`
}

function statusLine(status: number): string {
  const tint = status >= 200 && status < 300 ? c.green : status >= 400 ? c.red : c.yellow
  const label = STATUS_LABELS[status] ?? ''
  return `   ← HTTP/1.1 ${tint(String(status))} ${tint(label)}`
}

const STATUS_LABELS: Record<number, string> = {
  200: 'OK', 201: 'Created', 202: 'Accepted',
  401: 'Unauthorized', 403: 'Forbidden', 404: 'Not Found',
  500: 'Internal Server Error',
}

// Fields we hide from JWT decoded display — internal/timestamp noise that
// distracts from the pedagogically interesting claims.
const JWT_HIDDEN_FIELDS = new Set(['jti', 'iat', 'dwk', 'nbf'])

function renderJwtBlock(label: string, decoded: Record<string, unknown> | undefined, annotations?: Record<string, string>): string {
  if (!decoded) return ''
  const lines: string[] = []
  lines.push(`   ${c.bold(label)}`)
  const entries = Object.entries(decoded).filter(([k]) => !JWT_HIDDEN_FIELDS.has(k))
  const maxKey = Math.max(...entries.map(([k]) => k.length), 8)
  for (const [key, val] of entries) {
    const annot = annotations?.[key]
    let valStr: string
    if (val === null || val === undefined) {
      valStr = String(val)
    } else if (typeof val === 'object') {
      valStr = compactJson(val)
    } else {
      valStr = typeof val === 'string' ? val : String(val)
    }
    const annotSuffix = annot ? `   ${c.dim(`← ${annot}`)}` : ''
    lines.push(`     ${c.bold(key + ':').padEnd(maxKey + 5)}${valStr}${annotSuffix}`)
  }
  lines.push('')
  return lines.join('\n')
}

function truncateHeaderValue(v: string, maxLen = 80): string {
  if (v.length <= maxLen) return v
  // Try to truncate inside quoted JWT values gracefully
  const m = v.match(/^(.*?")([A-Za-z0-9_\-.]+)(".*)$/)
  if (m && m[2].length > 20) {
    return `${m[1]}${m[2].slice(0, 20)}…${m[3]}`
  }
  return `${v.slice(0, maxLen)}…`
}

function compactJson(v: unknown): string {
  // One-line JSON for inline values like cnf.jwk = { kty: ..., crv: ..., x: ... }
  if (v === null || typeof v !== 'object') return JSON.stringify(v)
  if (Array.isArray(v)) return JSON.stringify(v)
  const entries = Object.entries(v as Record<string, unknown>)
  if (entries.length === 0) return '{}'
  const inner = entries.map(([k, val]) => {
    if (val && typeof val === 'object' && !Array.isArray(val)) {
      return `${k}: ${compactJson(val)}`
    }
    if (typeof val === 'string' && val.length > 32) {
      return `${k}: ${JSON.stringify(short(val, 24))}`
    }
    return `${k}: ${JSON.stringify(val)}`
  }).join(', ')
  return `{ ${inner} }`
}

// Header-Case formatter: "signature-input" → "Signature-Input"
function headerCase(name: string): string {
  return name.split('-').map(p => p ? p[0].toUpperCase() + p.slice(1) : '').join('-')
}

// Truncate the Signature header's base64 value: sig=:<long base64>: → sig=:<16 chars>…:
function truncateSig(value: string): string {
  return value.replace(/=:([^:]+):/g, (_, b64) =>
    b64.length > 16 ? `=:${b64.slice(0, 16)}…:` : `=:${b64}:`)
}

// Truncate the JWT inside Signature-Key: sig=jwt;jwt="<long base64.base64.base64>"
function truncateSigKey(value: string): string {
  return value.replace(/jwt="([^"]+)"/g, (_, jwt) =>
    jwt.length > 24 ? `jwt="${jwt.slice(0, 24)}…"` : `jwt="${jwt}"`)
}

// Pretty-print a request/response body. JSON gets parsed + indented; long
// JWT-looking string values inside are truncated. Non-JSON returns as-is
// with simple length truncation.
function formatBody(body: string): string {
  try {
    const parsed = JSON.parse(body)
    const pretty = JSON.stringify(parsed, null, 2)
    // Truncate JWT-shaped values (>= 40 chars, alphanum/-/_) so the body stays scannable.
    return pretty.replace(/("[\w\-.]+":\s*)"([a-zA-Z0-9_\-.]{40,})"/g, (_m, key, val) =>
      `${key}"${val.slice(0, 32)}…"`)
  } catch {
    return body.length > 200 ? `${body.slice(0, 200)}…` : body
  }
}

// Canonical ordering for the AAuth-relevant request headers we know about.
// Anything not in this list is appended after, in insertion order.
const REQUEST_HEADER_ORDER = [
  'content-type',
  'content-length',
  'content-digest',
  'prefer',
  'authorization',
  'aauth-capabilities',
  'aauth-mission',
  'signature-input',
  'signature',
  'signature-key',
]

function renderRequestHeaders(
  method: string,
  url: string,
  headers: Record<string, string> | undefined,
  body?: string,
): string[] {
  const u = new URL(url)
  const path = u.pathname + u.search
  const lines: string[] = []
  lines.push(`   ${c.bold(method)} ${path}  HTTP/1.1`)
  lines.push(`   ${c.bold('Host:')} ${u.host}`)

  if (!headers) {
    // Fallback for events without captured headers (shouldn't happen post-Layer-2).
    lines.push(`   ${c.dim('(signed-request headers not captured for this exchange)')}`)
    return lines
  }

  const seen = new Set<string>(['host'])
  for (const name of REQUEST_HEADER_ORDER) {
    const value = headers[name]
    if (value === undefined) continue
    seen.add(name)
    const display =
      name === 'signature' ? truncateSig(value)
      : name === 'signature-key' ? truncateSigKey(value)
      : value
    lines.push(`   ${c.bold(headerCase(name) + ':')} ${display}`)
  }
  // Trailing pass for any headers we didn't anticipate (HTTP/2 implementations
  // sometimes add extras like accept-encoding).
  for (const [k, v] of Object.entries(headers)) {
    if (seen.has(k)) continue
    lines.push(`   ${c.bold(headerCase(k) + ':')} ${v}`)
  }
  if (body) {
    lines.push('')
    const formatted = formatBody(body)
    lines.push(...formatted.split('\n').map(l => `   ${l}`))
  }
  return lines
}

// ── Collected event state ─────────────────────────────────────────────────────

interface Step1Data {
  url?: string
  method?: string
  agentToken?: Record<string, unknown>
  requestHeaders?: Record<string, string>
}
interface Step2Data {
  status?: number
  resourceToken?: Record<string, unknown>
  aauthRequirement?: string
  responseBody?: string
}
interface Step3Data {
  url?: string
  status?: number
  body?: Record<string, unknown>
  requestHeaders?: Record<string, string>
  responseBody?: string
}
interface Step4Data {
  url?: string
  status?: number
  agentToken?: Record<string, unknown>
  aauthRequirement?: string
  location?: string
  requestHeaders?: Record<string, string>
  requestBody?: string
  responseBody?: string
}
interface Step5UserData { interactionUrl?: string; code?: string; resolvedAt?: number; startedAt?: number }
interface Step6TokenData { authToken?: Record<string, unknown>; expiresIn?: number }
interface Step8Data {
  url?: string
  method?: string
  authToken?: Record<string, unknown>
  requestHeaders?: Record<string, string>
}
interface Step9Data { status?: number }

interface FlowState {
  step1: Step1Data
  step2: Step2Data
  step3: Step3Data
  step4: Step4Data
  step5: Step5UserData
  step6: Step6TokenData
  step8: Step8Data
  step9: Step9Data
  consentRequired: boolean
}

function newState(): FlowState {
  return {
    step1: {}, step2: {}, step3: {}, step4: {}, step5: {},
    step6: {}, step8: {}, step9: {},
    consentRequired: false,
  }
}

// ── Render the flow ───────────────────────────────────────────────────────────

function pushDescription(out: string[], step: string, phase: 'start' | 'done' | 'info', status?: number): void {
  const text = describe(step, phase, status)
  if (text) {
    out.push(...wrap(text))
    out.push('')
  }
}

function renderColdFlow(s: FlowState): string {
  const out: string[] = []

  // Step 1: AGENT → RESOURCE
  out.push(stepHeader(1, 'AGENT', 'RESOURCE', "sign with agent's key"))
  out.push('')
  pushDescription(out, 'signed_request', 'start')
  if (s.step1.url) {
    out.push(...renderRequestHeaders(s.step1.method ?? 'GET', s.step1.url, s.step1.requestHeaders))
    out.push('')
    out.push(renderJwtBlock('agent_token (decoded JWT in Signature-Key)', s.step1.agentToken))
  }

  // Step 2: RESOURCE → AGENT (401 + resource_token)
  out.push(stepHeader(2, 'RESOURCE', 'AGENT', '401 with capability'))
  out.push('')
  pushDescription(out, 'signed_request', 'done', 401)
  out.push(statusLine(s.step2.status ?? 401))
  out.push(`   ${c.bold('Content-Type:')} application/json`)
  if (s.step2.aauthRequirement) {
    out.push(`   ${c.bold('AAuth-Requirement:')} ${truncateHeaderValue(s.step2.aauthRequirement)}`)
  }
  out.push('')
  out.push(renderJwtBlock('resource_token (decoded JWT in the challenge)', s.step2.resourceToken))

  // Step 3: AGENT → PS (discovery)
  out.push(stepHeader(3, 'AGENT', 'PERSON SERVER', 'discover token endpoint'))
  out.push('')
  pushDescription(out, 'ps_metadata_request', 'start')
  if (s.step3.url) {
    const u = new URL(s.step3.url)
    out.push(`   ${c.bold('GET')} ${u.pathname}  HTTP/1.1`)
    out.push(`   ${c.bold('Host:')} ${u.host}`)
    out.push('')
    out.push(statusLine(s.step3.status ?? 200))
    out.push(`   ${c.bold('Content-Type:')} application/json`)
    if (s.step3.body) {
      const json = JSON.stringify(s.step3.body, null, 2).split('\n').map(l => `   ${l}`).join('\n')
      out.push(json)
    }
    out.push('')
  }

  // Step 4: AGENT → PS (token exchange)
  out.push(stepHeader(4, 'AGENT', 'PERSON SERVER', 'exchange resource_token'))
  out.push('')
  pushDescription(out, 'ps_token_request', 'start')
  if (s.step4.url) {
    out.push(...renderRequestHeaders('POST', s.step4.url, s.step4.requestHeaders, s.step4.requestBody))
    out.push('')
    out.push(renderJwtBlock('agent_token (decoded JWT in Signature-Key)', s.step4.agentToken ?? s.step1.agentToken))
  }

  if (s.consentRequired) {
    // Step 5: PS → AGENT (202 consent required)
    out.push(stepHeader(5, 'PERSON SERVER', 'AGENT', '202, consent required'))
    out.push('')
    pushDescription(out, 'ps_token_request', 'done', 202)
    out.push(statusLine(202))
    out.push(`   ${c.bold('Content-Type:')} application/json; charset=utf-8`)
    if (s.step4.aauthRequirement) {
      out.push(`   ${c.bold('AAuth-Requirement:')} ${truncateHeaderValue(s.step4.aauthRequirement)}`)
    }
    if (s.step4.location) {
      out.push(`   ${c.bold('Location:')} ${s.step4.location}`)
    }
    out.push('')

    // Step 6: USER → PS (approve in browser)
    out.push(stepHeader(6, 'user', 'PERSON SERVER', 'approve in browser'))
    out.push('')
    pushDescription(out, 'consent_prompt', 'info')
    if (s.step5.interactionUrl) {
      out.push(`   ${c.bold('→ Open')}  ${s.step5.interactionUrl}`)
    }
    if (s.step5.code) {
      out.push(`     ${c.bold('Code')}  ${s.step5.code}`)
    }
    out.push('')
    const dur = s.step5.startedAt && s.step5.resolvedAt
      ? `${Math.round((s.step5.resolvedAt - s.step5.startedAt) / 1000)}s`
      : '?'
    out.push(`   ${c.green('✓')} approved ${c.dim(`(resolved in ${dur})`)}`)
    out.push('')

    // Step 7: PS → AGENT (auth_token issued)
    out.push(stepHeader(7, 'PERSON SERVER', 'AGENT', 'issues auth_token'))
    out.push('')
    pushDescription(out, 'auth_token_received', 'info')
    out.push(statusLine(200))
    out.push(`   ${c.bold('Content-Type:')} application/json`)
    out.push('')
    out.push(renderJwtBlock('auth_token (decoded)', s.step6.authToken, {
      scope: 'identity scopes consumed as claims',
    }))
  } else {
    // Warm path: PS returns 200 directly with auth_token
    out.push(stepHeader(5, 'PERSON SERVER', 'AGENT', '200 with auth_token'))
    out.push('')
    pushDescription(out, 'ps_token_request', 'done', 200)
    out.push(statusLine(200))
    out.push(`   ${c.bold('Content-Type:')} application/json`)
    out.push('')
    out.push(renderJwtBlock('auth_token (decoded)', s.step6.authToken, {
      scope: 'identity scopes consumed as claims',
    }))
  }

  // Step 8 / 6 (warm): AGENT → RESOURCE retry
  const retryStepNum = s.consentRequired ? 8 : 6
  out.push(stepHeader(retryStepNum, 'AGENT', 'RESOURCE', 'retry with auth_token'))
  out.push('')
  pushDescription(out, 'retry_with_auth_token', 'start')
  if (s.step8.url) {
    out.push(...renderRequestHeaders(s.step8.method ?? 'GET', s.step8.url, s.step8.requestHeaders))
    out.push('')
    out.push(renderJwtBlock('auth_token (decoded JWT in Signature-Key)', s.step8.authToken ?? s.step6.authToken))
    out.push('')
  }

  // Step 9 / 7 (warm): RESOURCE → AGENT 200 with data
  const finalStepNum = s.consentRequired ? 9 : 7
  out.push(stepHeader(finalStepNum, 'RESOURCE', 'AGENT', '200 with data'))
  out.push('')
  pushDescription(out, 'retry_with_auth_token', 'done', 200)
  out.push(statusLine(s.step9.status ?? 200))
  out.push(`   ${c.bold('Content-Type:')} application/json`)
  out.push('')

  return out.join('\n')
}

function renderCloser(consentRequired: boolean): string {
  if (consentRequired) {
    return [
      '',
      `${c.green('✓ Done.')} The agent now holds an auth_token cached for this resource.`,
      `  Future calls reuse it — no fresh consent needed unless the user revokes or`,
      `  the scope changes.`,
      '',
    ].join('\n')
  }
  return [
    '',
    `${c.green('✓ Done.')} The warm path skipped consent — the PS recognised this agent +`,
    `  scope combination and issued an auth_token without re-prompting the user.`,
    '',
  ].join('\n')
}

// ── Public API ────────────────────────────────────────────────────────────────

type EventDescriber = (e: AAuthEvent) => string | undefined

const narrations: Record<string, EventDescriber> = {
  signed_request: (e) => e.phase === 'start'
    ? `Agent → Resource: ${e.method ?? 'GET'} ${e.url} (HTTP-signed)`
    : `Resource responded ${e.status}`,
  challenge_received: (e) => `Resource returned 401 with AAuth challenge (requirement=${e.requirement})`,
  ps_metadata_request: (e) => e.phase === 'start'
    ? `Agent → Person Server: GET ${e.url}`
    : `Person Server metadata received (${e.status})`,
  ps_token_request: (e) => e.phase === 'start'
    ? `Agent → Person Server: POST ${e.url}`
    : `Person Server responded ${e.status}`,
  ps_consent_pending: () => 'Person Server returned 202 — user consent required',
  consent_prompt: (e) => `Open ${e.url} in your browser to approve (code: ${e.code})`,
  consent_poll: (e) => e.phase === 'start' ? 'Polling Person Server' : `Long-poll result: ${e.status}`,
  consent_resolved: (e) => `Consent resolved (status=${e.status})`,
  auth_token_received: (e) => `Person Server issued auth_token (expires in ${e.expiresIn}s)`,
  retry_with_auth_token: (e) => e.phase === 'start'
    ? `Agent → Resource: retrying ${e.url} signed with auth_token`
    : `Resource responded ${e.status}`,
}

// Long-form per-step prose explaining what's happening at the protocol level.
// Single source of truth for both --log (pretty CLI rendering) and --jsonl
// (machine-readable events). Each function returns a paragraph (no embedded
// newlines); the CLI word-wraps for terminal display, JSON consumers can
// reflow as they see fit. Disambiguated by phase/status when one step has
// multiple narrative outcomes (e.g., ps_token_request:done is 200 for warm
// path, 202 for cold).
const descriptions: Record<string, EventDescriber> = {
  signed_request: (e) => e.phase === 'start'
    ? "We sign an HTTP request with the agent's keypair and call the resource. The Signature-Key header carries the agent_token so the resource can verify the signature against the agent's public key."
    : e.status === 401
      ? "The resource verified the signature, but the agent isn't carrying an auth_token for this call. It mints a resource_token bound to the agent's public-key thumbprint and tells us to exchange it at the Person Server."
      : undefined,
  ps_metadata_request: (e) => e.phase === 'start'
    ? "We fetch the Person Server's well-known metadata to find the token endpoint we'll POST the resource_token to."
    : undefined,
  ps_token_request: (e) => e.phase === 'start'
    ? 'We POST the resource_token to the token endpoint we just discovered, signed with the same agent key as the initial call.'
    : e.status === 202
      ? "The PS recognised the agent and the resource_token, but the user has not yet consented to this agent acting on their behalf. It deferred — returning a URL and a short code the user must approve, plus a Location to long-poll."
      : e.status === 200
        ? "The PS recognised the agent and saw that the user has already consented to this agent + scope combination. It issued an auth_token directly — no 202, no consent screen, no long-poll."
        : undefined,
  consent_prompt: () =>
    "The user opens the consent screen, signs in to the Person Server, sees what scopes this agent is requesting, and approves. AAuth's consent always happens at the user's PS — never at the resource and never at the agent.",
  auth_token_received: () =>
    "The PS issued an auth_token. It's bound to the agent's key, scoped only to what the user granted, and carries identity claims released by the openid + profile scopes (if requested).",
  retry_with_auth_token: (e) => e.phase === 'start'
    ? 'Same signature scheme as the initial call, but the Signature-Key now carries the auth_token instead of the agent_token.'
    : e.status === 200
      ? "The resource verifies the HTTP signature against the auth_token's cnf.jwk, confirms the PS issued the token (using a cached copy of the PS's JWKS), checks the scope covers this endpoint, and returns the data."
      : undefined,
}

function formatNdjson(event: AAuthEvent): string {
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

// Look up a description for a synthetic event shape — used by the CLI
// pretty-printer so both --log and --jsonl read from the same map.
function describe(step: string, phase: 'start' | 'done' | 'info', status?: number): string | undefined {
  const e: AAuthEvent = { step, phase, ...(status !== undefined ? { status } : {}) }
  return descriptions[step]?.(e)
}

export interface LogHandle {
  onEvent: OnEvent
  finish: () => void
}

export type LogMode = 'pretty' | 'jsonl'

/**
 * Build a stream-aware fetch event handler.
 *
 * mode='pretty':  collects events, renders the human-readable step cards
 *                 (Already-set-up + This-call + numbered steps + closer)
 * mode='jsonl':   emits each event as one JSON object per line on stderr.
 *                 Each line carries `narration` (short) and `description`
 *                 (paragraph) fields so machine + AI consumers get the
 *                 same prose --log shows.
 */
export function buildLogEmitter(
  mode: LogMode | undefined,
  context: { url?: string; agentUrl?: string; personServer?: string } = {},
): LogHandle | undefined {
  if (!mode) return undefined

  if (mode === 'jsonl') {
    return {
      onEvent: (event: AAuthEvent) => process.stderr.write(formatNdjson(event)),
      finish: () => {},
    }
  }

  // TTY: write preamble eagerly, then collect events and render on finish.
  let preamblePrinted = false
  const state = newState()

  function printPreamble() {
    if (preamblePrinted) return
    preamblePrinted = true
    process.stderr.write(renderAlreadySetUp(context.agentUrl))
    if (context.url) {
      process.stderr.write(renderThisCall(context.url, context.agentUrl, context.personServer))
    }
  }

  const onEvent: OnEvent = (event) => {
    printPreamble()
    switch (event.step) {
      case 'signed_request':
        if (event.phase === 'start') {
          state.step1.url = event.url as string | undefined
          state.step1.method = event.method as string | undefined
          state.step1.agentToken = event.agent_token as Record<string, unknown> | undefined
        } else if (event.phase === 'done') {
          state.step2.status = event.status as number | undefined
          state.step1.requestHeaders = event.request_headers as Record<string, string> | undefined
          const response = event.response as Record<string, unknown> | undefined
          const headers = response?.headers as Record<string, string> | undefined
          if (headers) {
            state.step2.aauthRequirement = headers['aauth-requirement']
          }
          if (typeof response?.body === 'string') {
            state.step2.responseBody = response.body
          }
        }
        break
      case 'challenge_received':
        state.step2.resourceToken = event.resourceToken as Record<string, unknown> | undefined
        break
      case 'ps_metadata_request':
        if (event.phase === 'start') {
          state.step3.url = event.url as string | undefined
        } else if (event.phase === 'done') {
          state.step3.status = event.status as number | undefined
          state.step3.requestHeaders = event.request_headers as Record<string, string> | undefined
          const response = event.response as Record<string, unknown> | undefined
          if (typeof response?.body === 'string') {
            try { state.step3.body = JSON.parse(response.body) } catch { state.step3.responseBody = response.body }
          }
        }
        break
      case 'ps_token_request':
        if (event.phase === 'start') {
          state.step4.url = event.url as string | undefined
          state.step4.agentToken = event.agent_token as Record<string, unknown> | undefined
        } else if (event.phase === 'done') {
          state.step4.status = event.status as number | undefined
          state.step4.requestHeaders = event.request_headers as Record<string, string> | undefined
          state.step4.requestBody = event.request_body as string | undefined
          const response = event.response as Record<string, unknown> | undefined
          const headers = response?.headers as Record<string, string> | undefined
          if (headers) {
            state.step4.aauthRequirement = headers['aauth-requirement']
            state.step4.location = headers['location']
          }
          if (typeof response?.body === 'string') {
            state.step4.responseBody = response.body
          }
        }
        break
      case 'ps_consent_pending':
        state.consentRequired = true
        state.step5.startedAt = Date.now()
        break
      case 'consent_prompt':
        state.step5.interactionUrl = event.url as string | undefined
        state.step5.code = event.code as string | undefined
        break
      case 'consent_resolved':
        state.step5.resolvedAt = Date.now()
        break
      case 'auth_token_received':
        state.step6.authToken = event.authToken as Record<string, unknown> | undefined
        state.step6.expiresIn = event.expiresIn as number | undefined
        break
      case 'retry_with_auth_token':
        if (event.phase === 'start') {
          state.step8.url = event.url as string | undefined
          state.step8.method = (event.method as string | undefined) ?? 'GET'
          state.step8.authToken = event.auth_token as Record<string, unknown> | undefined
        } else if (event.phase === 'done') {
          state.step9.status = event.status as number | undefined
          state.step8.requestHeaders = event.request_headers as Record<string, string> | undefined
        }
        break
    }
  }

  function finish() {
    if (!preamblePrinted) return
    // Only render the flow if we actually saw a signed request
    if (state.step1.url) {
      process.stderr.write(renderColdFlow(state))
      process.stderr.write(renderCloser(state.consentRequired))
    }
  }

  return { onEvent, finish }
}

export function logEvent(enabled: boolean, event: AAuthEvent): void {
  if (!enabled) return
  buildLogEmitter('jsonl')?.onEvent(event)
}
