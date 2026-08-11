/**
 * TEST-ONLY STUB of `@aauth/protocol`.
 *
 * WP-1 builds the real package in a parallel worktree that this one cannot see.
 * This file implements the exported surface pinned in AAUTH-11-PACKAGE-CONTRACT.md
 * exactly, so that this package's tests can run before integration.
 *
 * It is NOT shipped: `tsconfig.json` only includes `src`, and `files` only
 * publishes `dist`. Integration MUST delete this directory and
 * `mcp-server/vitest.config.ts` once `@aauth/protocol` resolves for real.
 */

// ---------- AAuth-Requirement ----------

export type RequirementValue =
  | 'agent-token' | 'person-token' | 'auth-token'
  | 'approval' | 'interaction' | 'clarification' | 'claims'

export interface AAuthChallenge {
  requirement: RequirementValue
  resourceToken?: string
  url?: string
  code?: string
}

const REQUIREMENT_VALUES: readonly string[] = [
  'agent-token', 'person-token', 'auth-token',
  'approval', 'interaction', 'clarification', 'claims',
]

export class UnsupportedRequirementError extends Error {
  readonly value: string
  constructor(value: string) {
    super(`Unsupported AAuth requirement: ${value}`)
    this.name = 'UnsupportedRequirementError'
    this.value = value
  }
}

export function buildRequirementHeader(challenge: AAuthChallenge): string {
  const { requirement } = challenge
  if (!REQUIREMENT_VALUES.includes(requirement)) {
    throw new UnsupportedRequirementError(requirement)
  }
  if (requirement === 'auth-token') {
    if (!challenge.resourceToken) throw new Error('auth-token requires resourceToken')
    return `requirement=auth-token; resource-token="${challenge.resourceToken}"`
  }
  if (requirement === 'interaction') {
    if (!challenge.url || !challenge.code) throw new Error('interaction requires url and code')
    return `requirement=interaction; url="${challenge.url}"; code="${challenge.code}"`
  }
  return `requirement=${requirement}`
}

export function parseRequirementHeader(headerValue: string): AAuthChallenge {
  const parts = headerValue.split(';').map(s => s.trim())
  const first = parts[0] ?? ''
  const value = first.startsWith('requirement=')
    ? first.slice('requirement='.length).replace(/^"|"$/g, '')
    : ''
  if (!REQUIREMENT_VALUES.includes(value)) {
    throw new UnsupportedRequirementError(value)
  }
  const challenge: AAuthChallenge = { requirement: value as RequirementValue }
  for (const part of parts.slice(1)) {
    const m = part.match(/^([a-z-]+)=(?:"([^"]*)"|(.*))$/)
    if (!m) continue
    const v = m[2] ?? m[3] ?? ''
    if (m[1] === 'resource-token') challenge.resourceToken = v
    if (m[1] === 'url') challenge.url = v
    if (m[1] === 'code') challenge.code = v
  }
  return challenge
}

// ---------- AAuth-Capabilities ----------

export type Capability = 'interaction' | 'clarification' | 'payment'

const CAPABILITIES: readonly string[] = ['interaction', 'clarification', 'payment']

export function buildCapabilitiesHeader(capabilities: string[]): string {
  return capabilities.join(', ')
}

export function parseCapabilitiesHeader(headerValue: string): string[] {
  return headerValue.split(',').map(s => s.trim()).filter(s => CAPABILITIES.includes(s))
}

// ---------- access_mode (N4) ----------

export type KnownAccessMode =
  | 'agent-token' | 'person-token' | 'session-token' | 'auth-token' | 'per-call'

export interface AgentSetup {
  hasPersonServer: boolean
}

export type AccessModePlan =
  | { kind: 'undeclared' }
  | { kind: 'satisfiable'; mode: KnownAccessMode }
  | { kind: 'unsatisfiable'; mode: KnownAccessMode; reason: string }

const KNOWN_MODES: readonly string[] = [
  'agent-token', 'person-token', 'session-token', 'auth-token', 'per-call',
]

export function planAccessMode(declared: string | undefined, setup: AgentSetup): AccessModePlan {
  if (!declared || !KNOWN_MODES.includes(declared)) return { kind: 'undeclared' }
  const mode = declared as KnownAccessMode
  const needsPs = mode === 'person-token' || mode === 'auth-token' || mode === 'per-call'
  if (needsPs && !setup.hasPersonServer) {
    return { kind: 'unsatisfiable', mode, reason: 'agent has no person server' }
  }
  return { kind: 'satisfiable', mode }
}

// ---------- constants ----------

export const TOKEN_TYP = {
  agent: 'aa-agent+jwt',
  person: 'aa-person+jwt',
  resource: 'aa-resource+jwt',
  auth: 'aa-auth+jwt',
} as const

export const DWK = {
  agent: 'aauth-agent.json',
  person: 'aauth-person.json',
  resource: 'aauth-resource.json',
  access: 'aauth-access.json',
} as const

export const SIGNING_ALG = 'Ed25519' as const

// ---------- JWT decoding (no verification) ----------

function b64urlToJson(segment: string): Record<string, unknown> {
  const b64 = segment.replace(/-/g, '+').replace(/_/g, '/')
  const pad = b64.length % 4 === 0 ? '' : '='.repeat(4 - (b64.length % 4))
  const bin = atob(b64 + pad)
  const bytes = Uint8Array.from(bin, c => c.charCodeAt(0))
  return JSON.parse(new TextDecoder().decode(bytes)) as Record<string, unknown>
}

export function decodeJwtHeader(jwt: string): Record<string, unknown> {
  const parts = jwt.split('.')
  if (parts.length !== 3) throw new Error('Invalid JWT')
  return b64urlToJson(parts[0])
}

export function decodeJwtPayload(jwt: string): Record<string, unknown> {
  const parts = jwt.split('.')
  if (parts.length !== 3) throw new Error('Invalid JWT')
  return b64urlToJson(parts[1])
}
