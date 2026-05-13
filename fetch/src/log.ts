import type { AAuthEvent, OnEvent } from '@aauth/mcp-agent'

type Narration = (e: AAuthEvent) => string | undefined

const narrations: Record<string, Narration> = {
  signed_request: (e) => e.phase === 'start'
    ? `Agent → Resource: ${e.method ?? 'GET'} ${e.url} (HTTP-signed)`
    : `Resource responded ${e.status}`,

  challenge_received: (e) =>
    `Resource returned 401 with AAuth challenge (requirement=${e.requirement}). Resource token issued — agent will exchange it at the Person Server.`,

  r3_authorize_request: (e) => e.phase === 'start'
    ? `Agent → Resource: POST ${e.url} — requesting authorization for operations`
    : `Resource issued resource_token (${e.status})`,

  ps_metadata_request: (e) => e.phase === 'start'
    ? `Agent → Person Server: GET ${e.url}`
    : `Person Server metadata received (${e.status})`,

  ps_token_request: (e) => e.phase === 'start'
    ? `Agent → Person Server: POST ${e.url} — exchanging resource_token for auth_token`
    : `Person Server responded ${e.status}`,

  ps_consent_pending: () =>
    `Person Server returned 202 — user consent required. Waiting for approval.`,

  consent_prompt: (e) =>
    `Open ${e.url} in your browser to approve (code: ${e.code}).`,

  consent_poll: (e) => e.phase === 'start'
    ? `Polling Person Server for consent (iteration ${e.iteration})`
    : `Long-poll result: ${e.status}`,

  consent_resolved: (e) =>
    `Consent resolved (status=${e.status})`,

  auth_token_received: (e) =>
    `Person Server issued auth_token (expires in ${e.expiresIn}s)`,

  retry_with_auth_token: (e) => e.phase === 'start'
    ? `Agent → Resource: retrying ${e.url} signed with auth_token`
    : `Resource responded ${e.status}`,
}

// Decoded-JWT-payload fields worth pretty-printing in TTY mode.
const PAYLOAD_KEYS = ['agent_token', 'agentToken', 'resourceToken', 'authToken', 'auth_token']

function formatPretty(event: AAuthEvent): string {
  const narration = narrations[event.step]?.(event)
  const phaseTag = event.phase === 'info' ? '' : ` (${event.phase})`
  const lines: string[] = [`● ${event.step}${phaseTag}`]
  if (narration) lines.push(`  ${narration}`)
  for (const key of PAYLOAD_KEYS) {
    const value = event[key]
    if (value && typeof value === 'object') {
      lines.push(`  ${key}:`)
      const pretty = JSON.stringify(value, null, 2).split('\n').map(l => `    ${l}`).join('\n')
      lines.push(pretty)
    }
  }
  return lines.join('\n') + '\n\n'
}

function formatNdjson(event: AAuthEvent): string {
  const narration = narrations[event.step]?.(event)
  const line = narration ? { ...event, narration } : event
  return JSON.stringify(line) + '\n'
}

export function buildLogEmitter(enabled: boolean): OnEvent | undefined {
  if (!enabled) return undefined
  const pretty = process.stderr.isTTY === true
  return (event: AAuthEvent) => {
    process.stderr.write(pretty ? formatPretty(event) : formatNdjson(event))
  }
}

export function logEvent(enabled: boolean, event: AAuthEvent): void {
  if (!enabled) return
  buildLogEmitter(true)?.(event)
}
