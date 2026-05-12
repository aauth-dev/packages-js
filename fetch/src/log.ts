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
    ? undefined
    : `Long-poll result: ${e.status}`,

  consent_resolved: (e) =>
    `Consent resolved (status=${e.status})`,

  auth_token_received: (e) =>
    `Person Server issued auth_token (expires in ${e.expiresIn}s)`,

  retry_with_auth_token: (e) => e.phase === 'start'
    ? `Agent → Resource: retrying ${e.url} signed with auth_token`
    : `Resource responded ${e.status}`,
}

export function buildLogEmitter(enabled: boolean): OnEvent | undefined {
  if (!enabled) return undefined
  return (event: AAuthEvent) => {
    const narration = narrations[event.step]?.(event)
    const line = narration ? { ...event, narration } : event
    process.stderr.write(JSON.stringify(line) + '\n')
  }
}

export function logEvent(enabled: boolean, event: AAuthEvent): void {
  if (!enabled) return
  buildLogEmitter(true)?.(event)
}
