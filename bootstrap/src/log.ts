export interface BootstrapEvent {
  step: string
  phase: 'start' | 'done' | 'info'
  [key: string]: unknown
}

export type OnBootstrapEvent = (event: BootstrapEvent) => void

type Narration = (e: BootstrapEvent) => string | undefined

const narrations: Record<string, Narration> = {
  backend_discovery: (e) => e.phase === 'start'
    ? 'Discovering available key backends on this machine'
    : `Found ${(e.backends as unknown[] | undefined)?.length ?? 0} backend(s)`,

  key_generation: (e) => e.phase === 'start'
    ? `Generating ${e.algorithm} key on ${e.backend} backend`
    : `Generated key — kid ${e.kid}`,

  ps_metadata_request: (e) => e.phase === 'start'
    ? `Agent → Person Server: GET ${e.url}`
    : `Person Server metadata received (${e.status})`,

  ps_metadata_validated: () =>
    'Person Server metadata validated (issuer, token_endpoint, jwks_uri present and consistent)',

  agent_config_persisted: (e) =>
    `Agent configured: agentId=${e.agentId}, personServer=${e.personServerUrl}`,

  bootstrap_started: (e) =>
    `Configuring ${e.agentUrl} with person server ${e.personServerUrl}`,

  bootstrap_complete: () =>
    'Person server configured. Person binding will happen on the agent\'s first authorized request.',

  sign_token: (e) => e.phase === 'start'
    ? `Signing agent_token for ${e.agentId} (lifetime ${e.lifetime}s)`
    : 'Agent token signed (decoded payload included)',

  backends_discovered: (e) => {
    const list = (e.backends as Array<{ backend: string }> | undefined)?.map(b => b.backend).join(', ') || '(none)'
    return `Discovered key backends on this machine: ${list}`
  },

  agents_listed: (e) =>
    `Read ~/.aauth/config.json — ${(e.agents as string[] | undefined)?.length ?? 0} configured agent(s)`,

  keychain_scanned: (e) =>
    `Scanned OS keychain — ${(e.urls as string[] | undefined)?.length ?? 0} agent URL(s) with software keys`,
}

// Decoded-JWT-payload fields worth pretty-printing in TTY mode.
const PAYLOAD_KEYS = ['agent_token', 'agentToken', 'decoded']

function formatPretty(event: BootstrapEvent): string {
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

function formatNdjson(event: BootstrapEvent): string {
  const narration = narrations[event.step]?.(event)
  const line = narration ? { ...event, narration } : event
  return JSON.stringify(line) + '\n'
}

export function buildLogEmitter(enabled: boolean): OnBootstrapEvent | undefined {
  if (!enabled) return undefined
  const pretty = process.stderr.isTTY === true
  return (event: BootstrapEvent) => {
    process.stderr.write(pretty ? formatPretty(event) : formatNdjson(event))
  }
}
