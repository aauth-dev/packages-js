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
}

export function buildLogEmitter(enabled: boolean): OnBootstrapEvent | undefined {
  if (!enabled) return undefined
  return (event: BootstrapEvent) => {
    const narration = narrations[event.step]?.(event)
    const line = narration ? { ...event, narration } : event
    process.stderr.write(JSON.stringify(line) + '\n')
  }
}
