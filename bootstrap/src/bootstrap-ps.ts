import { setAgentConfig, getAgentConfig } from '@aauth/local-keys'
import type { OnBootstrapEvent } from './log.js'

export interface BootstrapPSOptions {
  agentUrl: string
  personServerUrl: string
  local?: string
  onEvent?: OnBootstrapEvent
}

interface PSMetadata {
  issuer: string
  token_endpoint: string
  jwks_uri: string
  interaction_endpoint?: string
}

/**
 * Configure an agent with a person server.
 *
 * Per draft-hardt-aauth-bootstrap §Self-Hosted Enrollment, publication of the
 * JWKS is the enrollment — there is no separate enrollment step. The PS
 * binding to a person happens lazily on the agent's first /aauth/token call,
 * per draft-hardt-oauth-aauth-protocol §Agent-Person Binding.
 *
 * This function:
 * 1. Fetches and validates PS metadata
 * 2. Persists agentId + personServerUrl to ~/.aauth/config.json
 *
 * No network registration call is made; signAgentToken reads personServerUrl
 * from config and includes it in the `ps` claim of every minted agent_token.
 */
export async function bootstrapWithPS(options: BootstrapPSOptions): Promise<void> {
  const { agentUrl, personServerUrl, local = 'local', onEvent } = options

  const metadata = await fetchPSMetadata(personServerUrl, onEvent)

  if (!metadata.issuer) {
    throw new Error('PS metadata missing required field: issuer')
  }
  if (!metadata.token_endpoint) {
    throw new Error('PS metadata missing required field: token_endpoint')
  }
  if (!metadata.jwks_uri) {
    throw new Error('PS metadata missing required field: jwks_uri')
  }

  const normalisedIssuer = metadata.issuer.replace(/\/$/, '')
  const normalisedUrl = personServerUrl.replace(/\/$/, '')
  if (normalisedIssuer !== normalisedUrl) {
    throw new Error(
      `PS issuer (${metadata.issuer}) does not match URL (${personServerUrl})`,
    )
  }
  onEvent?.({ step: 'ps_metadata_validated', phase: 'info' })

  const agentId = `aauth:${local}@${new URL(agentUrl).hostname}`
  const existing = getAgentConfig(agentUrl)
  setAgentConfig(agentUrl, {
    ...(existing ?? { keys: {} }),
    agentId,
    personServerUrl,
  })
  onEvent?.({ step: 'agent_config_persisted', phase: 'info', agentId, personServerUrl })
}

async function fetchPSMetadata(personServerUrl: string, onEvent?: OnBootstrapEvent): Promise<PSMetadata> {
  const url = `${personServerUrl.replace(/\/$/, '')}/.well-known/aauth-person.json`
  onEvent?.({ step: 'ps_metadata_request', phase: 'start', url })
  const response = await fetch(url)
  onEvent?.({ step: 'ps_metadata_request', phase: 'done', status: response.status })
  if (!response.ok) {
    throw new Error(`Failed to fetch PS metadata at ${url}: ${response.status}`)
  }
  return await response.json() as PSMetadata
}
