import { setAgentConfig, getAgentConfig, writeCachedMetadata, parseMaxAge } from '@aauth/local-keys'

export interface BootstrapPSOptions {
  agentUrl: string
  personServerUrl: string
  local?: string
}

interface PSMetadata {
  issuer: string
  token_endpoint: string
  jwks_uri: string
  authorization_endpoint?: string
  interaction_endpoint?: string
}

/**
 * Bind an agent provider to a person server.
 *
 * Per draft-hardt-aauth-bootstrap §Self-Hosted Enrollment, publication of the
 * JWKS is the enrollment — there is no separate enrollment step. The PS
 * binding to a person happens lazily on the agent's first /aauth/token call,
 * per draft-hardt-oauth-aauth-protocol §Agent-Person Binding.
 *
 * This function:
 * 1. Fetches and validates PS metadata
 * 2. Persists agentId + personServerUrl to ~/.aauth/config.json
 * 3. Caches the fetched PS metadata (public) to ~/.aauth/cache/ so fetch can
 *    skip the runtime /.well-known/aauth-person.json round-trip until it expires
 *
 * No network registration call is made; signAgentToken reads personServerUrl
 * from config and includes it in the `ps` claim of every minted agent_token.
 */
export async function bootstrapWithPS(options: BootstrapPSOptions): Promise<void> {
  const { agentUrl, personServerUrl, local = 'local' } = options

  const { metadata, cacheControl } = await fetchPSMetadata(personServerUrl)

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

  const agentId = `aauth:${local}@${new URL(agentUrl).hostname}`
  const existing = getAgentConfig(agentUrl)
  setAgentConfig(agentUrl, {
    ...(existing ?? { keys: {} }),
    agentId,
    personServerUrl,
  })

  // Cache the PS metadata we just fetched (public, not a secret) so fetch can
  // skip the runtime /.well-known/aauth-person.json round-trip. Honour the
  // server's Cache-Control: max-age if it sent one, else the cache's default TTL.
  writeCachedMetadata(
    new URL(personServerUrl).hostname,
    metadata,
    parseMaxAge(cacheControl),
  )
}

async function fetchPSMetadata(
  personServerUrl: string,
): Promise<{ metadata: PSMetadata; cacheControl: string | null }> {
  const url = `${personServerUrl.replace(/\/$/, '')}/.well-known/aauth-person.json`
  const response = await fetch(url)
  if (!response.ok) {
    throw new Error(`Failed to fetch PS metadata at ${url}: ${response.status}`)
  }
  const metadata = await response.json() as PSMetadata
  return { metadata, cacheControl: response.headers.get('cache-control') }
}
