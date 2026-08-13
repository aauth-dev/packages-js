import { setAgentConfig, getAgentConfig, writeCachedMetadata, parseMaxAge } from '@aauth/local-keys'

export interface BootstrapPSOptions {
  agentUrl: string
  personServerUrl: string
  local?: string
}

/**
 * Person server metadata, `/.well-known/aauth-person.json`
 * (draft-hardt-oauth-aauth-protocol §Person Server Metadata).
 *
 * Protocol -11 renamed `token_endpoint` to `auth_token_endpoint` and added
 * `person_token_endpoint`, REQUIRED of every PS.
 */
interface PSMetadata {
  issuer: string
  /** REQUIRED — renamed from `token_endpoint` in -11. */
  auth_token_endpoint: string
  /** REQUIRED, new in -11 — where the agent obtains a person token for a resource. */
  person_token_endpoint: string
  jwks_uri: string
  authorization_endpoint?: string
  mission_endpoint?: string
  permission_endpoint?: string
  audit_endpoint?: string
  interaction_endpoint?: string
  mission_control_endpoint?: string
  revocation_endpoint?: string
  /** The -10 name for `auth_token_endpoint`. Read only to explain the failure. */
  token_endpoint?: string
}

const REQUIRED_FIELDS = [
  'issuer',
  'auth_token_endpoint',
  'person_token_endpoint',
  'jwks_uri',
] as const

/**
 * Name every REQUIRED field the PS did not publish, or null if it published all
 * of them.
 *
 * Why a missing `person_token_endpoint` is fatal here rather than at first use:
 * under -11 the agent's first step at a resource it has not used is obtaining a
 * person token from its PS, so a PS that cannot issue one cannot serve this
 * agent at any resource. Binding to it would succeed and then fail on every call.
 */
function metadataError(metadata: PSMetadata, personServerUrl: string, metadataUrl: string): string | null {
  const missing = REQUIRED_FIELDS.filter((field) => !metadata[field])
  if (missing.length === 0) return null

  const label = missing.length === 1 ? 'field' : 'fields'
  let message =
    `PS metadata missing required ${label}: ${missing.join(', ')} — ` +
    `${personServerUrl} is not a conformant AAuth person server. See ${metadataUrl}.`

  if (missing.includes('auth_token_endpoint') && metadata.token_endpoint) {
    message +=
      ' It publishes `token_endpoint`, the AAuth -10 name for that field;' +
      ' -11 renamed it to `auth_token_endpoint`.'
  }
  if (missing.includes('person_token_endpoint')) {
    message +=
      ' Without `person_token_endpoint` it cannot issue person tokens, and obtaining a person' +
      " token is the agent's first step at a resource it has not used — so binding to this" +
      ' person server would succeed here and fail on every call. Bind one that publishes it.'
  }
  return message
}

/**
 * Bind an agent provider to a person server.
 *
 * Per draft-hardt-aauth-bootstrap §Self-Hosted Enrollment, publication of the
 * JWKS is the enrollment — there is no separate enrollment step. The PS
 * binding to a person happens lazily on the agent's first call to the PS —
 * under -11 that is the person token request it makes before its first call to
 * a resource — per draft-hardt-oauth-aauth-protocol §Agent-Person Binding.
 *
 * This function:
 * 1. Fetches and validates PS metadata — including that the PS publishes a
 *    `person_token_endpoint`, without which it cannot serve this agent at all
 * 2. Persists agentId + personServerUrl to ~/.aauth/config.json
 * 3. Caches the fetched PS metadata (public) to ~/.aauth/cache/ so fetch can
 *    skip the runtime /.well-known/aauth-person.json round-trip until it expires
 *
 * No network registration call is made; signAgentToken reads personServerUrl
 * from config and includes it in the `ps` claim of every minted agent_token.
 */
export async function bootstrapWithPS(options: BootstrapPSOptions): Promise<void> {
  const { agentUrl, personServerUrl, local = 'local' } = options

  const { metadata, cacheControl, metadataUrl } = await fetchPSMetadata(personServerUrl)

  const error = metadataError(metadata, personServerUrl.replace(/\/$/, ''), metadataUrl)
  if (error) {
    throw new Error(error)
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
): Promise<{ metadata: PSMetadata; cacheControl: string | null; metadataUrl: string }> {
  const url = `${personServerUrl.replace(/\/$/, '')}/.well-known/aauth-person.json`
  const response = await fetch(url)
  if (!response.ok) {
    throw new Error(`Failed to fetch PS metadata at ${url}: ${response.status}`)
  }
  const metadata = await response.json() as PSMetadata
  return { metadata, cacheControl: response.headers.get('cache-control'), metadataUrl: url }
}
