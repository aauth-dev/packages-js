import { createHash, randomUUID } from 'node:crypto'
import { generateKeyPair, exportJWK } from 'jose'
import { fetch as httpSigFetch } from '@hellocoop/httpsig'
import { pollDeferred } from '@aauth/mcp-agent'
import { setPersonServer, getAgentConfig, setAgentConfig, resolveKey, getBackend, readKeychain } from '@aauth/local-keys'
import type { FetchLike } from '@aauth/mcp-agent'

export interface BootstrapPSOptions {
  agentUrl: string
  personServerUrl: string
  local?: string  // Local part of agent identifier (default: "local")
  loginHint?: string
  domainHint?: string
  tenant?: string
  onInteraction: (url: string, code: string) => void
}

interface PSMetadata {
  bootstrap_endpoint: string
  token_endpoint: string
  interaction_endpoint?: string
  jwks_uri: string
}

/**
 * Bootstrap an agent with a person server.
 *
 * 1. Fetch PS metadata → bootstrap_endpoint
 * 2. Generate ephemeral keypair
 * 3. POST to PS /bootstrap with hwk signature
 * 4. Handle 202 interaction (user consent in browser)
 * 5. Get bootstrap_token from PS
 * 6. Sign agent token locally (with PS override)
 * 7. Announce to PS with agent token
 * 8. Store PS URL in config
 */
export async function bootstrapWithPS(options: BootstrapPSOptions): Promise<void> {
  const { agentUrl, personServerUrl, local = 'local', loginHint, domainHint, tenant, onInteraction } = options

  // 1. Fetch PS metadata
  const metadata = await fetchPSMetadata(personServerUrl)
  if (!metadata.bootstrap_endpoint) {
    throw new Error('Person server metadata missing bootstrap_endpoint')
  }

  // 2. Generate ephemeral keypair for hwk signing
  const { publicKey: ephPub, privateKey: ephPriv } = await generateKeyPair('ES256', { crv: 'P-256' })
  const ephPrivJwk = await exportJWK(ephPriv)
  const ephPubJwk = await exportJWK(ephPub)

  // Build signed fetch for hwk scheme
  const hwkFetch: FetchLike = async (url, init) => {
    const response = await httpSigFetch(url, {
      ...init,
      signingKey: ephPrivJwk,
      signatureKey: { type: 'hwk' },
    })
    return response as Response
  }

  // 3. POST to PS /bootstrap
  const body: Record<string, string> = {
    agent_server: agentUrl,
  }
  if (loginHint) body.login_hint = loginHint
  if (domainHint) body.domain_hint = domainHint
  if (tenant) body.tenant = tenant

  const bootstrapResponse = await hwkFetch(metadata.bootstrap_endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'AAuth-Capabilities': 'interaction',
    },
    body: JSON.stringify(body),
  })

  if (bootstrapResponse.status !== 202) {
    const text = await bootstrapResponse.text()
    throw new Error(`PS bootstrap request failed with status ${bootstrapResponse.status}: ${text}`)
  }

  // 4. Extract location and interaction info
  const locationUrl = bootstrapResponse.headers.get('location')
  if (!locationUrl) {
    throw new Error('PS bootstrap 202 response missing Location header')
  }

  const resolvedLocation = resolveUrl(personServerUrl, locationUrl)

  let interactionUrl: string | undefined
  let interactionCode: string | undefined
  const aauthHeader = bootstrapResponse.headers.get('aauth-requirement')
  if (aauthHeader) {
    const match = aauthHeader.match(/url="([^"]+)"/)
    const codeMatch = aauthHeader.match(/code="([^"]+)"/)
    if (match) interactionUrl = match[1]
    if (codeMatch) interactionCode = codeMatch[1]
  }

  // 5. Poll for bootstrap_token
  const result = await pollDeferred({
    signedFetch: hwkFetch,
    locationUrl: resolvedLocation,
    interactionUrl,
    interactionCode,
    onInteraction,
  })

  if (result.response.status !== 200) {
    const errorMsg = result.error?.error_description || result.error?.error || `status ${result.response.status}`
    throw new Error(`PS bootstrap polling failed: ${errorMsg}`)
  }

  const responseBody = await result.response.json() as Record<string, unknown>
  const bootstrapToken = responseBody.bootstrap_token
  if (!bootstrapToken || typeof bootstrapToken !== 'string') {
    throw new Error('PS bootstrap response missing bootstrap_token')
  }

  // 6. Sign agent token using the SAME ephemeral key from the bootstrap request.
  //    The PS matches the announcement to the bootstrap record via this key.
  const domain = new URL(agentUrl).hostname
  const agentTokenJwt = await buildAgentToken({
    agentUrl,
    sub: `aauth:${local}@${domain}`,
    personServerUrl,
    ephPubJwk,
  })

  // 7. Announce to PS — POST with agent token, signed with bootstrap ephemeral key
  const announceResponse = await httpSigFetch(metadata.bootstrap_endpoint, {
    method: 'POST',
    signingKey: ephPrivJwk,
    signatureKey: { type: 'jwt', jwt: agentTokenJwt },
  }) as Response

  if (announceResponse.status !== 204 && announceResponse.status !== 200) {
    const text = await announceResponse.text()
    throw new Error(`PS bootstrap announcement failed with status ${announceResponse.status}: ${text}`)
  }

  // 8. Store agent identifier and PS URL in config
  const agentId = `aauth:${local}@${domain}`
  const existing = getAgentConfig(agentUrl)
  setAgentConfig(agentUrl, { ...existing || { keys: {} }, agentId, personServerUrl })
}

/**
 * Build an agent token signed by the root key, with the bootstrap ephemeral key as cnf.
 * This ensures the announcement is tied to the same ephemeral key used in the bootstrap request.
 */
async function buildAgentToken(opts: {
  agentUrl: string
  sub: string
  personServerUrl: string
  ephPubJwk: unknown
}): Promise<string> {
  const { agentUrl, sub, personServerUrl, ephPubJwk } = opts

  const resolved = await resolveKey(agentUrl)
  const now = Math.floor(Date.now() / 1000)

  const header: Record<string, string> = {
    alg: resolved.algorithm === 'RS256' ? 'RS256' : resolved.algorithm,
    typ: 'aa-agent+jwt',
    kid: resolved.kid,
  }

  const payload: Record<string, unknown> = {
    iss: agentUrl,
    dwk: 'aauth-agent.json',
    sub,
    jti: randomUUID(),
    cnf: { jwk: ephPubJwk },
    ps: personServerUrl,
    iat: now,
    exp: now + 300,
  }

  const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64url')
  const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64url')
  const signingInput = `${headerB64}.${payloadB64}`

  if (resolved.backend === 'software') {
    // Software keys: import private key from keychain and sign with jose
    const { importJWK, SignJWT } = await import('jose')
    const data = readKeychain(agentUrl)
    if (!data) throw new Error(`No software keys found in keychain for ${agentUrl}`)
    const rootJwk = data.keys[resolved.kid] || data.keys[data.current]
    if (!rootJwk) throw new Error(`Key ${resolved.kid} not found in keychain`)
    const alg = rootJwk.alg || (rootJwk.crv === 'P-256' ? 'ES256' : 'EdDSA')
    const rootKey = await importJWK(rootJwk, alg)
    const jwt = await new SignJWT(payload)
      .setProtectedHeader({ alg, typ: 'aa-agent+jwt', kid: rootJwk.kid || resolved.kid })
      .sign(rootKey)
    return jwt
  }

  // Hardware keys: sign hash via backend driver
  const driver = getBackend(resolved.backend)
  const hash = createHash('sha256').update(signingInput).digest()
  const { signature } = await driver.signHash(resolved.keyId, hash)
  const sigB64 = Buffer.from(signature).toString('base64url')
  return `${signingInput}.${sigB64}`
}

async function fetchPSMetadata(personServerUrl: string): Promise<PSMetadata> {
  const url = `${personServerUrl.replace(/\/$/, '')}/.well-known/aauth-person.json`
  const response = await fetch(url)
  if (!response.ok) {
    throw new Error(`Failed to fetch PS metadata at ${url}: ${response.status}`)
  }
  return await response.json() as PSMetadata
}

function resolveUrl(base: string, url: string): string {
  if (url.startsWith('http://') || url.startsWith('https://')) {
    return url
  }
  return new URL(url, base).href
}
