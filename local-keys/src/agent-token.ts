import { createHash } from 'node:crypto'
import { importJWK, SignJWT, generateKeyPair, exportJWK } from 'jose'
import type { JWK } from 'jose'
import { readKeychain } from './keychain.js'
import { getAgentConfig } from './config.js'
import { getBackend } from './backends/index.js'
import { resolveKey } from './resolve-key.js'
import type { SignAgentTokenOptions, AgentTokenResult, ResolvedKey } from './types.js'

/**
 * Sign an agent token for the given agent URL.
 *
 * Resolves the signing key automatically:
 * 1. Fetches {agentUrl}/.well-known/aauth-agent.json → JWKS
 * 2. Matches JWKS against local hardware + software keys
 * 3. Falls back to config, then keychain, then any available hardware key
 * 4. Prefers hardware keys over software keys
 */
export async function signAgentToken(
  options: SignAgentTokenOptions,
): Promise<AgentTokenResult> {
  const { agentUrl, delegateUrl, lifetime = 3600 } = options
  const agentConfig = getAgentConfig(agentUrl)
  const personServerUrl = agentConfig?.personServerUrl

  const resolved = await resolveKey(agentUrl)

  // Software keys in the OS keychain sign via jose (they have the private JWK)
  if (resolved.backend === 'software') {
    return signWithSoftwareKey(agentUrl, delegateUrl, lifetime, resolved.kid, personServerUrl)
  }

  // Hardware keys sign via raw hash
  return signWithHardwareKey(resolved, { agentUrl, delegateUrl, lifetime, personServerUrl })
}

async function signWithSoftwareKey(
  agentUrl: string,
  delegateUrl: string,
  lifetime: number,
  kid: string,
  personServerUrl?: string,
): Promise<AgentTokenResult> {
  const data = readKeychain(agentUrl)
  if (!data) {
    throw new Error(`No software keys found in keychain for ${agentUrl}`)
  }

  const rootJwk = data.keys[kid] || data.keys[data.current]
  if (!rootJwk) {
    throw new Error(`Key ${kid} not found in keychain for ${agentUrl}`)
  }

  const actualKid = rootJwk.kid || kid
  const alg = rootJwk.alg || (rootJwk.crv === 'P-256' ? 'ES256' : 'EdDSA')

  const ephAlg = alg === 'ES256' ? 'ES256' : 'EdDSA'
  const ephOpts = alg === 'ES256' ? { crv: 'P-256' } : { crv: 'Ed25519' }
  const { publicKey: ephPub, privateKey: ephPriv } = await generateKeyPair(ephAlg, ephOpts)
  const ephPrivJwk = await exportJWK(ephPriv)
  const ephPubJwk = await exportJWK(ephPub)

  const rootKey = await importJWK(rootJwk, alg)
  const now = Math.floor(Date.now() / 1000)

  const claims: Record<string, unknown> = {
    iss: agentUrl,
    dwk: 'aauth-agent.json',
    sub: delegateUrl,
    cnf: { jwk: ephPubJwk },
    iat: now,
    exp: now + lifetime,
  }
  if (personServerUrl) claims.ps = personServerUrl

  const jwt = await new SignJWT(claims)
    .setProtectedHeader({ alg, typ: 'aa-agent+jwt', kid: actualKid })
    .sign(rootKey)

  return {
    signingKey: ephPrivJwk,
    signatureKey: { type: 'jwt', jwt },
  }
}

async function signWithHardwareKey(
  resolved: ResolvedKey,
  opts: {
    agentUrl: string
    delegateUrl: string
    lifetime: number
    personServerUrl?: string
  },
): Promise<AgentTokenResult> {
  const { agentUrl, delegateUrl, lifetime, personServerUrl } = opts
  const driver = getBackend(resolved.backend)

  const alg = resolved.algorithm === 'RS256' ? 'RS256' : resolved.algorithm

  // Ephemeral delegate key — always software, always ES256 or EdDSA
  const ephAlg = alg === 'RS256' ? 'ES256' : alg
  const ephOpts = ephAlg === 'ES256' ? { crv: 'P-256' } : { crv: 'Ed25519' }
  const { publicKey: ephPub, privateKey: ephPriv } = await generateKeyPair(ephAlg, ephOpts)
  const ephPrivJwk = await exportJWK(ephPriv)
  const ephPubJwk = await exportJWK(ephPub)

  const now = Math.floor(Date.now() / 1000)

  const header: Record<string, string> = {
    alg,
    typ: 'aa-agent+jwt',
    kid: resolved.kid,
  }

  const payload: Record<string, unknown> = {
    iss: agentUrl,
    dwk: 'aauth-agent.json',
    sub: delegateUrl,
    cnf: { jwk: ephPubJwk },
    iat: now,
    exp: now + lifetime,
  }
  if (personServerUrl) payload.ps = personServerUrl

  const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64url')
  const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64url')
  const signingInput = `${headerB64}.${payloadB64}`

  const hash = createHash('sha256').update(signingInput).digest()
  const { signature } = await driver.signHash(resolved.keyId, hash)
  const sigB64 = Buffer.from(signature).toString('base64url')

  return {
    signingKey: ephPrivJwk,
    signatureKey: { type: 'jwt', jwt: `${signingInput}.${sigB64}` },
  }
}
