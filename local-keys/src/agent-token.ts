import { createHash, randomUUID } from 'node:crypto'
import { importJWK, SignJWT, generateKeyPair, exportJWK } from 'jose'
import { readKeychain } from './keychain.js'
import { getAgentConfig } from './config.js'
import { getBackend } from './backends/index.js'
import { resolveKey } from './resolve-key.js'
import { publicJwkWithAlg, normalizeAlgId } from './jwk-alg.js'
import type { SignAgentTokenOptions, AgentTokenResult, ResolvedKey } from './types.js'

/**
 * Generate the ephemeral key the agent token confirms in `cnf.jwk`.
 *
 * Both JWKs carry a fully-specified `alg` (RFC 9864): `@hellocoop/httpsig` 2.0
 * (signature-key -08) takes the signing algorithm from the JWK's `alg` and
 * rejects the polymorphic `EdDSA`, and AAuth -11 §Signature Algorithms requires
 * the same of every key it conveys. `exportJWK` sets no `alg` at all, so it is
 * derived from the key material here.
 */
async function generateEphemeralKey(alg: 'Ed25519' | 'ES256') {
  // jose 6: keys are non-extractable by default, and these are exported to JWK below
  const opts = alg === 'ES256' ? { crv: 'P-256', extractable: true } : { crv: 'Ed25519', extractable: true }
  const { publicKey, privateKey } = await generateKeyPair(alg, opts)
  return {
    privateJwk: publicJwkWithAlg(await exportJWK(privateKey), alg, 'ephemeral private key'),
    publicJwk: publicJwkWithAlg(await exportJWK(publicKey), alg, 'ephemeral public key'),
  }
}

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
  const { agentUrl, sub, lifetime = 3600, personServerUrl: psOverride } = options
  const agentConfig = getAgentConfig(agentUrl)
  const personServerUrl = psOverride ?? agentConfig?.personServerUrl

  const resolved = await resolveKey(agentUrl)

  // Software keys in the OS keychain sign via jose (they have the private JWK)
  if (resolved.backend === 'software') {
    return signWithSoftwareKey(agentUrl, sub, lifetime, resolved.kid, personServerUrl)
  }

  // Hardware keys sign via raw hash
  return signWithHardwareKey(resolved, { agentUrl, sub, lifetime, personServerUrl })
}

async function signWithSoftwareKey(
  agentUrl: string,
  sub: string,
  lifetime: number,
  kid: string,
  personServerUrl?: string,
): Promise<AgentTokenResult> {
  const data = readKeychain(agentUrl)
  if (!data) {
    throw new Error(`No software keys found in keychain for ${agentUrl}`)
  }

  const storedJwk = data.keys[kid] || data.keys[data.current]
  if (!storedJwk) {
    throw new Error(`Key ${kid} not found in keychain for ${agentUrl}`)
  }

  // Keys minted before AAuth -11 sit in the keychain with `alg: "EdDSA"`.
  // Derive the fully-specified alg from the key material so neither the JWT
  // header nor anything downstream ever sees the polymorphic identifier.
  const rootJwk = publicJwkWithAlg(storedJwk, undefined, `keychain key ${kid}`)
  const actualKid = rootJwk.kid || kid
  const alg = rootJwk.alg as string

  const ephAlg = alg === 'ES256' ? 'ES256' : 'Ed25519'
  const { privateJwk: ephPrivJwk, publicJwk: ephPubJwk } = await generateEphemeralKey(ephAlg)

  const rootKey = await importJWK(rootJwk, alg)
  const now = Math.floor(Date.now() / 1000)

  const claims: Record<string, unknown> = {
    iss: agentUrl,
    dwk: 'aauth-agent.json',
    sub,
    jti: randomUUID(),
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
    sub: string
    lifetime: number
    personServerUrl?: string
  },
): Promise<AgentTokenResult> {
  const { agentUrl, sub, lifetime, personServerUrl } = opts
  const driver = getBackend(resolved.backend)

  // A pre-11 config entry can still say "EdDSA"; never put that in a header.
  const alg = normalizeAlgId(resolved.algorithm)

  // Ephemeral signing key — always software, always ES256 or Ed25519
  const ephAlg = alg === 'ES256' || alg === 'RS256' ? 'ES256' : 'Ed25519'
  const { privateJwk: ephPrivJwk, publicJwk: ephPubJwk } = await generateEphemeralKey(ephAlg)

  const now = Math.floor(Date.now() / 1000)

  const header: Record<string, string> = {
    alg,
    typ: 'aa-agent+jwt',
    kid: resolved.kid,
  }

  const payload: Record<string, unknown> = {
    iss: agentUrl,
    dwk: 'aauth-agent.json',
    sub,
    jti: randomUUID(),
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
