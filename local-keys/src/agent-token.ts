import { importJWK, SignJWT, generateKeyPair, exportJWK } from 'jose'
import type { JWK } from 'jose'
import { readKeychain } from './keychain.js'
import type { SignAgentTokenOptions, AgentTokenResult } from './types.js'

export async function signAgentToken(
  options: SignAgentTokenOptions,
): Promise<AgentTokenResult> {
  const { agentUrl, delegateUrl, lifetime = 3600 } = options

  const data = readKeychain(agentUrl)
  if (!data) {
    throw new Error(`No keys found in keychain for ${agentUrl}`)
  }

  const kid = data.current
  const rootJwk = data.keys[kid]
  if (!rootJwk) {
    throw new Error(`Current key ${kid} not found in keychain`)
  }

  // Generate ephemeral key pair for the delegate
  const { publicKey: ephPub, privateKey: ephPriv } = await generateKeyPair(
    'EdDSA',
    { crv: 'Ed25519' },
  )
  const ephPrivJwk = await exportJWK(ephPriv)
  const ephPubJwk = await exportJWK(ephPub)

  // Sign agent token with root key
  const rootKey = await importJWK(rootJwk, 'EdDSA')
  const now = Math.floor(Date.now() / 1000)

  const jwt = await new SignJWT({
    iss: agentUrl,
    dwk: 'aauth-agent.json',
    sub: delegateUrl,
    cnf: { jwk: ephPubJwk },
    iat: now,
    exp: now + lifetime,
  })
    .setProtectedHeader({ alg: 'EdDSA', typ: 'agent+jwt', kid })
    .sign(rootKey)

  return {
    signingKey: ephPrivJwk,
    signatureKey: { type: 'jwt', jwt },
  }
}
