import { generateKeyPair, exportJWK } from 'jose'
import type { JWK } from 'jose'
import { readKeychain, writeKeychain, listAgentUrls } from '../keychain.js'
import { machineLabel } from '../device-label.js'
import type {
  BackendInfo,
  KeyReference,
  KeyBackendDriver,
  KeyAlgorithm,
} from '../types.js'

function generateKid(): string {
  const now = new Date()
  const date = now.toISOString().slice(0, 10)
  const hex = Math.floor(Math.random() * 0xfff)
    .toString(16)
    .padStart(3, '0')
  return `${date}_${hex}`
}

export const softwareBackend: KeyBackendDriver = {
  discover(): BackendInfo | null {
    return {
      backend: 'software',
      description: 'Software keys stored in OS keychain',
      algorithms: ['EdDSA', 'ES256'],
      deviceId: 'local',
    }
  },

  async generateKey(algorithm: KeyAlgorithm): Promise<KeyReference> {
    const kid = generateKid()
    let alg: string
    let opts: Record<string, string>

    if (algorithm === 'EdDSA') {
      alg = 'EdDSA'
      opts = { crv: 'Ed25519' }
    } else if (algorithm === 'ES256') {
      alg = 'ES256'
      opts = { crv: 'P-256' }
    } else {
      throw new Error(`Software backend does not support ${algorithm}`)
    }

    const { publicKey, privateKey } = await generateKeyPair(alg, opts)
    const privateJwk = await exportJWK(privateKey)
    const publicJwk = await exportJWK(publicKey)

    privateJwk.kid = kid
    privateJwk.alg = alg
    privateJwk.use = 'sig'
    publicJwk.kid = kid
    publicJwk.alg = alg
    publicJwk.use = 'sig'

    return {
      backend: 'software',
      algorithm,
      keyId: kid,
      publicJwk,
    }
  },

  async signHash(
    _keyId: string,
    _hash: Buffer,
  ): Promise<{ signature: Buffer; algorithm: KeyAlgorithm }> {
    // Software keys sign via jose's SignJWT (not raw hash signing)
    // This method exists for interface consistency but software keys
    // use importJWK + SignJWT in agent-token.ts directly
    throw new Error(
      'Software backend uses jose SignJWT, not raw hash signing',
    )
  },

  async listKeys(): Promise<KeyReference[]> {
    const urls = listAgentUrls()
    const refs: KeyReference[] = []
    for (const url of urls) {
      const data = readKeychain(url)
      if (!data) continue
      for (const [kid, jwk] of Object.entries(data.keys)) {
        const alg: KeyAlgorithm =
          jwk.crv === 'P-256' ? 'ES256' : 'EdDSA'
        const { d: _d, ...pub } = jwk
        refs.push({
          backend: 'software',
          algorithm: alg,
          keyId: kid,
          publicJwk: { ...pub, use: 'sig', alg: alg === 'ES256' ? 'ES256' : 'EdDSA' },
        })
      }
    }
    return refs
  },

  async getPublicKey(keyId: string): Promise<JWK> {
    const urls = listAgentUrls()
    for (const url of urls) {
      const data = readKeychain(url)
      if (!data) continue
      const jwk = data.keys[keyId]
      if (jwk) {
        const { d: _d, ...pub } = jwk
        return { ...pub, use: 'sig' }
      }
    }
    throw new Error(`Software key not found: ${keyId}`)
  },

  getDeviceLabel(): string {
    return machineLabel()
  },
}
