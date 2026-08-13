import { generateKeyPair, exportJWK } from 'jose'
import type { JWK } from 'jose'
import { readKeychain, writeKeychain, deleteKeychain, listAgentUrls } from '../keychain.js'
import { machineLabel } from '../device-label.js'
import { publicJwkWithAlg } from '../jwk-alg.js'
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
      algorithms: ['Ed25519', 'ES256'],
      deviceId: 'local',
    }
  },

  async generateKey(algorithm: KeyAlgorithm): Promise<KeyReference> {
    const kid = generateKid()
    let alg: string
    let opts: { crv: string; extractable: boolean }

    if (algorithm === 'Ed25519') {
      alg = 'Ed25519'
      // jose 6: keys are non-extractable by default, and these are exported to JWK below
      opts = { crv: 'Ed25519', extractable: true }
    } else if (algorithm === 'ES256') {
      alg = 'ES256'
      opts = { crv: 'P-256', extractable: true }
    } else {
      throw new Error(`Software backend does not support ${algorithm}`)
    }

    const { publicKey, privateKey } = await generateKeyPair(alg, opts)
    // Fully-specified alg (RFC 9864) — `Ed25519`, never the polymorphic `EdDSA`.
    const privateJwk = publicJwkWithAlg(await exportJWK(privateKey), alg, 'generated private key')
    const publicJwk = publicJwkWithAlg(await exportJWK(publicKey), alg, 'generated public key')

    privateJwk.kid = kid
    privateJwk.use = 'sig'
    publicJwk.kid = kid
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
        // The keychain may hold pre-11 JWKs stamped `alg: "EdDSA"`; derive the
        // fully-specified alg from the key material rather than trusting it.
        const alg: KeyAlgorithm = jwk.crv === 'P-256' ? 'ES256' : 'Ed25519'
        const { d: _d, ...pub } = jwk
        try {
          refs.push({
            backend: 'software',
            algorithm: alg,
            keyId: kid,
            publicJwk: { ...publicJwkWithAlg(pub, alg, `keychain key ${kid}`), use: 'sig' },
          })
        } catch {
          // Key material we can't pin a fully-specified alg to is unusable
          // under AAuth -11 — skip it rather than emitting a polymorphic alg.
        }
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
        // Re-derive `alg`: a key stored before -11 carries `EdDSA`, and callers
        // hand this JWK straight to a verifier that rejects it.
        return { ...publicJwkWithAlg(pub, undefined, `keychain key ${keyId}`), use: 'sig' }
      }
    }
    throw new Error(`Software key not found: ${keyId}`)
  },

  getDeviceLabel(): string {
    return machineLabel()
  },

  async deleteKey(keyId: string): Promise<void> {
    // Software keys live in the OS keychain, grouped per agent URL. Find the
    // entry holding this kid, remove it, and drop the whole entry if it's now empty.
    for (const url of listAgentUrls()) {
      const data = readKeychain(url)
      if (!data?.keys[keyId]) continue
      delete data.keys[keyId]
      const remaining = Object.keys(data.keys)
      if (remaining.length === 0) {
        deleteKeychain(url)
      } else {
        if (data.current === keyId) data.current = remaining[0]
        writeKeychain(url, data)
      }
      return
    }
  },
}
