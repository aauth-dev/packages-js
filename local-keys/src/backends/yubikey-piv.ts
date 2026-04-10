import { createRequire } from 'node:module'
import { dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import type { JWK } from 'jose'
import { yubikeyLabel } from '../device-label.js'
import type {
  BackendInfo,
  KeyReference,
  KeyBackendDriver,
  KeyAlgorithm,
} from '../types.js'

const require = createRequire(import.meta.url)
const __dirname = dirname(fileURLToPath(import.meta.url))

interface NativeAddon {
  discover(): Array<{
    backend: string
    description: string
    algorithms: string[]
    deviceId: string
  }>
  generateKey(
    backend: string,
    algorithm: string,
  ): { keyId: string; algorithm: string; publicJwk: string }
  signHash(
    backend: string,
    keyId: string,
    hash: Buffer,
  ): { signature: Buffer; algorithm: string }
  listKeys(
    backend: string,
  ): Array<{ keyId: string; algorithm: string; publicJwk: string }>
}

let nativeAddon: NativeAddon | null | undefined = undefined

function loadAddon(): NativeAddon | null {
  if (nativeAddon !== undefined) return nativeAddon
  try {
    nativeAddon = require('@aauth/hardware-keys') as NativeAddon
    return nativeAddon
  } catch {
    // Fallback: try loading from relative path in workspace
    try {
      const path = require('node:path')
      const addonPath = path.resolve(
        __dirname,
        '..', '..', '..', 'hardware-keys', 'index.js',
      )
      nativeAddon = require(addonPath) as NativeAddon
      return nativeAddon
    } catch {
      nativeAddon = null
      return null
    }
  }
}

export const yubikeyPivBackend: KeyBackendDriver = {
  discover(): BackendInfo | null {
    const addon = loadAddon()
    if (!addon) return null

    try {
      const backends = addon.discover()
      const yk = backends.find((b) => b.backend === 'yubikey-piv')
      if (!yk) return null
      return {
        backend: 'yubikey-piv',
        description: yk.description,
        algorithms: yk.algorithms as KeyAlgorithm[],
        deviceId: yk.deviceId,
      }
    } catch {
      return null
    }
  },

  async generateKey(algorithm: KeyAlgorithm): Promise<KeyReference> {
    const addon = loadAddon()
    if (!addon) throw new Error('hardware-keys addon not available')

    const algStr = algorithm === 'RS256' ? 'RS256' : 'ES256'
    const result = addon.generateKey('yubikey-piv', algStr)
    const publicJwk = JSON.parse(result.publicJwk) as JWK

    return {
      backend: 'yubikey-piv',
      algorithm,
      keyId: result.keyId,
      publicJwk,
    }
  },

  async signHash(
    keyId: string,
    hash: Buffer,
  ): Promise<{ signature: Buffer; algorithm: KeyAlgorithm }> {
    const addon = loadAddon()
    if (!addon) throw new Error('hardware-keys addon not available')

    const result = addon.signHash('yubikey-piv', keyId, hash)
    return {
      signature: Buffer.from(result.signature),
      algorithm: result.algorithm as KeyAlgorithm,
    }
  },

  async listKeys(): Promise<KeyReference[]> {
    const addon = loadAddon()
    if (!addon) return []

    try {
      const keys = addon.listKeys('yubikey-piv')
      return keys.map((k) => ({
        backend: 'yubikey-piv' as const,
        algorithm: k.algorithm as KeyAlgorithm,
        keyId: k.keyId,
        publicJwk: JSON.parse(k.publicJwk) as JWK,
      }))
    } catch {
      return []
    }
  },

  async getPublicKey(keyId: string): Promise<JWK> {
    const keys = await this.listKeys()
    const key = keys.find((k) => k.keyId === keyId)
    if (!key) throw new Error(`YubiKey PIV key not found in slot ${keyId}`)
    return key.publicJwk
  },

  getDeviceLabel(): string {
    const info = this.discover()
    if (!info) return 'yubikey'
    // description is like "YubiKey Yubico YubiKey OTP+FIDO+CCID (serial: 9570775, firmware: 5.1.2)"
    // deviceId is the serial number
    const name = info.description.split('(')[0].trim()
    return yubikeyLabel(name, info.deviceId)
  },
}
