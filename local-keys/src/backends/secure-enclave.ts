import { execFileSync } from 'node:child_process'
import { existsSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import type { JWK } from 'jose'
import { machineLabel } from '../device-label.js'
import type {
  BackendInfo,
  KeyReference,
  KeyBackendDriver,
  KeyAlgorithm,
} from '../types.js'

const __filename = fileURLToPath(import.meta.url)
const __dirname = dirname(__filename)

function getHelperPath(): string | null {
  const arch = process.arch === 'arm64' ? 'darwin-arm64' : 'darwin-x64'
  const candidates = [
    // Published: inside platform-specific hardware-keys package
    join(__dirname, '..', '..', 'node_modules', `@aauth/hardware-keys-${arch}`, 'se-helper'),
    // Workspace: hardware-keys sibling
    join(__dirname, '..', '..', '..', 'hardware-keys', 'se-helper', 'se-helper'),
    // Local dev: bin directory
    join(__dirname, '..', '..', 'bin', 'se-helper'),
  ]
  for (const p of candidates) {
    if (existsSync(p)) return p
  }
  return null
}

function callHelper(
  ...args: string[]
): Record<string, unknown> | Array<Record<string, unknown>> {
  const helper = getHelperPath()
  if (!helper) throw new Error('se-helper binary not found')

  const result = execFileSync(helper, args, {
    encoding: 'utf-8',
    timeout: 10000,
  })
  return JSON.parse(result.trim())
}

export const secureEnclaveBackend: KeyBackendDriver = {
  discover(): BackendInfo | null {
    if (process.platform !== 'darwin') return null

    const helper = getHelperPath()
    if (!helper) return null

    // Check if SE is available by trying to list keys
    try {
      callHelper('list')
      return {
        backend: 'secure-enclave',
        description: 'macOS Secure Enclave (Apple Silicon)',
        algorithms: ['ES256'],
        deviceId: 'local',
      }
    } catch {
      return null
    }
  },

  async generateKey(algorithm: KeyAlgorithm): Promise<KeyReference> {
    if (algorithm !== 'ES256') {
      throw new Error('Secure Enclave only supports ES256')
    }

    const now = new Date()
    const date = now.toISOString().slice(0, 10)
    const hex = Math.floor(Math.random() * 0xfff)
      .toString(16)
      .padStart(3, '0')
    const label = `com.aauth.agent.${date}_${hex}`

    const result = callHelper('generate', label) as Record<string, unknown>
    const publicJwk = result.publicJwk as JWK

    return {
      backend: 'secure-enclave',
      algorithm: 'ES256',
      keyId: label,
      publicJwk,
    }
  },

  async signHash(
    keyId: string,
    hash: Buffer,
  ): Promise<{ signature: Buffer; algorithm: KeyAlgorithm }> {
    const hexHash = hash.toString('hex')
    const result = callHelper('sign', keyId, hexHash) as Record<string, unknown>

    // Decode base64url signature
    const sigB64 = result.signature as string
    const signature = Buffer.from(sigB64, 'base64url')

    return {
      signature,
      algorithm: 'ES256',
    }
  },

  async listKeys(): Promise<KeyReference[]> {
    try {
      const items = callHelper('list') as Array<Record<string, unknown>>
      return items.map((item) => ({
        backend: 'secure-enclave' as const,
        algorithm: 'ES256' as const,
        keyId: item.label as string,
        publicJwk: {} as JWK, // public key fetched separately
      }))
    } catch {
      return []
    }
  },

  async getPublicKey(keyId: string): Promise<JWK> {
    const result = callHelper('public-key', keyId) as Record<string, unknown>
    return result.publicJwk as JWK
  },

  getDeviceLabel(): string {
    return machineLabel()
  },
}
