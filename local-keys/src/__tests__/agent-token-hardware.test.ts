import { describe, it, expect, afterEach } from 'vitest'
import { importJWK, jwtVerify } from 'jose'
import { signAgentToken } from '../agent-token.js'
import { writeConfig, addKeyToAgent, setPersonServer } from '../config.js'
import { discoverBackends, getBackend } from '../backends/index.js'

const AGENT_URL = 'https://test.example'
const DELEGATE_URL = 'https://test.example/claude'

// Save and restore config
import { readConfig } from '../config.js'
const originalConfig = readConfig()
afterEach(() => writeConfig(originalConfig))

describe('Agent Token with YubiKey PIV', () => {
  const backends = discoverBackends()
  const ykAvailable = backends.some((b) => b.backend === 'yubikey-piv')

  it.skipIf(!ykAvailable)(
    'signs and verifies agent token with YubiKey slot 9e',
    async () => {
      // Register YubiKey key for agent
      writeConfig({ agents: {} })
      addKeyToAgent(AGENT_URL, 'yk-test', {
        backend: 'yubikey-piv',
        algorithm: 'ES256',
        keyId: '9e',
        deviceLabel: 'test-yubikey',
      })

      const result = await signAgentToken({
        agentUrl: AGENT_URL,
        delegateUrl: DELEGATE_URL,
        lifetime: 3600,
      })

      expect(result.signingKey).toBeDefined()
      expect(result.signingKey.kty).toBe('EC')
      expect(result.signatureKey.type).toBe('jwt')

      // Verify JWT with YubiKey public key
      const backend = getBackend('yubikey-piv')
      const pubJwk = await backend.getPublicKey('9e')
      const publicKey = await importJWK(pubJwk, 'ES256')

      const { payload } = await jwtVerify(
        result.signatureKey.jwt,
        publicKey,
        { algorithms: ['ES256'] },
      )

      expect(payload.iss).toBe(AGENT_URL)
      expect(payload.sub).toBe(DELEGATE_URL)
      expect(payload.dwk).toBe('aauth-agent.json')
      expect(payload.cnf).toBeDefined()
      expect(payload.exp! - payload.iat!).toBe(3600)
    },
  )

  it.skipIf(!ykAvailable)(
    'includes person server URL as ps claim',
    async () => {
      writeConfig({ agents: {} })
      addKeyToAgent(AGENT_URL, 'yk-test', {
        backend: 'yubikey-piv',
        algorithm: 'ES256',
        keyId: '9e',
        deviceLabel: 'test-yubikey',
      })
      setPersonServer(AGENT_URL, 'https://person.example')

      const result = await signAgentToken({
        agentUrl: AGENT_URL,
        delegateUrl: DELEGATE_URL,
      })

      const backend = getBackend('yubikey-piv')
      const pubJwk = await backend.getPublicKey('9e')
      const publicKey = await importJWK(pubJwk, 'ES256')
      const { payload } = await jwtVerify(result.signatureKey.jwt, publicKey, {
        algorithms: ['ES256'],
      })

      expect(payload.ps).toBe('https://person.example')
    },
  )
})

describe('Agent Token with Secure Enclave', () => {
  const backends = discoverBackends()
  const seAvailable = backends.some((b) => b.backend === 'secure-enclave')
  let seKeyId: string | null = null

  afterEach(async () => {
    if (seKeyId) {
      try {
        const { execSync } = await import('node:child_process')
        const { join, dirname } = await import('node:path')
        const { fileURLToPath } = await import('node:url')
        const dir = dirname(fileURLToPath(import.meta.url))
        const helper = join(dir, '..', '..', 'bin', 'se-helper')
        execSync(`${helper} delete ${seKeyId}`)
      } catch { /* ignore */ }
      seKeyId = null
    }
  })

  it.skipIf(!seAvailable)(
    'signs and verifies agent token with Secure Enclave',
    async () => {
      const seBackend = getBackend('secure-enclave')
      const key = await seBackend.generateKey('ES256')
      seKeyId = key.keyId

      writeConfig({ agents: {} })
      addKeyToAgent(AGENT_URL, 'se-test', {
        backend: 'secure-enclave',
        algorithm: 'ES256',
        keyId: key.keyId,
        deviceLabel: 'test-machine',
      })

      const result = await signAgentToken({
        agentUrl: AGENT_URL,
        delegateUrl: DELEGATE_URL,
        lifetime: 7200,
      })

      expect(result.signingKey.kty).toBe('EC')

      // Decode the JWT header to find the kid, then verify with SE public key
      const [headerB64] = result.signatureKey.jwt.split('.')
      const header = JSON.parse(Buffer.from(headerB64, 'base64url').toString())
      expect(header.alg).toBe('ES256')
      expect(header.typ).toBe('aa-agent+jwt')

      const publicKey = await importJWK(key.publicJwk, 'ES256')
      const { payload } = await jwtVerify(result.signatureKey.jwt, publicKey, {
        algorithms: ['ES256'],
      })

      expect(payload.iss).toBe(AGENT_URL)
      expect(payload.sub).toBe(DELEGATE_URL)
      expect(payload.exp! - payload.iat!).toBe(7200)
    },
  )
})

describe('Agent Token fallback', () => {
  it('signs with any available hardware key when no config', async () => {
    // With key resolution, if a hardware key is available it will be used
    // even without explicit config. This tests that behavior.
    writeConfig({ agents: {} })
    const backends = discoverBackends()
    const hasHardware = backends.some(
      (b) => b.backend === 'yubikey-piv' || b.backend === 'secure-enclave',
    )

    if (hasHardware) {
      // Should succeed — resolveKey finds the hardware key
      const result = await signAgentToken({
        agentUrl: 'https://nonexistent.example',
        delegateUrl: 'https://nonexistent.example/agent',
      })
      expect(result.signatureKey.type).toBe('jwt')
    } else {
      // No hardware, no software key → should fail
      await expect(
        signAgentToken({
          agentUrl: 'https://nonexistent.example',
          delegateUrl: 'https://nonexistent.example/agent',
        }),
      ).rejects.toThrow()
    }
  })
})
