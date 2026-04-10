import { describe, it, expect } from 'vitest'
import { createHash } from 'node:crypto'
import { hostname } from 'node:os'
import { importJWK, jwtVerify } from 'jose'
import { discoverBackends, getBackend } from '../backends/index.js'
import { machineLabel, yubikeyLabel } from '../device-label.js'
import type { BackendInfo, KeyAlgorithm } from '../types.js'

describe('Backend Discovery', () => {
  it('discovers at least the software backend', () => {
    const backends = discoverBackends()
    expect(backends.length).toBeGreaterThanOrEqual(1)
    const software = backends.find((b) => b.backend === 'software')
    expect(software).toBeDefined()
    expect(software!.algorithms).toContain('EdDSA')
    expect(software!.algorithms).toContain('ES256')
  })

  it('returns valid BackendInfo for each discovered backend', () => {
    const backends = discoverBackends()
    for (const b of backends) {
      expect(b.backend).toBeTruthy()
      expect(b.description).toBeTruthy()
      expect(b.algorithms.length).toBeGreaterThan(0)
      expect(b.deviceId).toBeTruthy()
    }
  })
})

describe('Software Backend', () => {
  const backend = getBackend('software')

  it('generates EdDSA key', async () => {
    const key = await backend.generateKey('EdDSA')
    expect(key.backend).toBe('software')
    expect(key.algorithm).toBe('EdDSA')
    expect(key.keyId).toMatch(/^\d{4}-\d{2}-\d{2}_[0-9a-f]{3}$/)
    expect(key.publicJwk.kty).toBe('OKP')
    expect(key.publicJwk.crv).toBe('Ed25519')
  })

  it('generates ES256 key', async () => {
    const key = await backend.generateKey('ES256')
    expect(key.backend).toBe('software')
    expect(key.algorithm).toBe('ES256')
    expect(key.publicJwk.kty).toBe('EC')
    expect(key.publicJwk.crv).toBe('P-256')
  })
})

// Hardware tests - these require actual hardware and are skipped if not available
describe('YubiKey PIV Backend', () => {
  const backends = discoverBackends()
  const ykInfo = backends.find((b) => b.backend === 'yubikey-piv')

  it.skipIf(!ykInfo)('discovers YubiKey', () => {
    expect(ykInfo!.backend).toBe('yubikey-piv')
    expect(ykInfo!.algorithms).toContain('ES256')
    expect(ykInfo!.deviceId).toMatch(/^\d+$/) // serial number
  })

  it.skipIf(!ykInfo)('signs a hash with slot 9e (no PIN)', async () => {
    const backend = getBackend('yubikey-piv')

    // Create a test JWT signing input
    const header = Buffer.from('{"alg":"ES256","typ":"JWT"}').toString(
      'base64url',
    )
    const payload = Buffer.from(
      '{"sub":"test","iat":1234567890}',
    ).toString('base64url')
    const signingInput = `${header}.${payload}`
    const hash = createHash('sha256').update(signingInput).digest()

    const result = await backend.signHash('9e', hash)
    expect(result.algorithm).toBe('ES256')
    expect(result.signature.length).toBe(64) // raw r||s for P-256
  })

  it.skipIf(!ykInfo)('lists keys and returns public JWK', async () => {
    const backend = getBackend('yubikey-piv')
    const keys = await backend.listKeys()
    expect(keys.length).toBeGreaterThan(0)

    const key = keys.find((k) => k.keyId === '9e')
    expect(key).toBeDefined()
    expect(key!.publicJwk.kty).toBe('EC')
    expect(key!.publicJwk.crv).toBe('P-256')
  })

  it.skipIf(!ykInfo)(
    'signs and verifies a complete JWT',
    async () => {
      const backend = getBackend('yubikey-piv')
      const pubJwk = await backend.getPublicKey('9e')

      const header = Buffer.from(
        JSON.stringify({ alg: 'ES256', typ: 'aa-agent+jwt', kid: '9e' }),
      ).toString('base64url')
      const payload = Buffer.from(
        JSON.stringify({
          iss: 'https://test.example',
          sub: 'https://test.example/agent',
          iat: Math.floor(Date.now() / 1000),
          exp: Math.floor(Date.now() / 1000) + 3600,
        }),
      ).toString('base64url')
      const signingInput = `${header}.${payload}`
      const hash = createHash('sha256').update(signingInput).digest()

      const { signature } = await backend.signHash('9e', hash)
      const jwt = `${signingInput}.${Buffer.from(signature).toString('base64url')}`

      // Verify
      const publicKey = await importJWK(pubJwk, 'ES256')
      const { payload: verified } = await jwtVerify(jwt, publicKey, {
        algorithms: ['ES256'],
      })
      expect(verified.iss).toBe('https://test.example')
      expect(verified.sub).toBe('https://test.example/agent')
    },
  )
})

describe('Secure Enclave Backend', () => {
  const backends = discoverBackends()
  const seInfo = backends.find((b) => b.backend === 'secure-enclave')

  it.skipIf(!seInfo)('discovers Secure Enclave', () => {
    expect(seInfo!.backend).toBe('secure-enclave')
    expect(seInfo!.algorithms).toEqual(['ES256'])
    expect(seInfo!.deviceId).toBe('local')
  })

  it.skipIf(!seInfo)(
    'generates key, signs, verifies, and cleans up',
    async () => {
      const backend = getBackend('secure-enclave')

      // Generate
      const key = await backend.generateKey('ES256')
      expect(key.backend).toBe('secure-enclave')
      expect(key.algorithm).toBe('ES256')
      expect(key.keyId).toMatch(/^com\.aauth\.agent\./)
      expect(key.publicJwk.kty).toBe('EC')
      expect(key.publicJwk.crv).toBe('P-256')

      try {
        // Sign
        const header = Buffer.from(
          JSON.stringify({
            alg: 'ES256',
            typ: 'aa-agent+jwt',
            kid: key.keyId,
          }),
        ).toString('base64url')
        const payload = Buffer.from(
          JSON.stringify({
            iss: 'https://test.example',
            sub: 'https://test.example/agent',
            iat: Math.floor(Date.now() / 1000),
            exp: Math.floor(Date.now() / 1000) + 3600,
          }),
        ).toString('base64url')
        const signingInput = `${header}.${payload}`
        const hash = createHash('sha256').update(signingInput).digest()

        const { signature } = await backend.signHash(key.keyId, hash)
        expect(signature.length).toBe(64)

        // Verify
        const jwt = `${signingInput}.${Buffer.from(signature).toString('base64url')}`
        const publicKey = await importJWK(key.publicJwk, 'ES256')
        const { payload: verified } = await jwtVerify(jwt, publicKey, {
          algorithms: ['ES256'],
        })
        expect(verified.iss).toBe('https://test.example')

        // Reload public key from a new call
        const reloadedPubJwk = await backend.getPublicKey(key.keyId)
        expect(reloadedPubJwk.x).toBe(key.publicJwk.x)
        expect(reloadedPubJwk.y).toBe(key.publicJwk.y)
      } finally {
        // Cleanup - delete the test key via se-helper
        const { execSync } = await import('node:child_process')
        const { existsSync } = await import('node:fs')
        const { join, dirname } = await import('node:path')
        const { fileURLToPath } = await import('node:url')
        const dir = dirname(fileURLToPath(import.meta.url))
        const helper = join(dir, '..', '..', 'bin', 'se-helper')
        if (existsSync(helper)) {
          try {
            execSync(`${helper} delete ${key.keyId}`)
          } catch {
            // ignore cleanup errors
          }
        }
      }
    },
  )

  it.skipIf(!seInfo)('rejects non-ES256 algorithms', async () => {
    const backend = getBackend('secure-enclave')
    await expect(backend.generateKey('EdDSA')).rejects.toThrow(
      'only supports ES256',
    )
  })
})

describe('Device Labels', () => {
  it('derives machine label from hostname', () => {
    const label = machineLabel()
    expect(label).toBeTruthy()
    expect(label).not.toContain('.local')
    expect(label).toBe(label.toLowerCase())
  })

  it('derives yubikey label from name and serial', () => {
    expect(yubikeyLabel('YubiKey OTP+FIDO+CCID', '9570775')).toBe(
      'yubikey-otp+fido+ccid-0775',
    )
    expect(yubikeyLabel('Yubico YubiKey 5C Nano', '1234567')).toBe(
      'yubikey-5c-nano-4567',
    )
  })

  it('each backend has a getDeviceLabel', () => {
    const backends = discoverBackends()
    for (const info of backends) {
      const driver = getBackend(info.backend)
      const label = driver.getDeviceLabel()
      expect(label).toBeTruthy()
      expect(typeof label).toBe('string')
    }
  })
})
