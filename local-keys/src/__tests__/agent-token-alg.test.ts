import { describe, it, expect, vi, beforeEach } from 'vitest'
import { exportJWK, generateKeyPair, importJWK, jwtVerify } from 'jose'
import type { JWK } from 'jose'

// signAgentToken's key discovery (network + OS keychain + hardware) is not what
// is under test here — the algorithm identifiers it puts on the wire are.
vi.mock('../keychain.js', () => ({ readKeychain: vi.fn() }))
vi.mock('../config.js', () => ({ getAgentConfig: vi.fn(() => null) }))
vi.mock('../resolve-key.js', () => ({ resolveKey: vi.fn() }))

const { readKeychain } = await import('../keychain.js')
const { resolveKey } = await import('../resolve-key.js')
const { signAgentToken } = await import('../agent-token.js')

const AGENT_URL = 'https://agent.example'
const SUB = 'aauth:test@agent.example'

async function edKeychainKey(alg: string): Promise<{ jwk: JWK; publicJwk: JWK }> {
  const { publicKey, privateKey } = await generateKeyPair('Ed25519', { crv: 'Ed25519', extractable: true })
  const jwk = await exportJWK(privateKey)
  jwk.kid = 'kid-1'
  jwk.alg = alg
  return { jwk, publicJwk: await exportJWK(publicKey) }
}

function header(jwt: string): Record<string, unknown> {
  return JSON.parse(Buffer.from(jwt.split('.')[0], 'base64url').toString())
}

beforeEach(() => {
  vi.mocked(resolveKey).mockResolvedValue({
    backend: 'software',
    keyId: 'kid-1',
    kid: 'kid-1',
    algorithm: 'Ed25519',
    publicJwk: {},
  })
})

describe('agent token algorithm identifiers', () => {
  it('signs with alg=Ed25519 and confirms an Ed25519 cnf.jwk', async () => {
    const { jwk, publicJwk } = await edKeychainKey('Ed25519')
    vi.mocked(readKeychain).mockReturnValue({ current: 'kid-1', keys: { 'kid-1': jwk } })

    const result = await signAgentToken({ agentUrl: AGENT_URL, sub: SUB })
    const jwt = result.signatureKey.jwt

    expect(header(jwt).alg).toBe('Ed25519')
    expect(header(jwt).typ).toBe('aa-agent+jwt')

    const { payload } = await jwtVerify(jwt, await importJWK(publicJwk, 'Ed25519'), {
      algorithms: ['Ed25519'],
    })
    expect(payload.iss).toBe(AGENT_URL)
    expect((payload.cnf as { jwk: JWK }).jwk.alg).toBe('Ed25519')
    // The ephemeral private key handed to the HTTP-signature layer.
    expect(result.signingKey.alg).toBe('Ed25519')
  })

  it('upgrades a keychain key still stamped with the pre-11 EdDSA', async () => {
    const { jwk, publicJwk } = await edKeychainKey('EdDSA')
    vi.mocked(readKeychain).mockReturnValue({ current: 'kid-1', keys: { 'kid-1': jwk } })

    const result = await signAgentToken({ agentUrl: AGENT_URL, sub: SUB })
    const jwt = result.signatureKey.jwt

    expect(header(jwt).alg).toBe('Ed25519')
    expect(JSON.stringify(result)).not.toContain('EdDSA')

    const { payload } = await jwtVerify(jwt, await importJWK(publicJwk, 'Ed25519'), {
      algorithms: ['Ed25519'],
    })
    expect((payload.cnf as { jwk: JWK }).jwk.alg).toBe('Ed25519')
  })

  it('refuses a keychain key whose alg contradicts its curve', async () => {
    const { jwk } = await edKeychainKey('ES256')
    vi.mocked(readKeychain).mockReturnValue({ current: 'kid-1', keys: { 'kid-1': jwk } })

    await expect(signAgentToken({ agentUrl: AGENT_URL, sub: SUB })).rejects.toThrow(
      /disagrees with/,
    )
  })

  it('never puts EdDSA in a hardware-signed header, even from a pre-11 config', async () => {
    // A ~/.aauth/config.json written before -11 records algorithm: "EdDSA".
    vi.mocked(resolveKey).mockResolvedValue({
      backend: 'yubikey-piv',
      keyId: '9e',
      kid: 'kid-hw',
      algorithm: 'EdDSA' as 'Ed25519',
      publicJwk: {},
    })
    const backends = await import('../backends/index.js')
    vi.spyOn(backends, 'getBackend').mockReturnValue({
      discover: () => null,
      generateKey: vi.fn(),
      signHash: vi.fn(async () => ({ signature: Buffer.alloc(64), algorithm: 'Ed25519' as const })),
      listKeys: vi.fn(async () => []),
      getPublicKey: vi.fn(),
      getDeviceLabel: () => 'test',
    })

    const result = await signAgentToken({ agentUrl: AGENT_URL, sub: SUB })
    expect(header(result.signatureKey.jwt).alg).toBe('Ed25519')
    vi.restoreAllMocks()
  })
})
