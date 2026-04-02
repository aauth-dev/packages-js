import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import {
  generateKeyPair,
  exportJWK,
  SignJWT,
  calculateJwkThumbprint,
} from 'jose'
import type { KeyLike, JWK } from 'jose'
import { verifyToken, AAuthTokenError, clearMetadataCache } from './verify-token.js'

// --- Helpers ---

async function createKeys() {
  // Root key pair — signs the JWT (issuer's key, published in JWKS)
  const root = await generateKeyPair('EdDSA', { crv: 'Ed25519' })
  const rootPubJwk = { ...await exportJWK(root.publicKey), kid: 'root-1' }

  // Ephemeral key pair — signs the HTTP request (bound via cnf.jwk)
  const eph = await generateKeyPair('EdDSA', { crv: 'Ed25519' })
  const ephPubJwk = await exportJWK(eph.publicKey)

  const ephThumbprint = await calculateJwkThumbprint(ephPubJwk, 'sha256')

  return { root, rootPubJwk, eph, ephPubJwk, ephThumbprint }
}

async function signToken(
  rootPrivateKey: KeyLike,
  typ: string,
  claims: Record<string, unknown>,
  kid = 'root-1',
): Promise<string> {
  const now = Math.floor(Date.now() / 1000)
  return new SignJWT({ iat: now, exp: now + 3600, ...claims })
    .setProtectedHeader({ alg: 'EdDSA', typ, kid })
    .sign(rootPrivateKey)
}

function mockFetchForJwks(rootPubJwk: JWK, issuer: string, metadataPath: string) {
  const jwksUrl = `${issuer}/jwks`
  const metadataUrl = `${issuer}${metadataPath}`

  return vi.fn(async (url: string | URL) => {
    const urlStr = url.toString()
    if (urlStr === metadataUrl) {
      return new Response(JSON.stringify({ jwks_uri: jwksUrl }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      })
    }
    if (urlStr === jwksUrl) {
      return new Response(JSON.stringify({ keys: [rootPubJwk] }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      })
    }
    return new Response('Not Found', { status: 404 })
  })
}

// --- Tests ---

describe('verifyToken', () => {
  const originalFetch = globalThis.fetch

  beforeEach(() => {
    clearMetadataCache()
  })

  afterEach(() => {
    globalThis.fetch = originalFetch
  })

  it('verifies a valid agent token', async () => {
    const { root, rootPubJwk, ephPubJwk, ephThumbprint } = await createKeys()
    const iss = 'https://agent.example'

    globalThis.fetch = mockFetchForJwks(
      rootPubJwk, iss, '/.well-known/aauth-agent.json',
    ) as typeof fetch

    const jwt = await signToken(root.privateKey, 'agent+jwt', {
      iss,
      dwk: 'aauth-agent.json',
      sub: 'https://delegate.example',
      cnf: { jwk: ephPubJwk },
    })

    const result = await verifyToken({ jwt, httpSignatureThumbprint: ephThumbprint })

    expect(result.type).toBe('agent')
    expect(result.iss).toBe(iss)
    expect(result.dwk).toBe('aauth-agent.json')
    if (result.type === 'agent') {
      expect(result.sub).toBe('https://delegate.example')
    }
    expect(result.cnf.jwk).toEqual(ephPubJwk)
    expect(result.iat).toBeTypeOf('number')
    expect(result.exp).toBeTypeOf('number')
  })

  it('verifies a valid auth token', async () => {
    const { root, rootPubJwk, ephPubJwk, ephThumbprint } = await createKeys()
    const iss = 'https://auth.example'

    globalThis.fetch = mockFetchForJwks(
      rootPubJwk, iss, '/.well-known/aauth-issuer.json',
    ) as typeof fetch

    const jwt = await signToken(root.privateKey, 'auth+jwt', {
      iss,
      dwk: 'aauth-issuer.json',
      aud: 'https://resource.example',
      agent: 'https://agent.example',
      sub: 'user-123',
      scope: 'files.read',
      cnf: { jwk: ephPubJwk },
    })

    const result = await verifyToken({ jwt, httpSignatureThumbprint: ephThumbprint })

    expect(result.type).toBe('auth')
    expect(result.iss).toBe(iss)
    expect(result.dwk).toBe('aauth-issuer.json')
    if (result.type === 'auth') {
      expect(result.aud).toBe('https://resource.example')
      expect(result.agent).toBe('https://agent.example')
      expect(result.sub).toBe('user-123')
      expect(result.scope).toBe('files.read')
    }
  })

  it('throws on unknown typ', async () => {
    const { root, ephPubJwk, ephThumbprint } = await createKeys()

    const jwt = await signToken(root.privateKey, 'unknown+jwt', {
      iss: 'https://example.com',
      dwk: 'aauth-agent.json',
      sub: 'test',
      cnf: { jwk: ephPubJwk },
    })

    await expect(
      verifyToken({ jwt, httpSignatureThumbprint: ephThumbprint }),
    ).rejects.toThrow('Unknown JWT typ')
  })

  it('throws on missing iss claim', async () => {
    const { root, ephPubJwk, ephThumbprint } = await createKeys()

    // Sign without iss
    const jwt = await signToken(root.privateKey, 'agent+jwt', {
      dwk: 'aauth-agent.json',
      sub: 'https://delegate.example',
      cnf: { jwk: ephPubJwk },
    })

    await expect(
      verifyToken({ jwt, httpSignatureThumbprint: ephThumbprint }),
    ).rejects.toThrow('Missing required claim: iss')
  })

  it('throws on missing dwk claim', async () => {
    const { root, ephPubJwk, ephThumbprint } = await createKeys()

    const jwt = await signToken(root.privateKey, 'agent+jwt', {
      iss: 'https://agent.example',
      sub: 'https://delegate.example',
      cnf: { jwk: ephPubJwk },
    })

    await expect(
      verifyToken({ jwt, httpSignatureThumbprint: ephThumbprint }),
    ).rejects.toThrow('Missing required claim: dwk')
  })

  it('throws on missing sub for agent token', async () => {
    const { root, ephPubJwk, ephThumbprint } = await createKeys()

    const jwt = await signToken(root.privateKey, 'agent+jwt', {
      iss: 'https://agent.example',
      dwk: 'aauth-agent.json',
      cnf: { jwk: ephPubJwk },
    })

    await expect(
      verifyToken({ jwt, httpSignatureThumbprint: ephThumbprint }),
    ).rejects.toThrow('Missing required claim: sub')
  })

  it('throws on missing aud for auth token', async () => {
    const { root, ephPubJwk, ephThumbprint } = await createKeys()

    const jwt = await signToken(root.privateKey, 'auth+jwt', {
      iss: 'https://auth.example',
      dwk: 'aauth-issuer.json',
      agent: 'https://agent.example',
      cnf: { jwk: ephPubJwk },
    })

    await expect(
      verifyToken({ jwt, httpSignatureThumbprint: ephThumbprint }),
    ).rejects.toThrow('Missing required claim: aud')
  })

  it('throws on missing agent for auth token', async () => {
    const { root, ephPubJwk, ephThumbprint } = await createKeys()

    const jwt = await signToken(root.privateKey, 'auth+jwt', {
      iss: 'https://auth.example',
      dwk: 'aauth-issuer.json',
      aud: 'https://resource.example',
      cnf: { jwk: ephPubJwk },
    })

    await expect(
      verifyToken({ jwt, httpSignatureThumbprint: ephThumbprint }),
    ).rejects.toThrow('Missing required claim: agent')
  })

  it('throws on missing cnf.jwk', async () => {
    const { root, ephThumbprint } = await createKeys()

    const jwt = await signToken(root.privateKey, 'agent+jwt', {
      iss: 'https://agent.example',
      dwk: 'aauth-agent.json',
      sub: 'https://delegate.example',
    })

    await expect(
      verifyToken({ jwt, httpSignatureThumbprint: ephThumbprint }),
    ).rejects.toThrow('Missing required claim: cnf.jwk')
  })

  it('throws on expired token', async () => {
    const { root, ephPubJwk, ephThumbprint } = await createKeys()

    const past = Math.floor(Date.now() / 1000) - 3600
    const jwt = await new SignJWT({
      iss: 'https://agent.example',
      dwk: 'aauth-agent.json',
      sub: 'https://delegate.example',
      cnf: { jwk: ephPubJwk },
      iat: past - 3600,
      exp: past, // expired 1 hour ago
    })
      .setProtectedHeader({ alg: 'EdDSA', typ: 'agent+jwt', kid: 'root-1' })
      .sign(root.privateKey)

    await expect(
      verifyToken({ jwt, httpSignatureThumbprint: ephThumbprint }),
    ).rejects.toThrow('Token has expired')
  })

  it('throws key_binding_failed on thumbprint mismatch', async () => {
    const { root, ephPubJwk } = await createKeys()
    // Use a different key's thumbprint
    const other = await generateKeyPair('EdDSA', { crv: 'Ed25519' })
    const otherPubJwk = await exportJWK(other.publicKey)
    const wrongThumbprint = await calculateJwkThumbprint(otherPubJwk, 'sha256')

    const jwt = await signToken(root.privateKey, 'agent+jwt', {
      iss: 'https://agent.example',
      dwk: 'aauth-agent.json',
      sub: 'https://delegate.example',
      cnf: { jwk: ephPubJwk },
    })

    try {
      await verifyToken({ jwt, httpSignatureThumbprint: wrongThumbprint })
      expect.fail('Should have thrown')
    } catch (err) {
      expect(err).toBeInstanceOf(AAuthTokenError)
      expect((err as AAuthTokenError).code).toBe('key_binding_failed')
    }
  })

  it('throws on JWKS fetch failure', async () => {
    const { root, ephPubJwk, ephThumbprint } = await createKeys()
    const iss = 'https://agent.example'

    globalThis.fetch = vi.fn(async () =>
      new Response('Server Error', { status: 500 }),
    ) as typeof fetch

    const jwt = await signToken(root.privateKey, 'agent+jwt', {
      iss,
      dwk: 'aauth-agent.json',
      sub: 'https://delegate.example',
      cnf: { jwk: ephPubJwk },
    })

    await expect(
      verifyToken({ jwt, httpSignatureThumbprint: ephThumbprint }),
    ).rejects.toThrow('Failed to fetch metadata')
  })

  it('throws when kid not found in JWKS', async () => {
    const { root, ephPubJwk, ephThumbprint } = await createKeys()
    const iss = 'https://agent.example'

    // Publish a JWKS with a different kid
    const otherRoot = await generateKeyPair('EdDSA', { crv: 'Ed25519' })
    const otherPubJwk = { ...await exportJWK(otherRoot.publicKey), kid: 'other-key' }

    globalThis.fetch = mockFetchForJwks(
      otherPubJwk, iss, '/.well-known/aauth-agent.json',
    ) as typeof fetch

    const jwt = await signToken(root.privateKey, 'agent+jwt', {
      iss,
      dwk: 'aauth-agent.json',
      sub: 'https://delegate.example',
      cnf: { jwk: ephPubJwk },
    })

    await expect(
      verifyToken({ jwt, httpSignatureThumbprint: ephThumbprint }),
    ).rejects.toThrow('JWT signature verification failed')
  })
})
