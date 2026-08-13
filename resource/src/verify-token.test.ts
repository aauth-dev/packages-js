import { describe, it, expect, beforeEach, vi } from 'vitest'
import { generateKeyPair, exportJWK, SignJWT, calculateJwkThumbprint } from 'jose'
import { verifyToken, AAuthTokenError, clearMetadataCache } from './index.js'
import type { VerifiedPersonToken, VerifiedAuthToken, VerifiedAgentToken } from './index.js'
import {
  createTestKeys, signTestJwt, mockJwksFetch, RESOURCE, PS, AP, MISSION_S256,
  type TestKeys,
} from './testing.js'

let keys: TestKeys
let fetchMock: ReturnType<typeof mockJwksFetch>

beforeEach(async () => {
  clearMetadataCache()
  keys = await createTestKeys()
  fetchMock = mockJwksFetch([
    { iss: AP, dwk: 'aauth-agent.json', keys: [keys.issuerJwk] },
    { iss: PS, dwk: 'aauth-person.json', keys: [keys.issuerJwk] },
    { iss: PS, dwk: 'aauth-access.json', keys: [keys.issuerJwk] },
  ])
})

function opts(jwt: string, over: Record<string, unknown> = {}) {
  return {
    jwt,
    httpSignatureThumbprint: keys.agentThumbprint,
    resource: RESOURCE,
    accept: ['agent', 'person', 'auth'] as const,
    fetch: fetchMock as never,
    ...over,
  }
}

function agentClaims(over: Record<string, unknown> = {}) {
  return {
    iss: AP,
    dwk: 'aauth-agent.json',
    sub: 'aauth:test@agent.example',
    jti: 'at-1',
    cnf: { jwk: keys.agentJwk },
    ...over,
  }
}

function personClaims(over: Record<string, unknown> = {}) {
  return {
    iss: PS,
    dwk: 'aauth-person.json',
    aud: RESOURCE,
    sub: '8f14e45fceea167a5a36dedd4bea2543',
    jti: 'pt-3ab910',
    cnf: { jwk: keys.agentJwk },
    mission_s256: MISSION_S256,
    ...over,
  }
}

function authClaims(over: Record<string, unknown> = {}) {
  return {
    iss: PS,
    dwk: 'aauth-person.json',
    aud: RESOURCE,
    jti: 'auth-1',
    ps: PS,
    sub: '8f14e45fceea167a5a36dedd4bea2543',
    cnf: { jwk: keys.agentJwk },
    scope: 'notes.read',
    mission_s256: MISSION_S256,
    ...over,
  }
}

describe('agent token', () => {
  it('verifies and surfaces sub, ps and parent_agent', async () => {
    const jwt = await signTestJwt(keys.issuerPrivate, 'aa-agent+jwt', agentClaims({ ps: PS }))
    const result = (await verifyToken(opts(jwt))) as VerifiedAgentToken

    expect(result.type).toBe('agent')
    expect(result.iss).toBe(AP)
    expect(result.sub).toBe('aauth:test@agent.example')
    expect(result.ps).toBe(PS)
    expect(result.jti).toBe('at-1')
    expect(result.cnf.jwk).toEqual(keys.agentJwk)
  })

  it('rejects a ps that is not a server identifier', async () => {
    const jwt = await signTestJwt(
      keys.issuerPrivate, 'aa-agent+jwt', agentClaims({ ps: 'https://ps.example/' }),
    )
    await expect(verifyToken(opts(jwt))).rejects.toThrow('server identifier')
  })

  it('rejects the wrong dwk', async () => {
    const jwt = await signTestJwt(
      keys.issuerPrivate, 'aa-agent+jwt', agentClaims({ dwk: 'aauth-person.json' }),
    )
    await expect(verifyToken(opts(jwt))).rejects.toThrow('Expected dwk "aauth-agent.json"')
  })
})

describe('person token', () => {
  it('verifies a person token and carries the mission through', async () => {
    const jwt = await signTestJwt(keys.issuerPrivate, 'aa-person+jwt', personClaims())
    const result = (await verifyToken(opts(jwt))) as VerifiedPersonToken

    expect(result.type).toBe('person')
    expect(result.iss).toBe(PS)
    expect(result.dwk).toBe('aauth-person.json')
    expect(result.aud).toBe(RESOURCE)
    expect(result.sub).toBe('8f14e45fceea167a5a36dedd4bea2543')
    expect(result.jti).toBe('pt-3ab910')
    expect(result.mission_s256).toBe(MISSION_S256)
  })

  it('surfaces tenant when present', async () => {
    const jwt = await signTestJwt(
      keys.issuerPrivate, 'aa-person+jwt', personClaims({ tenant: 'acme' }),
    )
    const result = (await verifyToken(opts(jwt))) as VerifiedPersonToken
    expect(result.tenant).toBe('acme')
  })

  it('requires dwk aauth-person.json', async () => {
    const jwt = await signTestJwt(
      keys.issuerPrivate, 'aa-person+jwt', personClaims({ dwk: 'aauth-access.json' }),
    )
    await expect(verifyToken(opts(jwt))).rejects.toThrow('Expected dwk "aauth-person.json"')
  })

  it('requires jti', async () => {
    const claims = personClaims()
    delete (claims as Record<string, unknown>).jti
    const jwt = await signTestJwt(keys.issuerPrivate, 'aa-person+jwt', claims)
    await expect(verifyToken(opts(jwt))).rejects.toThrow('Missing required claim: jti')
  })

  it('rejects an aud that is not this resource', async () => {
    const jwt = await signTestJwt(
      keys.issuerPrivate, 'aa-person+jwt', personClaims({ aud: 'https://other.example' }),
    )
    try {
      await verifyToken(opts(jwt))
      expect.fail('should have thrown')
    } catch (err) {
      expect((err as AAuthTokenError).code).toBe('aud_mismatch')
    }
  })

  it('rejects scope or account on a person token', async () => {
    const jwt = await signTestJwt(
      keys.issuerPrivate, 'aa-person+jwt', personClaims({ scope: 'notes.write' }),
    )
    await expect(verifyToken(opts(jwt))).rejects.toThrow('MUST NOT carry scope or account')
  })

  it('rejects a cnf.jwk that is not the HTTP signing key', async () => {
    const other = await generateKeyPair('Ed25519', { extractable: true })
    const otherJwk = { ...(await exportJWK(other.publicKey)), alg: 'Ed25519' }
    const jwt = await signTestJwt(
      keys.issuerPrivate, 'aa-person+jwt', personClaims({ cnf: { jwk: otherJwk } }),
    )
    try {
      await verifyToken(opts(jwt))
      expect.fail('should have thrown')
    } catch (err) {
      expect((err as AAuthTokenError).code).toBe('key_binding_failed')
    }
  })

  it('rejects a cnf.jwk with no alg member', async () => {
    const bare = { ...keys.agentJwk }
    delete (bare as Record<string, unknown>).alg
    const jwt = await signTestJwt(
      keys.issuerPrivate, 'aa-person+jwt', personClaims({ cnf: { jwk: bare } }),
    )
    await expect(verifyToken(opts(jwt))).rejects.toThrow('alg is REQUIRED')
  })

  it('rejects a structurally incomplete cnf.jwk before decoding it', async () => {
    const jwt = await signTestJwt(
      keys.issuerPrivate,
      'aa-person+jwt',
      personClaims({ cnf: { jwk: { kty: 'OKP', crv: 'Ed25519', alg: 'Ed25519' } } }),
    )
    await expect(verifyToken(opts(jwt))).rejects.toThrow('structurally incomplete: missing x')
  })
})

describe('a person token is not an auth token', () => {
  it('is rejected wherever an auth token is required', async () => {
    // Same iss, dwk, aud, sub and cnf as the auth token below. Only typ differs.
    const jwt = await signTestJwt(keys.issuerPrivate, 'aa-person+jwt', personClaims())
    try {
      await verifyToken(opts(jwt, { accept: ['auth'] }))
      expect.fail('a person token MUST NOT be accepted where an auth token is required')
    } catch (err) {
      expect(err).toBeInstanceOf(AAuthTokenError)
      expect((err as AAuthTokenError).code).toBe('token_type_not_accepted')
    }
  })

  it('rejects it before any network call, so a hostile PS cannot help', async () => {
    const jwt = await signTestJwt(keys.issuerPrivate, 'aa-person+jwt', personClaims())
    await expect(verifyToken(opts(jwt, { accept: ['auth'] }))).rejects.toThrow()
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('symmetrically rejects an auth token where a person token is required', async () => {
    const jwt = await signTestJwt(keys.issuerPrivate, 'aa-auth+jwt', authClaims())
    try {
      await verifyToken(opts(jwt, { accept: ['person'] }))
      expect.fail('should have thrown')
    } catch (err) {
      expect((err as AAuthTokenError).code).toBe('token_type_not_accepted')
    }
  })

  it('rejects an agent token where an auth token is required', async () => {
    const jwt = await signTestJwt(keys.issuerPrivate, 'aa-agent+jwt', agentClaims())
    try {
      await verifyToken(opts(jwt, { accept: ['auth'] }))
      expect.fail('should have thrown')
    } catch (err) {
      expect((err as AAuthTokenError).code).toBe('token_type_not_accepted')
    }
  })
})

describe('auth token', () => {
  it('verifies and surfaces ps, sub, mission and R3 claims', async () => {
    const jwt = await signTestJwt(
      keys.issuerPrivate,
      'aa-auth+jwt',
      authClaims({
        account: 'acct-9',
        r3_uri: 'https://resource.example/r3/abc',
        r3_s256: 'aBcD',
        r3_granted: { vocabulary: 'urn:aauth:vocabulary:mcp', operations: [{ tool: 'read_note' }] },
        r3_per_call: { vocabulary: 'urn:aauth:vocabulary:mcp', operations: [{ tool: 'send_email' }] },
      }),
    )
    const result = (await verifyToken(opts(jwt, { accept: ['auth'] }))) as VerifiedAuthToken

    expect(result.type).toBe('auth')
    expect(result.ps).toBe(PS)
    expect(result.sub).toBe('8f14e45fceea167a5a36dedd4bea2543')
    expect(result.scope).toBe('notes.read')
    expect(result.account).toBe('acct-9')
    expect(result.mission_s256).toBe(MISSION_S256)
    expect(result.r3_uri).toBe('https://resource.example/r3/abc')
    expect(result.r3_granted?.operations).toEqual([{ tool: 'read_note' }])
    expect(result.r3_per_call?.operations).toEqual([{ tool: 'send_email' }])
    // No `agent` claim exists in -11.
    expect((result as unknown as { agent?: string }).agent).toBeUndefined()
  })

  it('requires ps', async () => {
    const claims = authClaims()
    delete (claims as Record<string, unknown>).ps
    const jwt = await signTestJwt(keys.issuerPrivate, 'aa-auth+jwt', claims)
    await expect(verifyToken(opts(jwt, { accept: ['auth'] })))
      .rejects.toThrow('Missing required claim: ps')
  })

  it('requires sub', async () => {
    const claims = authClaims()
    delete (claims as Record<string, unknown>).sub
    const jwt = await signTestJwt(keys.issuerPrivate, 'aa-auth+jwt', claims)
    await expect(verifyToken(opts(jwt, { accept: ['auth'] })))
      .rejects.toThrow('Missing required claim: sub')
  })

  it('accepts dwk aauth-access.json from an AS', async () => {
    const jwt = await signTestJwt(
      keys.issuerPrivate, 'aa-auth+jwt', authClaims({ dwk: 'aauth-access.json' }),
    )
    const result = (await verifyToken(opts(jwt, { accept: ['auth'] }))) as VerifiedAuthToken
    expect(result.dwk).toBe('aauth-access.json')
  })

  it('rejects any other dwk', async () => {
    const jwt = await signTestJwt(
      keys.issuerPrivate, 'aa-auth+jwt', authClaims({ dwk: 'aauth-resource.json' }),
    )
    await expect(verifyToken(opts(jwt, { accept: ['auth'] })))
      .rejects.toThrow('Auth token dwk must be')
  })

  it('accepts an aud array containing this resource', async () => {
    const jwt = await signTestJwt(
      keys.issuerPrivate, 'aa-auth+jwt', authClaims({ aud: ['https://other.example', RESOURCE] }),
    )
    const result = await verifyToken(opts(jwt, { accept: ['auth'] }))
    expect(result.type).toBe('auth')
  })
})

describe('algorithm policy', () => {
  it('rejects the polymorphic EdDSA in the JWT header', async () => {
    const ed = await generateKeyPair('Ed25519', { extractable: true })
    const jwk = { ...(await exportJWK(ed.publicKey)), alg: 'Ed25519', kid: 'issuer-1' }
    const agentThumb = await calculateJwkThumbprint(keys.agentJwk, 'sha256')
    const now = Math.floor(Date.now() / 1000)
    const jwt = await new SignJWT({ ...personClaims(), iat: now, exp: now + 3600 })
      .setProtectedHeader({ alg: 'EdDSA', typ: 'aa-person+jwt', kid: 'issuer-1' })
      .sign(ed.privateKey)

    void jwk
    await expect(
      verifyToken(opts(jwt, { httpSignatureThumbprint: agentThumb })),
    ).rejects.toThrow('MUST NOT be used')
  })

  it('rejects an unknown typ', async () => {
    const jwt = await signTestJwt(keys.issuerPrivate, 'aa-mystery+jwt', personClaims())
    try {
      await verifyToken(opts(jwt))
      expect.fail('should have thrown')
    } catch (err) {
      expect((err as AAuthTokenError).code).toBe('unsupported_token_type')
    }
  })
})

describe('time and key discovery', () => {
  it('rejects an expired token with a stable code', async () => {
    const past = Math.floor(Date.now() / 1000) - 7200
    const jwt = await signTestJwt(
      keys.issuerPrivate, 'aa-person+jwt', { ...personClaims(), iat: past, exp: past + 60 },
    )
    try {
      await verifyToken(opts(jwt))
      expect.fail('should have thrown')
    } catch (err) {
      expect((err as AAuthTokenError).code).toBe('token_expired')
      expect((err as Error).message).toBe('Token has expired')
    }
  })

  it('rejects an iat in the future', async () => {
    const future = Math.floor(Date.now() / 1000) + 7200
    const jwt = await signTestJwt(
      keys.issuerPrivate, 'aa-person+jwt', { ...personClaims(), iat: future, exp: future + 600 },
    )
    await expect(verifyToken(opts(jwt))).rejects.toThrow('iat is in the future')
  })

  it('rejects an iss that is not a server identifier', async () => {
    const jwt = await signTestJwt(
      keys.issuerPrivate, 'aa-person+jwt', personClaims({ iss: 'http://ps.example' }),
    )
    await expect(verifyToken(opts(jwt))).rejects.toThrow('not a valid HTTPS server identifier')
  })

  it('rejects when no JWKS key matches kid', async () => {
    const jwt = await signTestJwt(
      keys.issuerPrivate, 'aa-person+jwt', personClaims(), { kid: 'rotated-out' },
    )
    await expect(verifyToken(opts(jwt))).rejects.toThrow('No key with kid "rotated-out"')
  })

  it('rejects a signature made by a key the issuer does not publish', async () => {
    const rogue = await generateKeyPair('Ed25519', { extractable: true })
    const jwt = await signTestJwt(rogue.privateKey as CryptoKey, 'aa-person+jwt', personClaims())
    await expect(verifyToken(opts(jwt))).rejects.toThrow('signature verification failed')
  })

  it('surfaces a metadata fetch failure', async () => {
    const failing = vi.fn(async () => new Response('nope', { status: 500 }))
    const jwt = await signTestJwt(keys.issuerPrivate, 'aa-person+jwt', personClaims())
    await expect(verifyToken(opts(jwt, { fetch: failing })))
      .rejects.toThrow('Failed to fetch metadata')
  })

  it('caches discovery across calls', async () => {
    const jwt = await signTestJwt(keys.issuerPrivate, 'aa-person+jwt', personClaims())
    await verifyToken(opts(jwt))
    await verifyToken(opts(jwt))
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })
})

describe('call-site configuration', () => {
  it('requires an accept list', async () => {
    const jwt = await signTestJwt(keys.issuerPrivate, 'aa-person+jwt', personClaims())
    await expect(verifyToken(opts(jwt, { accept: [] }))).rejects.toThrow('requires an `accept` list')
  })

  it('requires the resource identifier to be a server identifier', async () => {
    const jwt = await signTestJwt(keys.issuerPrivate, 'aa-person+jwt', personClaims())
    await expect(verifyToken(opts(jwt, { resource: 'https://resource.example/' })))
      .rejects.toThrow('must be a valid HTTPS server identifier')
  })
})
