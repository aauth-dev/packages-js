import { describe, it, expect, beforeEach } from 'vitest'
import {
  verifyToken,
  AAuthTokenError,
  clearMetadataCache,
  MemoryRevocationStore,
  KVRevocationStore,
  applyRevocation,
  revocationResponse,
  handleRevocation,
  REVOKED_JWT,
  DWK,
  type RevocationKV,
} from './index.js'
import { createTestKeys, signTestJwt, mockJwksFetch, RESOURCE, PS, AP, type TestKeys } from './testing.js'

const AS = 'https://as.example'
const NOW = 1_800_000_000

let keys: TestKeys
let fetchMock: ReturnType<typeof mockJwksFetch>

beforeEach(async () => {
  clearMetadataCache()
  keys = await createTestKeys()
  fetchMock = mockJwksFetch([
    { iss: AP, dwk: 'aauth-agent.json', keys: [keys.issuerJwk] },
    { iss: PS, dwk: 'aauth-person.json', keys: [keys.issuerJwk] },
    { iss: AS, dwk: 'aauth-access.json', keys: [keys.issuerJwk] },
  ])
})

const caller = { id: PS, dwk: DWK.person }
const options = (store = new MemoryRevocationStore()) => ({ store, issuers: [PS, AS], now: NOW })

describe('MemoryRevocationStore', () => {
  it('keys entries by (iss, jti) and forgets them once exp plus skew has passed', async () => {
    let now = NOW
    const store = new MemoryRevocationStore({ now: () => now })
    await store.revoke(PS, 'jti-1', NOW + 100)
    expect(await store.isRevoked(PS, 'jti-1')).toBe(true)
    // Another issuer's jti-1 is a different token.
    expect(await store.isRevoked(AS, 'jti-1')).toBe(false)
    now = NOW + 100 + 60
    expect(await store.isRevoked(PS, 'jti-1')).toBe(true)
    now = NOW + 100 + 61
    expect(await store.isRevoked(PS, 'jti-1')).toBe(false)
    expect(store.size).toBe(0)
  })
})

describe('KVRevocationStore', () => {
  function fakeKv(): RevocationKV & { rows: Map<string, { value: string; ttl?: number }> } {
    const rows = new Map<string, { value: string; ttl?: number }>()
    return {
      rows,
      async get(key) {
        return rows.get(key)?.value ?? null
      },
      async put(key, value, opts) {
        rows.set(key, { value, ttl: opts?.expirationTtl })
      },
    }
  }

  it('writes a prefixed marker row with the token’s remaining lifetime plus skew as TTL', async () => {
    const kv = fakeKv()
    const store = new KVRevocationStore(kv, { now: () => NOW })
    await store.revoke(PS, 'jti-1', NOW + 600)
    expect(kv.rows.get(`revoked:${PS}:jti-1`)).toEqual({ value: '1', ttl: 660 })
    expect(await store.isRevoked(PS, 'jti-1')).toBe(true)
    expect(await store.isRevoked(PS, 'jti-2')).toBe(false)
  })

  it('never asks KV for a TTL under its 60 s floor', async () => {
    const kv = fakeKv()
    await new KVRevocationStore(kv, { now: () => NOW, prefix: 'rv:' }).revoke(PS, 'jti-1', NOW - 30)
    expect(kv.rows.get(`rv:${PS}:jti-1`)?.ttl).toBe(60)
  })
})

describe('applyRevocation', () => {
  it('records (caller, jti) until exp and answers 200 with an empty body', async () => {
    const store = new MemoryRevocationStore({ now: () => NOW })
    const outcome = await applyRevocation(caller, JSON.stringify({ jti: 'auth-1', exp: NOW + 3600 }), options(store))
    expect(outcome).toEqual({ ok: true, iss: PS, jti: 'auth-1', exp: NOW + 3600, expired: false })
    expect(await store.isRevoked(PS, 'auth-1')).toBe(true)
    const res = revocationResponse(outcome)
    expect(res.status).toBe(200)
    expect(await res.text()).toBe('')
    expect(res.headers.get('cache-control')).toBe('no-store')
  })

  it('accepts a parsed body as well as the JSON text', async () => {
    const store = new MemoryRevocationStore({ now: () => NOW })
    const outcome = await applyRevocation(caller, { jti: 'auth-2', exp: NOW + 60 }, options(store))
    expect(outcome.ok).toBe(true)
    expect(await store.isRevoked(PS, 'auth-2')).toBe(true)
  })

  it('keys the entry by the verified caller, never by anything in the body', async () => {
    const store = new MemoryRevocationStore({ now: () => NOW })
    // An `iss` in the body is not a parameter; it is ignored.
    await applyRevocation({ id: AS, dwk: DWK.access }, { jti: 'auth-1', exp: NOW + 60, iss: PS }, options(store))
    expect(await store.isRevoked(AS, 'auth-1')).toBe(true)
    expect(await store.isRevoked(PS, 'auth-1')).toBe(false)
  })

  it('answers 200 for a token already past its exp without recording it', async () => {
    const store = new MemoryRevocationStore({ now: () => NOW })
    const outcome = await applyRevocation(caller, { jti: 'old', exp: NOW - 120 }, options(store))
    expect(outcome).toMatchObject({ ok: true, expired: true })
    expect(store.size).toBe(0)
    expect(revocationResponse(outcome).status).toBe(200)
  })

  it('unsupported_iss (403) for a caller not on the list, a caller with the wrong dwk, or a non-identifier', async () => {
    for (const c of [
      { id: 'https://other-ps.example', dwk: DWK.person },
      { id: PS, dwk: DWK.agent },
      { id: PS, dwk: DWK.resource },
      { id: 'http://ps.example', dwk: DWK.person },
      { id: `${PS}/`, dwk: DWK.person },
    ]) {
      const outcome = await applyRevocation(c, { jti: 'x', exp: NOW + 60 }, options())
      expect(outcome, JSON.stringify(c)).toMatchObject({ ok: false, status: 403, error: 'unsupported_iss' })
      const res = revocationResponse(outcome)
      expect(res.status).toBe(403)
      expect(res.headers.get('content-type')).toBe('application/problem+json')
      expect((await res.json()) as unknown).toMatchObject({ error: 'unsupported_iss' })
    }
  })

  it('a resource may accept a narrower set of metadata documents', async () => {
    const outcome = await applyRevocation({ id: AS, dwk: DWK.access }, { jti: 'x', exp: NOW + 60 }, { ...options(), dwks: [DWK.person] })
    expect(outcome).toMatchObject({ ok: false, error: 'unsupported_iss' })
  })

  it('invalid_request (400) for malformed JSON, a non-object, or a missing or malformed jti / exp', async () => {
    for (const body of ['{not json', '[]', 'null', '"s"', '{}', '{"jti":"x"}', '{"exp":1}', '{"jti":"","exp":1}', '{"jti":"x","exp":"1"}', '{"jti":"x","exp":1.5}', '{"jti":"x","exp":-1}', '{"jti":5,"exp":1}']) {
      const outcome = await applyRevocation(caller, body, options())
      expect(outcome, body).toMatchObject({ ok: false, status: 400, error: 'invalid_request' })
    }
  })

  it('the caller is judged before the body: an unsupported caller with a broken body is 403', async () => {
    const outcome = await applyRevocation({ id: 'https://other-ps.example', dwk: DWK.person }, '{not json', options())
    expect(outcome).toMatchObject({ ok: false, status: 403 })
  })

  it('invalid_request for an exp further out than the longest lifetime the resource accepts', async () => {
    const day = 24 * 3600
    expect(await applyRevocation(caller, { jti: 'x', exp: NOW + day + 61 }, options())).toMatchObject({ ok: false, status: 400, error: 'invalid_request' })
    expect(await applyRevocation(caller, { jti: 'x', exp: NOW + day + 60 }, options())).toMatchObject({ ok: true })
    expect(await applyRevocation(caller, { jti: 'x', exp: NOW + 7200 }, { ...options(), maxLifetimeSeconds: 3600 })).toMatchObject({ ok: false, status: 400 })
  })

  it('handleRevocation reads the body off the Request', async () => {
    const store = new MemoryRevocationStore({ now: () => NOW })
    const req = new Request(`${RESOURCE}/aauth/revoke`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jti: 'auth-9', exp: NOW + 60 }),
    })
    const res = await handleRevocation(req, caller, options(store))
    expect(res.status).toBe(200)
    expect(await store.isRevoked(PS, 'auth-9')).toBe(true)
  })
})

describe('verifyToken with a revocation list', () => {
  function opts(jwt: string, revocation?: MemoryRevocationStore) {
    return {
      jwt,
      httpSignatureThumbprint: keys.agentThumbprint,
      resource: RESOURCE,
      accept: ['agent', 'person', 'auth'] as const,
      fetch: fetchMock as never,
      revocation,
    }
  }
  const authClaims = (jti: string, over: Record<string, unknown> = {}) => ({
    iss: PS,
    dwk: 'aauth-person.json',
    aud: RESOURCE,
    jti,
    ps: PS,
    sub: '8f14e45fceea167a5a36dedd4bea2543',
    cnf: { jwk: keys.agentJwk },
    ...over,
  })

  it('refuses a revoked auth token with revoked_jwt, and only that token', async () => {
    const store = new MemoryRevocationStore()
    await store.revoke(PS, 'auth-1', Math.floor(Date.now() / 1000) + 3600)
    const revoked = await signTestJwt(keys.issuerPrivate, 'aa-auth+jwt', authClaims('auth-1'))
    const other = await signTestJwt(keys.issuerPrivate, 'aa-auth+jwt', authClaims('auth-2'))

    await expect(verifyToken(opts(revoked, store))).rejects.toMatchObject({ code: REVOKED_JWT })
    await expect(verifyToken(opts(other, store))).resolves.toMatchObject({ type: 'auth', jti: 'auth-2' })
    // The same token without a list attached still verifies: the check is opt-in.
    await expect(verifyToken(opts(revoked))).resolves.toMatchObject({ type: 'auth' })
  })

  it('keys on the issuer: a revocation from the AS does not touch the PS’s token of the same jti', async () => {
    const store = new MemoryRevocationStore()
    await store.revoke(AS, 'auth-1', Math.floor(Date.now() / 1000) + 3600)
    const psToken = await signTestJwt(keys.issuerPrivate, 'aa-auth+jwt', authClaims('auth-1'))
    const asToken = await signTestJwt(keys.issuerPrivate, 'aa-auth+jwt', authClaims('auth-1', { iss: AS, dwk: 'aauth-access.json' }))
    await expect(verifyToken(opts(psToken, store))).resolves.toMatchObject({ iss: PS })
    await expect(verifyToken(opts(asToken, store))).rejects.toMatchObject({ code: REVOKED_JWT })
  })

  it('applies to person and agent tokens too', async () => {
    const store = new MemoryRevocationStore()
    const exp = Math.floor(Date.now() / 1000) + 3600
    await store.revoke(PS, 'pt-1', exp)
    await store.revoke(AP, 'at-1', exp)
    const person = await signTestJwt(keys.issuerPrivate, 'aa-person+jwt', {
      iss: PS, dwk: 'aauth-person.json', aud: RESOURCE, sub: 'u', jti: 'pt-1', cnf: { jwk: keys.agentJwk },
    })
    const agent = await signTestJwt(keys.issuerPrivate, 'aa-agent+jwt', {
      iss: AP, dwk: 'aauth-agent.json', sub: 'aauth:a@agent.example', jti: 'at-1', cnf: { jwk: keys.agentJwk },
    })
    await expect(verifyToken(opts(person, store))).rejects.toMatchObject({ code: REVOKED_JWT })
    await expect(verifyToken(opts(agent, store))).rejects.toMatchObject({ code: REVOKED_JWT })
  })

  it('runs after every other check: a revoked token that also fails verification reports the earlier failure', async () => {
    const store = new MemoryRevocationStore()
    await store.revoke(PS, 'auth-1', Math.floor(Date.now() / 1000) + 3600)
    const wrongAud = await signTestJwt(keys.issuerPrivate, 'aa-auth+jwt', authClaims('auth-1', { aud: 'https://elsewhere.example' }))
    await expect(verifyToken(opts(wrongAud, store))).rejects.toMatchObject({ code: 'aud_mismatch' })
    const expired = await signTestJwt(keys.issuerPrivate, 'aa-auth+jwt', authClaims('auth-1', { exp: Math.floor(Date.now() / 1000) - 3600 }))
    const err = await verifyToken(opts(expired, store)).catch((e: unknown) => e)
    expect(err).toBeInstanceOf(AAuthTokenError)
    expect((err as AAuthTokenError).code).toBe('token_expired')
  })
})
