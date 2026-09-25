import { describe, it, expect } from 'vitest'
import { createHash } from 'node:crypto'
import { callIdOf, tokenOf, tokenize, signerOf, paramsOf, errorOf, levelOf, partOf, cap, buildRecord, targetOf, MAX_RECORD_BYTES } from './index.js'

const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url')
const jwt = (typ: string, payload: Record<string, unknown>) => `${b64({ alg: 'Ed25519', typ })}.${b64(payload)}.c2ln`
const PS = 'https://person.hello-beta.net'
const person = jwt('aa-person+jwt', { iss: PS, aud: 'https://r.example', jti: 'ptk_1', agent_id: 'aauth:a@ap.example' })

describe('call_id', () => {
  it('is base64url SHA-256 of the Signature header; random without one', async () => {
    expect(await callIdOf('sig=:abc:')).toBe(createHash('sha256').update('sig=:abc:').digest('base64url'))
    expect(await callIdOf(undefined)).toMatch(/^[0-9a-f-]{36}$/)
  })
})

describe('tokens', () => {
  it('a JWT is its typ and payload; a JWE and plain strings stay', () => {
    expect(tokenOf(person)).toEqual({ type: 'aa-person+jwt', payload: { iss: PS, aud: 'https://r.example', jti: 'ptk_1', agent_id: 'aauth:a@ap.example' } })
    expect(tokenOf('a.b.c.d.e')).toBeNull()
    expect(tokenOf('https://r.example/path')).toBeNull()
    expect(tokenize({ t: person, list: [{ t: person }], n: 1 })).toEqual({ t: tokenOf(person), list: [{ t: tokenOf(person) }], n: 1 })
  })
})

describe('the signer', () => {
  it('an agent token names the agent in sub; a person or auth token in agent_id or agent', () => {
    const agent = jwt('aa-agent+jwt', { iss: 'https://ap.example', sub: 'aauth:a@ap.example', jti: 'agt_1' })
    expect(signerOf(`sig=jwt; jwt="${agent}"`)).toEqual({ signed: { scheme: 'jwt', token: tokenOf(agent) }, from: 'aauth:a@ap.example', from_role: 'agent', agent: 'aauth:a@ap.example' })
    expect(signerOf(`sig=jwt; jwt="${person}"`).agent).toBe('aauth:a@ap.example')
    const auth = jwt('aa-auth+jwt', { iss: 'https://access.example', agent: 'aauth:f@ap.example' })
    expect(signerOf(`sig=jwt; jwt="${auth}"`).from).toBe('aauth:f@ap.example')
    const bare = jwt('aa-person+jwt', { iss: PS, sub: 'pw_1' })
    expect(signerOf(`sig=jwt; jwt="${bare}"`)).toEqual({ signed: { scheme: 'jwt', token: tokenOf(bare) }, from: undefined, from_role: undefined, agent: undefined })
  })

  it('jwks_uri names the server and its role by dwk; hwk names nothing; junk is nothing', () => {
    expect(signerOf('sig=jwks_uri; id="https://access.example"; dwk="aauth-access.json"; kid="k1"')).toEqual({
      signed: { scheme: 'jwks_uri', id: 'https://access.example', dwk: 'aauth-access.json', kid: 'k1' }, from: 'https://access.example', from_role: 'as',
    })
    expect(signerOf('sig=hwk; jwk="{\\"kty\\":\\"OKP\\"}"')).toEqual({ signed: { scheme: 'hwk' } })
    expect(signerOf('not a dictionary =')).toEqual({})
    expect(signerOf(null)).toEqual({})
  })
})

describe('params, error, level', () => {
  it('parses the three AAuth headers and passes Location', () => {
    const params = paramsOf(new Headers({
      'aauth-requirement': 'requirement=interaction; url="https://ps.example/auth"; code="K7QX-M2"',
      'signature-error': 'error=revoked_jwt',
      'aauth-budget': 'cost=2; remaining=98; unit="credits"',
      location: '/aauth/pending/pnd_1',
    }))
    expect(params).toEqual({
      'AAuth-Requirement': { requirement: 'interaction', url: 'https://ps.example/auth', code: 'K7QX-M2' },
      'Signature-Error': { error: 'revoked_jwt' },
      'AAuth-Budget': { cost: '2', remaining: '98', unit: 'credits' },
      Location: '/aauth/pending/pnd_1',
    })
    expect(paramsOf(new Headers({ 'content-type': 'application/json' }))).toBeUndefined()
    expect(paramsOf({ 'aauth-requirement': 'requirement=person-token' })).toEqual({ 'AAuth-Requirement': { requirement: 'person-token' } })
    expect(errorOf(params, { error: 'other' })).toBe('revoked_jwt')
    expect(errorOf(undefined, { error: 'invalid_request' })).toBe('invalid_request')
    expect(errorOf(undefined, { error: { message: 'NO_SESSION' } })).toBe('NO_SESSION')
  })

  it('a challenge is 30, a refusal 40, our own 5xx 50, a peer failure 40', () => {
    const chal = { params: { 'AAuth-Requirement': { requirement: 'person-token' } } }
    expect(levelOf({ side: 'callee', status: 200 })).toBe(30)
    expect(levelOf({ side: 'callee', status: 401, response: chal })).toBe(30)
    expect(levelOf({ side: 'callee', status: 202, response: chal })).toBe(30)
    expect(levelOf({ side: 'callee', status: 401 })).toBe(40)
    expect(levelOf({ side: 'callee', status: 502 })).toBe(50)
    expect(levelOf({ side: 'caller', status: 502 })).toBe(40)
    expect(levelOf({ side: 'caller' })).toBe(40)
  })
})

describe('bodies', () => {
  it('a JSON body becomes a value with its tokens as payloads; anything else its type and size', async () => {
    const json = new Response(JSON.stringify({ person_token: person, n: 1 }), { headers: { 'content-type': 'application/json' } })
    expect(await partOf(json)).toEqual({ body: { person_token: tokenOf(person), n: 1 } })
    const sse = new Response('data: x\n\n', { headers: { 'content-type': 'text/event-stream', 'content-length': '9' } })
    expect(await partOf(sse)).toEqual({ content_type: 'text/event-stream', size: 9 })
    const bad = new Response('{not json', { headers: { 'content-type': 'application/json' } })
    expect(await partOf(bad)).toEqual({ content_type: 'application/json', size: 9 })
    expect(await partOf(null)).toBeUndefined()
    expect(await partOf(null, { Location: '/x' })).toEqual({ params: { Location: '/x' } })
    expect(await partOf(new Response(null))).toBeUndefined()
  })

  it('the cap cuts the larger body to text and says so', () => {
    const big = { entities: Array.from({ length: 2000 }, (_, i) => ({ id: i, name: `Robert Smith ${i}` })) }
    const r = cap({ request: { body: { q: 'x' } }, response: { body: big } })
    expect(r.truncated).toBe(true)
    expect(typeof r.response!.body).toBe('string')
    expect(r.request!.body).toEqual({ q: 'x' })
    expect(Buffer.byteLength(JSON.stringify(r))).toBeLessThanOrEqual(MAX_RECORD_BYTES)
    expect(cap({ request: { body: { q: 'x' } } }).truncated).toBeUndefined()
  })
})

describe('the record', () => {
  it('has the level, a message, no undefined fields, and a target split from the url', () => {
    const r = buildRecord({ side: 'callee', call_id: 'c', to: 'https://r.example', to_role: 'resource', method: 'POST', path: '/send', status: 401, started_at: 't', from: undefined, response: { params: { 'AAuth-Requirement': { requirement: 'person-token' } }, body: undefined } })
    expect(r).toEqual({ event: 'aauth.call', side: 'callee', call_id: 'c', to: 'https://r.example', to_role: 'resource', method: 'POST', path: '/send', status: 401, started_at: 't', response: { params: { 'AAuth-Requirement': { requirement: 'person-token' } } }, level: 30, msg: 'callee POST https://r.example/send → 401' })
    expect(buildRecord({ side: 'person', call_id: 'p', to: PS, action: 'approved', started_at: 't' }).msg).toBe('Person approved')
    expect(targetOf('https://secret.agent.coop/public-key?from=a&to=b')).toEqual({ to: 'https://secret.agent.coop', path: '/public-key', query: 'from=a&to=b' })
    expect(targetOf('nonsense')).toEqual({ to: 'nonsense' })
  })
})
