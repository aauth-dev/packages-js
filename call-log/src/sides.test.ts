import { describe, it, expect } from 'vitest'
import { createHash } from 'node:crypto'
import { callLogMiddleware, loggedFetch, loggedHttpsigFetch, failedFetch, nameAgent, parentFromContext, runInCall, type CallRecord, type CallLogHost } from './index.js'

const sha = (s: string) => createHash('sha256').update(s).digest('base64url')
const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url')
const agentJwt = `${b64({ alg: 'Ed25519', typ: 'aa-agent+jwt' })}.${b64({ iss: 'https://ap.example', sub: 'aauth:owl@ap.example', jti: 'agt_1' })}.c2ln`

/** A host that keeps its records and runs deferred work so a test can await it. */
function testHost(role: CallLogHost['role'] = 'resource') {
  const records: CallRecord[] = []
  const pending: Promise<unknown>[] = []
  const host: CallLogHost = { origin: 'https://encrypt.aauth.dev', role, log: (r) => { records.push(r) }, defer: (p) => { pending.push(p) } }
  const settled = async () => { await Promise.all(pending) }
  return { host, records, settled }
}

/** The little of Hono the middleware touches, driven by hand. */
function contextFor(request: Request, handler: () => Promise<Response>) {
  const c = { req: { raw: request }, res: new Response(null, { status: 404 }) }
  const next = async () => { c.res = await handler() }
  return { c, next }
}

describe('the callee side', () => {
  it('names the call from the Signature header, reads both bodies, and logs one record after the response', async () => {
    const { host, records, settled } = testHost()
    const mw = callLogMiddleware(host)
    const request = new Request('https://encrypt.aauth.dev/send?dry=1', {
      method: 'POST',
      headers: { 'content-type': 'application/json', signature: 'sig=:AAAA:', 'signature-key': `sig=jwt; jwt="${agentJwt}"` },
      body: JSON.stringify({ to: 'mailto:bob@example.com' }),
    })
    let parentSeen: string | undefined
    let bodySeenByHandler: unknown
    const { c, next } = contextFor(request, async () => {
      parentSeen = parentFromContext()
      bodySeenByHandler = await request.json() // the handler still reads the body
      return Response.json({ error: 'person_token_required' }, { status: 401, headers: { 'AAuth-Requirement': 'requirement=person-token' } })
    })
    await mw(c, next)
    expect(records).toEqual([]) // nothing on the request path
    await settled()
    expect(bodySeenByHandler).toEqual({ to: 'mailto:bob@example.com' })
    expect(parentSeen).toBe(sha('sig=:AAAA:'))
    expect(records).toHaveLength(1)
    const [r] = records
    expect(r).toMatchObject({
      side: 'callee', call_id: sha('sig=:AAAA:'), from: 'aauth:owl@ap.example', from_role: 'agent', agent: 'aauth:owl@ap.example',
      to: 'https://encrypt.aauth.dev', to_role: 'resource', method: 'POST', path: '/send', query: 'dry=1', status: 401, level: 30,
      signed: { scheme: 'jwt', token: { type: 'aa-agent+jwt' } },
      request: { body: { to: 'mailto:bob@example.com' } },
      response: { params: { 'AAuth-Requirement': { requirement: 'person-token' } }, body: { error: 'person_token_required' } },
      error: 'person_token_required',
    })
    expect(r.duration_ms).toBeTypeOf('number')
    expect(r.parent).toBeUndefined()
  })

  it('takes the agent from the verifier when the token names none, and skips what is not a call', async () => {
    const { host, records, settled } = testHost('ps')
    const mw = callLogMiddleware(host)
    const personJwt = `${b64({ alg: 'Ed25519', typ: 'aa-person+jwt' })}.${b64({ iss: 'https://ps.example', sub: 'pw_1', jti: 'ptk_1' })}.c2ln`
    const request = new Request('https://encrypt.aauth.dev/aauth/person', { headers: { signature: 'sig=:BBBB:', 'signature-key': `sig=jwt; jwt="${personJwt}"` } })
    const { c, next } = contextFor(request, async () => { nameAgent('aauth:fox@ap.example'); return Response.json({ sub: 'pw_1' }) })
    await mw(c, next)
    await settled()
    expect(records[0]).toMatchObject({ from: 'aauth:fox@ap.example', from_role: 'agent', agent: 'aauth:fox@ap.example', status: 200 })
    for (const url of ['https://encrypt.aauth.dev/.well-known/aauth-resource.json', 'https://encrypt.aauth.dev/health']) {
      const skipped = contextFor(new Request(url), async () => Response.json({}))
      await mw(skipped.c, skipped.next)
    }
    const options = contextFor(new Request('https://encrypt.aauth.dev/send', { method: 'OPTIONS' }), async () => new Response(null, { status: 204 }))
    await mw(options.c, options.next)
    await settled()
    expect(records).toHaveLength(1)
  })

  it('an unsigned call has a random id and no caller; its own 5xx is error level', async () => {
    const { host, records, settled } = testHost()
    const { c, next } = contextFor(new Request('https://encrypt.aauth.dev/send', { method: 'POST' }), async () => new Response('boom', { status: 500 }))
    await callLogMiddleware(host)(c, next)
    await settled()
    expect(records[0]).toMatchObject({ status: 500, level: 50 })
    expect(records[0].call_id).toMatch(/^[0-9a-f-]{36}$/)
    expect(records[0].from).toBeUndefined()
    expect(records[0].signed).toBeUndefined()
  })
})

describe('the caller side', () => {
  const sent = (signature: string) => ({ headers: new Headers({ signature, 'signature-key': 'sig=jwks_uri; id="https://encrypt.aauth.dev"; dwk="aauth-agent.json"; kid="k"' }) })

  it('loggedFetch: one signed fetch per call, call_id from what it sent, the parent from the context, the reply read from a clone', async () => {
    const { host, records, settled } = testHost()
    const makeFetch = (onSigned: (s: { headers: Headers }) => void) => async (url: string) => {
      onSigned(sent(`sig=:${url.endsWith('/a') ? 'AAAA' : 'BBBB'}:`))
      return Response.json({ person_token: agentJwt }, { headers: { 'content-type': 'application/json' } })
    }
    const fetchA = loggedFetch(makeFetch, host, { to_role: 'ps', agent: 'aauth:owl@ap.example' })
    const [ra, rb] = await runInCall({ callId: 'parent-1' }, () => Promise.all([
      fetchA('https://ps.example/aauth/token/person?x=1', { method: 'POST', body: JSON.stringify({ resource: 'https://r.example', upstream_token: agentJwt }) }),
      fetchA('https://ps.example/b'),
    ]))
    expect(await ra.json()).toMatchObject({ person_token: agentJwt }) // the caller's own read is untouched
    expect(rb.status).toBe(200)
    await settled()
    expect(records).toHaveLength(2)
    const a = records.find((r) => r.path === '/aauth/token/person')!
    expect(a).toMatchObject({
      side: 'caller', call_id: sha('sig=:BBBB:'), parent: 'parent-1', from: 'https://encrypt.aauth.dev', from_role: 'resource',
      to: 'https://ps.example', to_role: 'ps', agent: 'aauth:owl@ap.example', method: 'POST', query: 'x=1', status: 200, level: 30,
      signed: { scheme: 'jwks_uri', id: 'https://encrypt.aauth.dev' },
      request: { body: { resource: 'https://r.example', upstream_token: { type: 'aa-agent+jwt' } } },
      response: { body: { person_token: { type: 'aa-agent+jwt' } } },
    })
    expect(records.find((r) => r.path === '/b')!.call_id).toBe(sha('sig=:BBBB:'))
    expect(records.find((r) => r.path === '/b')!.request).toBeUndefined()
  })

  it('an explicit parent wins over the context; outside any call there is none', async () => {
    const { host, records, settled } = testHost()
    const makeFetch = (onSigned: (s: { headers: Headers }) => void) => async () => { onSigned(sent('sig=:C:')); return new Response(null, { status: 204 }) }
    await runInCall({ callId: 'ctx' }, () => loggedFetch(makeFetch, host, { parent: 'given' })('https://r.example/x'))
    await loggedFetch(makeFetch, host)('https://r.example/y')
    await settled()
    expect(records.map((r) => r.parent)).toEqual(['given', undefined])
  })

  it('a refusal carries the error code; a throw is a record with no status, at warn', async () => {
    const { host, records, settled } = testHost()
    const refuse = (onSigned: (s: { headers: Headers }) => void) => async () => { onSigned(sent('sig=:D:')); return Response.json({ error: 'unsupported_iss' }, { status: 403 }) }
    await loggedFetch(refuse, host)('https://as.example/revoke', { method: 'POST', body: '{"jti":"x"}' })
    const boom = () => async () => { throw Object.assign(new Error('aborted'), { name: 'TimeoutError' }) }
    await expect(loggedFetch(boom, host)('https://as.example/revoke')).rejects.toThrow('aborted')
    await settled()
    const outcomes = records.map((r) => [r.status, r.error, r.level]).sort((a, b) => String(a[1]).localeCompare(String(b[1])))
    expect(outcomes).toEqual([[undefined, 'timeout', 40], [403, 'unsupported_iss', 40]])
  })

  it('loggedHttpsigFetch asks for the sent request and unwraps it', async () => {
    const { host, records, settled } = testHost('ps')
    const seen: Record<string, unknown>[] = []
    const httpsig = async (_url: string, options: Record<string, unknown>) => {
      seen.push(options)
      return { response: Response.json({ auth_token: agentJwt }, { headers: { 'AAuth-Budget': 'cost=1; remaining=9; unit="credits"' } }), sent: sent('sig=:E:') }
    }
    const res = await loggedHttpsigFetch(httpsig, host, { to_role: 'as' })('https://as.example/token', { method: 'POST', body: '{}', signingKey: {} })
    expect(res.status).toBe(200)
    expect(seen[0].returnSent).toBe(true)
    await settled()
    expect(records[0]).toMatchObject({ call_id: sha('sig=:E:'), to_role: 'as', response: { params: { 'AAuth-Budget': { cost: '1', remaining: '9', unit: 'credits' } }, body: { auth_token: { type: 'aa-agent+jwt' } } } })
  })

  it('failedFetch records a fetch the caller could not wrap', () => {
    const { host, records } = testHost('ps')
    runInCall({ callId: 'p' }, () => failedFetch(host, { url: 'https://r.example/.well-known/aauth-resource.json', to_role: 'resource', status: 404 }))
    expect(records[0]).toMatchObject({ side: 'caller', parent: 'p', method: 'GET', path: '/.well-known/aauth-resource.json', status: 404, level: 40 })
  })
})
