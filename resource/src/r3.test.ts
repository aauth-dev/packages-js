import { describe, it, expect, beforeEach } from 'vitest'
import {
  serializeR3Document,
  computeR3Hash,
  publishR3Document,
  serveR3Document,
  isAuthorizedR3Fetcher,
  assertAuthorizedR3Fetcher,
  verifyR3Hash,
  getR3ByHash,
  getR3ByUri,
  parseR3Record,
  MemoryR3Store,
  R3Error,
} from './index.js'
import type { R3Document } from './index.js'
import { RESOURCE, PS } from './testing.js'

const AS = 'https://as.example'
const AGENT_PS = 'https://agent-ps.example'

const doc: R3Document = {
  vocabulary: 'urn:aauth:vocabulary:mcp',
  operations: [{ tool: 'create_calendar_event' }, { tool: 'modify_calendar_event' }],
  account: 'dick@example.com',
  display: {
    summary: 'Create and modify events on your work calendar (dick@example.com)',
    implications: 'Meetings can be scheduled or rescheduled.',
    data_accessed: 'Event titles, times, attendees',
    irreversible: 'Sent meeting invitations cannot be unsent',
  },
}

let store: MemoryR3Store

beforeEach(() => {
  store = new MemoryR3Store()
})

describe('content addressing', () => {
  it('hashes the bytes as served', async () => {
    const { body, s256 } = await serializeR3Document(doc)
    expect(await computeR3Hash(body)).toBe(s256)
    expect(await verifyR3Hash(body, s256)).toBe(true)
  })

  it('serves byte-identical bytes on every request for the same r3_uri', async () => {
    const published = await publishR3Document({
      document: doc, baseUri: `${RESOURCE}/r3`, store, authorized: [PS],
    })

    const first = await serveR3Document({ store, key: published.r3_uri, signer: PS })
    const second = await serveR3Document({ store, key: published.r3_uri, signer: PS })

    expect(first.body).toBe(second.body)
    expect(first.body).toBe(published.body)
    expect(await computeR3Hash(first.body)).toBe(published.r3_s256)
  })

  it('breaks if the served bytes are re-stringified — the reason we store them', async () => {
    const { body, s256 } = await serializeR3Document(doc)
    // A framework `json()` helper, CDN minification, or any parse/re-encode.
    const reStringified = JSON.stringify(JSON.parse(body), null, 2)
    expect(await computeR3Hash(reStringified)).not.toBe(s256)
  })

  it('a document with different bytes gets a different hash and URI', async () => {
    const a = await publishR3Document({
      document: doc, baseUri: `${RESOURCE}/r3`, store, authorized: [PS],
    })
    const b = await publishR3Document({
      document: { ...doc, account: 'other@example.com' },
      baseUri: `${RESOURCE}/r3`, store, authorized: [PS],
    })
    expect(b.r3_s256).not.toBe(a.r3_s256)
    expect(b.r3_uri).not.toBe(a.r3_uri)
  })

  it('rejects a document carrying the removed `version` field', async () => {
    await expect(
      serializeR3Document({ ...doc, version: '1' } as unknown as R3Document),
    ).rejects.toThrow('removed the `version` field')
  })

  it('requires vocabulary and operations', async () => {
    await expect(serializeR3Document({ operations: [{}] } as unknown as R3Document))
      .rejects.toThrow('requires a `vocabulary`')
    await expect(serializeR3Document({ vocabulary: 'urn:x', operations: [] }))
      .rejects.toThrow('requires a non-empty `operations`')
  })
})

describe('publication', () => {
  it('stores under both the hash and the URI', async () => {
    const p = await publishR3Document({
      document: doc, baseUri: `${RESOURCE}/r3`, store, authorized: [PS, AGENT_PS],
    })

    const byHash = await getR3ByHash(store, p.r3_s256)
    const byUri = await getR3ByUri(store, p.r3_uri)
    expect(byHash?.body).toBe(p.body)
    expect(byUri?.body).toBe(p.body)
    expect(p.r3_uri).toBe(`${RESOURCE}/r3/${p.r3_s256}`)
  })

  it('accepts an explicit URI', async () => {
    const p = await publishR3Document({
      document: doc, uri: `${RESOURCE}/r3/opaque-id`, store, authorized: [PS],
    })
    expect(p.r3_uri).toBe(`${RESOURCE}/r3/opaque-id`)
    expect((await getR3ByUri(store, p.r3_uri))?.s256).toBe(p.r3_s256)
  })

  it('refuses to publish with no entitled fetcher', async () => {
    await expect(
      publishR3Document({ document: doc, baseUri: `${RESOURCE}/r3`, store, authorized: [undefined] }),
    ).rejects.toThrow('at least one authorized fetcher')
  })

  it('requires HTTPS', async () => {
    await expect(
      publishR3Document({ document: doc, uri: 'http://resource.example/r3/x', store, authorized: [PS] }),
    ).rejects.toThrow('MUST be served over HTTPS')
  })

  it('round-trips through a JSON-encoding store without changing the bytes', async () => {
    // Cloudflare KV stores `JSON.stringify(record)`; the body string survives.
    const p = await publishR3Document({
      document: doc, baseUri: `${RESOURCE}/r3`, store, authorized: [PS],
    })
    const record = (await getR3ByHash(store, p.r3_s256))!
    const roundTripped = JSON.parse(JSON.stringify(record)) as typeof record
    expect(roundTripped.body).toBe(p.body)
    expect(await computeR3Hash(roundTripped.body)).toBe(p.r3_s256)
  })

  it('parses back for inspection', async () => {
    const p = await publishR3Document({
      document: doc, baseUri: `${RESOURCE}/r3`, store, authorized: [PS],
    })
    expect(parseR3Record((await getR3ByHash(store, p.r3_s256))!)).toEqual(doc)
  })
})

describe('R3 document access restriction', () => {
  it('serves to the AS named in the resource token aud', async () => {
    const p = await publishR3Document({
      document: doc, baseUri: `${RESOURCE}/r3`, store, authorized: [AS, AGENT_PS],
    })
    const res = await serveR3Document({ store, key: p.r3_uri, signer: AS })
    expect(res.status).toBe(200)
    expect(res.body).toBe(p.body)
    expect(res.headers.ETag).toBe(`"${p.r3_s256}"`)
  })

  it('serves to the PS named by the agent token ps claim', async () => {
    const p = await publishR3Document({
      document: doc, baseUri: `${RESOURCE}/r3`, store, authorized: [AS, AGENT_PS],
    })
    expect((await serveR3Document({ store, key: p.r3_uri, signer: AGENT_PS })).status).toBe(200)
  })

  it('rejects the agent — agents must never read R3 documents', async () => {
    const p = await publishR3Document({
      document: doc, baseUri: `${RESOURCE}/r3`, store, authorized: [AS, AGENT_PS],
    })
    const res = await serveR3Document({ store, key: p.r3_uri, signer: 'https://agent.example' })
    expect(res.status).toBe(403)
    expect(res.body).not.toContain('create_calendar_event')
  })

  it('rejects some other PS', async () => {
    const p = await publishR3Document({
      document: doc, baseUri: `${RESOURCE}/r3`, store, authorized: [AS, AGENT_PS],
    })
    expect((await serveR3Document({ store, key: p.r3_uri, signer: PS })).status).toBe(403)
  })

  it('rejects an unsigned request', async () => {
    const p = await publishR3Document({
      document: doc, baseUri: `${RESOURCE}/r3`, store, authorized: [AS],
    })
    const res = await serveR3Document({ store, key: p.r3_uri, signer: undefined })
    expect(res.status).toBe(401)
    expect(JSON.parse(res.body).error).toBe('signature_required')
  })

  it('404s an unknown document', async () => {
    expect((await serveR3Document({ store, key: `${RESOURCE}/r3/nope`, signer: AS })).status)
      .toBe(404)
  })

  it('compares identifiers by exact string equality', async () => {
    const p = await publishR3Document({
      document: doc, baseUri: `${RESOURCE}/r3`, store, authorized: [AS],
    })
    const record = (await getR3ByHash(store, p.r3_s256))!
    expect(isAuthorizedR3Fetcher(record, AS)).toBe(true)
    expect(isAuthorizedR3Fetcher(record, `${AS}/`)).toBe(false)
    expect(isAuthorizedR3Fetcher(record, AS.toUpperCase())).toBe(false)
    expect(isAuthorizedR3Fetcher(record, '')).toBe(false)
  })

  it('assertAuthorizedR3Fetcher throws with a code', async () => {
    const p = await publishR3Document({
      document: doc, baseUri: `${RESOURCE}/r3`, store, authorized: [AS],
    })
    const record = (await getR3ByHash(store, p.r3_s256))!
    expect(() => assertAuthorizedR3Fetcher(record, undefined))
      .toThrow(R3Error)
    try {
      assertAuthorizedR3Fetcher(record, 'https://agent.example')
      expect.fail('should have thrown')
    } catch (err) {
      expect((err as R3Error).code).toBe('r3_fetch_forbidden')
    }
  })
})
