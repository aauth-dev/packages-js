import { describe, it, expect, beforeEach } from 'vitest'
import {
  buildProposal,
  publishProposal,
  digestParameter,
  isParameterDigest,
  isProposal,
  verifyProposalParameters,
  publishR3Document,
  serveR3Document,
  createResourceToken,
  MemoryR3Store,
  R3Error,
} from './index.js'
import type { SignFn } from './index.js'
import { RESOURCE, PS, MISSION_S256 } from './testing.js'

const AS = 'https://as.example'
const AGENT_PS = 'https://agent-ps.example'

let store: MemoryR3Store

beforeEach(() => {
  store = new MemoryR3Store()
})

const BODY = 'Hi Mom, are you free for dinner on Sunday? It has been a while.'

async function emailProposal() {
  return publishProposal({
    vocabulary: 'urn:aauth:vocabulary:mcp',
    operation: { tool: 'send_email' },
    parameters: {
      to: 'mom@example.com',
      subject: 'Dinner Sunday?',
      body: await digestParameter(BODY, { media_type: 'text/plain', excerptLength: 20 }),
    },
    display: {
      summary: 'Send an email as you',
      detail: '## Action\nSend an email\n\n## To\nmom@example.com',
    },
    store,
    baseUri: `${RESOURCE}/r3`,
    authorized: [AS, AGENT_PS],
  })
}

describe('buildProposal', () => {
  it('requires parameters', () => {
    expect(() =>
      buildProposal({
        vocabulary: 'urn:aauth:vocabulary:mcp',
        operation: { tool: 'send_email' },
        parameters: undefined as never,
      }),
    ).toThrow('requires a `parameters` object')
  })

  it('scopes the document to one operation', () => {
    const p = buildProposal({
      vocabulary: 'urn:aauth:vocabulary:mcp',
      operation: { tool: 'send_email' },
      parameters: { to: 'mom@example.com' },
    })
    expect(p.operations).toEqual([{ tool: 'send_email' }])
    expect(p.parameters).toEqual({ to: 'mom@example.com' })
    expect((p as Record<string, unknown>).version).toBeUndefined()
  })
})

describe('digestParameter', () => {
  it('produces s256, excerpt and media_type', async () => {
    const d = await digestParameter(BODY, { media_type: 'text/plain', excerptLength: 20 })
    expect(d.s256).toMatch(/^[A-Za-z0-9_-]{43}$/)
    expect(d.excerpt).toBe('Hi Mom, are you free…')
    expect(d.media_type).toBe('text/plain')
    expect(isParameterDigest(d)).toBe(true)
    // The full value never appears in the proposal.
    expect(JSON.stringify(d)).not.toContain('dinner on Sunday')
  })
})

describe('the per-call flow', () => {
  it('challenges with a resource token that carries only the reference', async () => {
    const published = await emailProposal()

    let payload: Record<string, unknown> = {}
    const sign: SignFn = async p => { payload = p; return 'jwt' }
    await createResourceToken(
      {
        resource: RESOURCE,
        audience: AS,
        personToken: { iss: PS, sub: 'u-1', jti: 'pt-1', mission_s256: MISSION_S256 },
        agentJkt: 'jkt-1',
        scope: 'email.send',
        r3: { uri: published.r3_uri, s256: published.r3_s256 },
      },
      sign,
    )

    expect(payload.r3_uri).toBe(published.r3_uri)
    expect(payload.r3_s256).toBe(published.r3_s256)
    expect(payload.mission_s256).toBe(MISSION_S256)
    // The parameters are in the proposal, never in the token.
    expect(JSON.stringify(payload)).not.toContain('mom@example.com')
  })

  it('accepts the retry when the parameters match exactly', async () => {
    const published = await emailProposal()
    const verified = await verifyProposalParameters({
      store,
      r3_s256: published.r3_s256,
      presented: { to: 'mom@example.com', subject: 'Dinner Sunday?', body: BODY },
      operation: { tool: 'send_email' },
    })
    expect(verified.document.operations).toEqual([{ tool: 'send_email' }])
  })

  it('rejects a different recipient — an approval cannot be replayed', async () => {
    const published = await emailProposal()
    try {
      await verifyProposalParameters({
        store,
        r3_s256: published.r3_s256,
        presented: { to: 'boss@example.com', subject: 'Dinner Sunday?', body: BODY },
      })
      expect.fail('should have thrown')
    } catch (err) {
      expect((err as R3Error).code).toBe('proposal_parameter_mismatch')
      expect((err as Error).message).toContain('"to"')
    }
  })

  it('rejects a digest parameter whose bytes changed by one character', async () => {
    const published = await emailProposal()
    await expect(
      verifyProposalParameters({
        store,
        r3_s256: published.r3_s256,
        presented: { to: 'mom@example.com', subject: 'Dinner Sunday?', body: `${BODY} ` },
      }),
    ).rejects.toThrow('does not hash to the approved s256')
  })

  it('accepts digest bytes presented as a Uint8Array', async () => {
    const published = await emailProposal()
    const bytes = new TextEncoder().encode(BODY)
    const verified = await verifyProposalParameters({
      store,
      r3_s256: published.r3_s256,
      presented: { to: 'mom@example.com', subject: 'Dinner Sunday?', body: bytes },
    })
    expect(verified.parameters.to).toBe('mom@example.com')
  })

  it('rejects a digest parameter presented as a non-byte value', async () => {
    const published = await emailProposal()
    await expect(
      verifyProposalParameters({
        store,
        r3_s256: published.r3_s256,
        presented: { to: 'mom@example.com', subject: 'Dinner Sunday?', body: { s256: 'x' } },
      }),
    ).rejects.toThrow('must present its bytes')
  })

  it('rejects a missing parameter', async () => {
    const published = await emailProposal()
    await expect(
      verifyProposalParameters({
        store,
        r3_s256: published.r3_s256,
        presented: { to: 'mom@example.com', body: BODY },
      }),
    ).rejects.toThrow('missing from the call')
  })

  it('rejects a parameter that was never approved', async () => {
    const published = await emailProposal()
    await expect(
      verifyProposalParameters({
        store,
        r3_s256: published.r3_s256,
        presented: { to: 'mom@example.com', subject: 'Dinner Sunday?', body: BODY, bcc: 'x@y.z' },
      }),
    ).rejects.toThrow('was not in the approved proposal')
  })

  it('rejects a different operation', async () => {
    const published = await emailProposal()
    await expect(
      verifyProposalParameters({
        store,
        r3_s256: published.r3_s256,
        presented: { to: 'mom@example.com', subject: 'Dinner Sunday?', body: BODY },
        operation: { tool: 'delete_email' },
      }),
    ).rejects.toThrow('not the one that was approved')
  })

  it('compares structured parameters deeply, ignoring key order', async () => {
    const published = await publishProposal({
      vocabulary: 'urn:aauth:vocabulary:mcp',
      operation: { tool: 'transfer' },
      parameters: { amount: { value: 100, currency: 'USD' }, tags: ['a', 'b'] },
      store,
      baseUri: `${RESOURCE}/r3`,
      authorized: [AS],
    })

    await expect(
      verifyProposalParameters({
        store,
        r3_s256: published.r3_s256,
        presented: { amount: { currency: 'USD', value: 100 }, tags: ['a', 'b'] },
      }),
    ).resolves.toBeTruthy()

    await expect(
      verifyProposalParameters({
        store,
        r3_s256: published.r3_s256,
        presented: { amount: { currency: 'USD', value: 1000 }, tags: ['a', 'b'] },
      }),
    ).rejects.toThrow('differs from the approved proposal')

    await expect(
      verifyProposalParameters({
        store,
        r3_s256: published.r3_s256,
        presented: { amount: { currency: 'USD', value: 100 }, tags: ['b', 'a'] },
      }),
    ).rejects.toThrow('differs from the approved proposal')
  })

  it('rejects an unknown r3_s256', async () => {
    await expect(
      verifyProposalParameters({ store, r3_s256: 'not-a-real-hash', presented: {} }),
    ).rejects.toThrow('No approved proposal')
  })

  it('rejects a class R3 document presented as a proposal', async () => {
    const classDoc = await publishR3Document({
      document: { vocabulary: 'urn:aauth:vocabulary:mcp', operations: [{ tool: 'read' }] },
      baseUri: `${RESOURCE}/r3`,
      store,
      authorized: [AS],
    })
    await expect(
      verifyProposalParameters({ store, r3_s256: classDoc.r3_s256, presented: {} }),
    ).rejects.toThrow('not a per-call proposal')
  })
})

describe('a proposal has the same fetch restriction as a class document', () => {
  it('serves to the AS and PS, never the agent', async () => {
    const published = await emailProposal()
    expect((await serveR3Document({ store, key: published.r3_uri, signer: AS })).status).toBe(200)
    expect((await serveR3Document({ store, key: published.r3_uri, signer: AGENT_PS })).status).toBe(200)

    const denied = await serveR3Document({
      store, key: published.r3_uri, signer: 'https://agent.example',
    })
    expect(denied.status).toBe(403)
    expect(denied.body).not.toContain('mom@example.com')
  })
})

describe('isProposal — the r3_s256 dispatch discriminator', () => {
  const classDocument = {
    vocabulary: 'urn:aauth:vocabulary:openapi',
    operations: [{ operationId: 'sendMessage' }],
  }
  const proposalDocument = { ...classDocument, parameters: { to: 'alice@example.com' } }

  const record = (document: object) => ({
    uri: 'https://resource.example/r3/x',
    s256: 'x',
    body: JSON.stringify(document),
    authorized: ['https://ps.example'],
    createdAt: 0,
  })

  it('is false for a class document — the case that makes presence of r3_s256 useless', () => {
    // A class-grant auth token carries this document's hash. Branching on
    // `if (auth.r3_s256)` would send every granted call into
    // verifyProposalParameters and fail with `invalid_proposal`.
    expect(isProposal(record(classDocument))).toBe(false)
    expect(isProposal(classDocument)).toBe(false)
  })

  it('is true for a per-call proposal', () => {
    expect(isProposal(record(proposalDocument))).toBe(true)
    expect(isProposal(proposalDocument)).toBe(true)
  })

  it('is true for a proposal with no parameters to vary', () => {
    // An empty `parameters` object still marks the document as per-call: the
    // approval is for one invocation, whether or not it takes arguments.
    expect(isProposal({ ...classDocument, parameters: {} })).toBe(true)
  })

  it('is false for a store miss, so a lookup can be passed straight in', () => {
    expect(isProposal(null)).toBe(false)
    expect(isProposal(undefined)).toBe(false)
  })

  it('is false when parameters is not an object', () => {
    expect(isProposal({ ...classDocument, parameters: [] as never })).toBe(false)
    expect(isProposal({ ...classDocument, parameters: 'to=alice' as never })).toBe(false)
  })

  it('is false for unparseable stored bytes rather than throwing', () => {
    expect(isProposal({ ...record(classDocument), body: 'not json' })).toBe(false)
  })
})
