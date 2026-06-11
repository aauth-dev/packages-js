import { describe, it, expect } from 'vitest'
import { colorizeJson, prettyJson, makeExplainRenderer, makeDebugRenderer } from './render.js'
import { renderSkill } from './skill.js'
import type { AAuthEvent } from '@aauth/mcp-agent'

describe('colorizeJson / prettyJson', () => {
  const json = JSON.stringify({ a: 'hi', n: 42 }, null, 2)
  it('adds ANSI and strips back to the original', () => {
    const out = colorizeJson(json)
    expect(out).toContain('\x1b[')
    expect(out.replace(/\x1b\[[0-9]*m/g, '')).toBe(json)
  })
  it('prettyJson stays plain when not a TTY', () => {
    expect(prettyJson({ a: 1 }, false)).toBe('{\n  "a": 1\n}')
  })
})

describe('makeExplainRenderer', () => {
  function collect(events: AAuthEvent[]): Array<Record<string, unknown>> {
    const objs: Array<Record<string, unknown>> = []
    const render = makeExplainRenderer((o) => objs.push(o))
    for (const e of events) render(e)
    return objs
  }

  // Helpers to read into the new nested shape.
  function req(obj: Record<string, unknown>): Record<string, unknown> {
    return (obj.request as Record<string, unknown>) ?? {}
  }
  function res(obj: Record<string, unknown>): Record<string, unknown> {
    return (obj.response as Record<string, unknown>) ?? {}
  }

  it('maps phase start+done to a request then a response, with display step name', () => {
    const objs = collect([
      { step: 'signed_request', phase: 'start', url: 'https://x', method: 'GET' },
      {
        step: 'signed_request', phase: 'done', status: 401,
        request_headers: { 'signature-input': 'sig=(…)', 'signature-key': 'sig=jwt;jwt="eyJ…"' },
        response: { headers: { 'aauth-requirement': 'auth-token' } },
      },
    ])
    expect(objs).toHaveLength(2)
    // signed_request → display step agent_token_request (named by the token it carries)
    expect(objs[0].step).toBe('agent_token_request')
    expect(req(objs[0])).toMatchObject({ method: 'GET', url: 'https://x' })
    expect((req(objs[0]).headers as Record<string, string>)['signature-key']).toContain('sig=jwt')
    expect(typeof objs[0].description).toBe('string')
    expect(objs[1].step).toBe('agent_token_request')
    expect(res(objs[1])).toMatchObject({ status: 401 })
    expect((res(objs[1]).headers as Record<string, string>)['aauth-requirement']).toBe('auth-token')
    // the response description teaches the branch the flow took (401 → three-party)
    expect(objs[1].description).toMatch(/three-party/)
    // the request carries the status-aware one-line gist of the exchange
    expect(objs[0].summary).toBe('agent → resource · agent-token → 401 + resource-token')
  })

  it('names the two resource calls by token: agent_token_request vs auth_token_request', () => {
    const agentCall = collect([
      { step: 'signed_request', phase: 'start', url: 'https://x', method: 'GET' },
      { step: 'signed_request', phase: 'done', status: 401 },
    ])
    const authCall = collect([
      { step: 'retry_with_auth_token', phase: 'start', url: 'https://x', method: 'GET' },
      { step: 'retry_with_auth_token', phase: 'done', status: 200 },
    ])
    expect(agentCall[0].step).toBe('agent_token_request')
    expect(authCall[0].step).toBe('auth_token_request')
    // each request's description states the intent of that specific call
    expect(agentCall[0].description).not.toBe(authCall[0].description)
  })

  it('pre-authed reuse also displays as auth_token_request', () => {
    const objs = collect([
      { step: 'auth_token_request', phase: 'start', url: 'https://x', method: 'GET' },
      { step: 'auth_token_request', phase: 'done', status: 200 },
    ])
    expect(objs[0].step).toBe('auth_token_request')
    expect(objs[0].request).toBeDefined()
    expect(objs[1].response).toBeDefined()
  })

  it('renders info events with step + description and no request/response', () => {
    const objs = collect([
      { step: 'interaction_required', phase: 'info', url: 'https://ps/auth', code: 'A1B2' },
    ])
    expect(objs[0].step).toBe('interaction_required')
    expect(typeof objs[0].description).toBe('string')
    expect(objs[0].url).toBe('https://ps/auth')
    expect(objs[0].code).toBe('A1B2')
    // The event self-assembles the CTA so renderers don't have to: the full
    // approval URL (url + ?code=code) and a scannable ASCII QR.
    expect(objs[0].approval_url).toBe('https://ps/auth?code=A1B2')
    expect(typeof objs[0].qr).toBe('string')
    expect((objs[0].qr as string).length).toBeGreaterThan(0)
    expect(objs[0].request).toBeUndefined()
    expect(objs[0].response).toBeUndefined()
  })

  it('cached PS metadata renders as a ps_metadata info event (no request/response)', () => {
    const objs = collect([{ step: 'ps_metadata_cached', phase: 'info' }])
    expect(objs[0].step).toBe('ps_metadata')
    expect(objs[0].description).toEqual(expect.stringContaining('locally cached'))
    expect(objs[0].request).toBeUndefined()
    expect(objs[0].response).toBeUndefined()
  })

  it('every request, response, and info event carries a description', () => {
    const objs = collect([
      { step: 'signed_request', phase: 'start', url: 'https://x', method: 'GET' },
      { step: 'signed_request', phase: 'done', status: 200 },
      { step: 'challenge_received', phase: 'info', requirement: 'auth-token' },
    ])
    expect(objs[0].description).toBeTruthy() // request
    expect(objs[1].description).toBeTruthy() // response — teaches the branch taken
    expect(objs[2].description).toBeTruthy() // info
  })

  // Locks the vocabulary for a full default-flow consent trace. Each event maps
  // to (step, kind, description) — kind is which key carries the payload.
  // auth_token_received and consent_resolved are recap-only info events that
  // the renderer drops; their meaning is folded into the next request's
  // description.
  it('maps a full consent trace to the display vocabulary', () => {
    const objs = collect([
      { step: 'signed_request', phase: 'start', url: 'https://r', method: 'GET' },
      { step: 'signed_request', phase: 'done', status: 401 },
      { step: 'challenge_received', phase: 'info', requirement: 'auth-token' },
      { step: 'ps_metadata_request', phase: 'start', url: 'https://ps/.well-known' },
      { step: 'ps_metadata_request', phase: 'done', status: 200 },
      { step: 'ps_token_request', phase: 'start', url: 'https://ps/token' },
      { step: 'ps_token_request', phase: 'done', status: 202 },
      { step: 'interaction_required', phase: 'info', url: 'https://ps/auth', code: 'A1B2' },
      { step: 'consent_poll', phase: 'start', url: 'https://ps/pending' },
      { step: 'consent_poll', phase: 'done', status: 200 },
      { step: 'auth_token_received', phase: 'info' },
      { step: 'retry_with_auth_token', phase: 'start', url: 'https://r', method: 'GET' },
      { step: 'retry_with_auth_token', phase: 'done', status: 200 },
    ])
    const kind = (o: Record<string, unknown>): string =>
      o.request !== undefined ? 'request' : o.response !== undefined ? 'response' : 'info'
    expect(objs.map((o) => [kind(o), o.step, o.description])).toEqual([
      ['request', 'agent_token_request', 'Call the resource with your agent token.'],
      ['response', 'agent_token_request', 'The resource requires a person-issued auth token — this begins the three-party flow (agent ↔ person server ↔ resource). The `AAuth-Requirement` header carries a resource token: the agent presents it to the person server to get authorized.'],
      ['info', 'requirement_parsed', 'Parsed `AAuth-Requirement` — must exchange the resource token for an auth token at the person server.'],
      ['request', 'ps_metadata', "Fetch the person server's metadata at `/.well-known/aauth-person.json`."],
      ['response', 'ps_metadata', "Received the person server's endpoints."],
      ['request', 'ps_token_request', 'POST the resource token to the person server `token_endpoint` to mint an auth token. `Prefer: wait=45` long-polls — the server may hold the connection up to 45s before returning.'],
      ['response', 'ps_token_request', 'User interaction required before the auth token is issued (`AAuth-Requirement: requirement=interaction`) — the person must approve in a browser; the agent polls the pending `location` until they do.'],
      ['info', 'interaction_required', 'Direct the person to the approval URL — show them the QR or open the link.'],
      ['request', 'consent_poll', 'Poll the pending URL — checking whether the person has acted. `Prefer: wait=45` long-polls so the response returns immediately on consent rather than burning round-trips.'],
      ['response', 'consent_poll', 'The person approved — the body carries the freshly issued auth token, bound (`cnf`) to the same ephemeral key the agent has been signing with.'],
      ['request', 'auth_token_request', 'Call the resource — `Signature-Key` now carries the person-issued auth token, not the agent token.'],
      ['response', 'auth_token_request', 'The resource verified the person-issued auth token — it now knows who is calling (`agent`) and on whose behalf (`sub`, plus claims the person server vouched for).'],
    ])
    // The summaries form the recap: one gist line per exchange, in order.
    expect(objs.filter((o) => o.summary !== undefined).map((o) => o.summary)).toEqual([
      'agent → resource · agent-token → 401 + resource-token',
      'agent → person server · metadata discovery',
      'agent → person server · resource-token → 202 pending + approval code',
      'person → person server · approve in browser',
      'agent → person server · poll → 200 + auth-token (person approved)',
      'agent → resource · auth-token → 200 + person claims',
    ])
  })

  // signed_request's REQUEST describes the call itself the same way regardless
  // of status — the response description carries the branch (challenge vs. 200).
  it('signed_request describes the call the same way; response carries the branch', () => {
    const ok = collect([
      { step: 'signed_request', phase: 'start', url: 'https://r', method: 'GET' },
      { step: 'signed_request', phase: 'done', status: 200 },
    ])
    const challenged = collect([
      { step: 'signed_request', phase: 'start', url: 'https://r', method: 'GET' },
      { step: 'signed_request', phase: 'done', status: 401 },
    ])
    expect(ok[0].description).toBe('Call the resource with your agent token.')
    expect(challenged[0].description).toBe('Call the resource with your agent token.')
    // here we assert that requests don't forward-narrate the branch...
    expect(ok[0].description).not.toMatch(/identity-based|challenged/)
    // ...the response description does: identity-based access vs the three-party flow
    expect(ok[1].description).toMatch(/Identity-based access/)
    expect(challenged[1].description).toMatch(/three-party flow/)
    // and the summary carries the branch as the one-line gist
    expect(ok[0].summary).toBe('agent → resource · agent-token → 200 (identity-based access)')
    expect(challenged[0].summary).toBe('agent → resource · agent-token → 401 + resource-token')
  })

  it('suppresses recap-only info events (auth_token_received, consent_resolved)', () => {
    const objs = collect([
      { step: 'auth_token_received', phase: 'info' },
      { step: 'consent_resolved', phase: 'info' },
    ])
    expect(objs).toEqual([])
  })

  it('drops repeated descriptions/summaries on consent_poll heartbeats; the 200 prints fresh ones', () => {
    const objs = collect([
      { step: 'consent_poll', phase: 'start', url: 'https://ps/pending' },
      { step: 'consent_poll', phase: 'done', status: 202 },
      { step: 'consent_poll', phase: 'start', url: 'https://ps/pending' },
      { step: 'consent_poll', phase: 'done', status: 202 },
      { step: 'consent_poll', phase: 'start', url: 'https://ps/pending' },
      { step: 'consent_poll', phase: 'done', status: 200 },
    ])
    expect(objs[0].description).toBe('Poll the pending URL — checking whether the person has acted. `Prefer: wait=45` long-polls so the response returns immediately on consent rather than burning round-trips.')
    expect(objs[0].summary).toBe('agent → person server · poll → 202 still pending')
    expect(objs[1].description).toBe('Still pending — the person has not acted yet.')
    // heartbeat repeats: same lines suppressed
    expect(objs[2].description).toBeUndefined()
    expect(objs[2].summary).toBeUndefined()
    expect(objs[3].description).toBeUndefined()
    // the final 200 carries NEW lines (different branch) — they print
    expect(objs[4].summary).toBe('agent → person server · poll → 200 + auth-token (person approved)')
    expect(objs[5].description).toMatch(/The person approved/)
    for (const o of objs) expect(o.step).toBe('consent_poll')
  })

  // The R3 entry step + the ps_token_request 200 (consent already on file) branch.
  it('maps the R3 authorize_request entry and the cached-consent ps_token_request', () => {
    const objs = collect([
      { step: 'r3_authorize_request', phase: 'start', url: 'https://r/authorize', method: 'POST' },
      { step: 'r3_authorize_request', phase: 'done', status: 200 },
      { step: 'ps_token_request', phase: 'start', url: 'https://ps/token' },
      { step: 'ps_token_request', phase: 'done', status: 200 },
    ])
    expect(objs[0].step).toBe('authorize_request')
    expect(objs[0].description).toBe("POST the requested operations to the resource's authorize endpoint, signed with your agent token.")
    expect(objs[1].step).toBe('authorize_request')
    expect(objs[1].response).toBeDefined()
    expect(objs[2].step).toBe('ps_token_request')
    expect(objs[2].description).toBe('POST the resource token to the person server `token_endpoint` to mint an auth token. `Prefer: wait=45` long-polls — the server may hold the connection up to 45s before returning.')
    expect(objs[3].step).toBe('ps_token_request')
    expect(objs[3].response).toBeDefined()
  })

  it('surfaces request and response bodies, parsing JSON for display', () => {
    const objs = collect([
      { step: 'ps_token_request', phase: 'start', url: 'https://ps/token' },
      {
        step: 'ps_token_request', phase: 'done', status: 200,
        request_body: '{"resource_token":"rt"}',
        response: { headers: {}, body: '{"auth_token":"at"}' },
      },
    ])
    expect(req(objs[0]).body).toEqual({ resource_token: 'rt' })
    expect(res(objs[1]).body).toEqual({ auth_token: 'at' })
  })

  it('interaction_required carries assembled approval_url + QR and does not mention stderr', () => {
    const objs = collect([
      { step: 'interaction_required', phase: 'info', url: 'https://ps/auth', code: 'AB12CD' },
    ])
    const ev = objs[0]
    expect(ev.approval_url).toBe('https://ps/auth?code=AB12CD')
    expect(typeof ev.qr).toBe('string')
    // QR scan target = approval_url, not the bare endpoint, so the scanner
    // lands the human at the page that consumes the code.
    expect((ev.qr as string).length).toBeGreaterThan(50)
    // Description is the header — no parenthetical pointing at stderr.
    expect(ev.description as string).not.toMatch(/stderr/i)
  })

  it('leaves a non-JSON body as a raw string', () => {
    const objs = collect([
      { step: 'signed_request', phase: 'start', url: 'https://x', method: 'GET' },
      { step: 'signed_request', phase: 'done', status: 200, response: { headers: {}, body: 'plain text' } },
    ])
    expect(res(objs[1]).body).toBe('plain text')
  })
})

describe('makeDebugRenderer', () => {
  function collect(events: AAuthEvent[]): Array<Record<string, unknown>> {
    const objs: Array<Record<string, unknown>> = []
    const render = makeDebugRenderer((o) => objs.push(o))
    for (const e of events) render(e)
    return objs
  }

  it('emits raw { request } then { response } per hop, with bodies, no descriptions/type', () => {
    const objs = collect([
      { step: 'signed_request', phase: 'start', url: 'https://x', method: 'GET' },
      {
        step: 'signed_request', phase: 'done', status: 401,
        request_headers: { 'signature-key': 'sig=jwt;jwt="eyJ…"' },
        response: { headers: { 'aauth-requirement': 'auth-token' }, body: '{"error":"auth_token_required"}' },
      },
    ])
    expect(objs).toHaveLength(2)
    const req = objs[0].request as Record<string, unknown>
    expect(req).toMatchObject({ method: 'GET', url: 'https://x' })
    expect((req.headers as Record<string, string>)['signature-key']).toContain('sig=jwt')
    const res = objs[1].response as Record<string, unknown>
    expect(res).toMatchObject({ status: 401, body: { error: 'auth_token_required' } })
    // raw view: no teaching vocabulary, no type discriminator
    for (const o of objs) {
      expect(o.type).toBeUndefined()
      expect(o.step).toBeUndefined()
      expect(o.description).toBeUndefined()
    }
  })

  it('skips info events (only requests and responses)', () => {
    const objs = collect([
      { step: 'challenge_received', phase: 'info', requirement: 'auth-token' },
      { step: 'interaction_required', phase: 'info', url: 'https://ps/auth', code: 'A1B2' },
    ])
    expect(objs).toHaveLength(0)
  })
})

describe('renderSkill', () => {
  it('prints the fetch guide and folds in the site + protocol spec URLs', () => {
    const md = renderSkill()
    expect(md).toContain('@aauth/fetch') // the guide
    expect(md).toContain('## Learn more')
    expect(md).toContain('https://www.aauth.dev')
    expect(md).toContain('https://www.aauth.dev/llms.txt')
    expect(md).toContain('draft-hardt-oauth-aauth-protocol.md')
    expect(md.trimStart().startsWith('[')).toBe(false) // markdown, not JSON
  })
})
