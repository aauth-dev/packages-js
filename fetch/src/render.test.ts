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
    const lines: string[] = []
    const render = makeExplainRenderer((l) => lines.push(l), false)
    for (const e of events) render(e)
    return lines.map((l) => JSON.parse(l) as Record<string, unknown>)
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
    // response events carry no description — the request's description framed the step
    expect(objs[1].description).toBeUndefined()
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
    const objs = collect([{ step: 'ps_consent_pending', phase: 'info' }])
    expect(objs[0].step).toBe('consent_required')
    expect(typeof objs[0].description).toBe('string')
    expect(objs[0].request).toBeUndefined()
    expect(objs[0].response).toBeUndefined()
  })

  it('cached PS metadata renders as a ps_metadata info event (no request/response)', () => {
    const objs = collect([{ step: 'ps_metadata_cached', phase: 'info' }])
    expect(objs[0].step).toBe('ps_metadata')
    expect(objs[0].description).toEqual(expect.stringContaining('from config'))
    expect(objs[0].request).toBeUndefined()
    expect(objs[0].response).toBeUndefined()
  })

  it('every request and info event carries a description; responses do not', () => {
    const objs = collect([
      { step: 'signed_request', phase: 'start', url: 'https://x', method: 'GET' },
      { step: 'signed_request', phase: 'done', status: 200 },
      { step: 'challenge_received', phase: 'info', requirement: 'auth-token' },
    ])
    expect(objs[0].description).toBeTruthy() // request
    expect(objs[1].description).toBeUndefined() // response
    expect(objs[2].description).toBeTruthy() // info
  })

  // Locks the vocabulary for a full default-flow consent trace. Each event maps
  // to (step, kind, description) — kind is which key carries the payload.
  it('maps a full consent trace to the display vocabulary', () => {
    const objs = collect([
      { step: 'signed_request', phase: 'start', url: 'https://r', method: 'GET' },
      { step: 'signed_request', phase: 'done', status: 401 },
      { step: 'challenge_received', phase: 'info', requirement: 'auth-token' },
      { step: 'ps_metadata_request', phase: 'start', url: 'https://ps/.well-known' },
      { step: 'ps_metadata_request', phase: 'done', status: 200 },
      { step: 'ps_token_request', phase: 'start', url: 'https://ps/token' },
      { step: 'ps_token_request', phase: 'done', status: 202 },
      { step: 'ps_consent_pending', phase: 'info' },
      { step: 'consent_prompt', phase: 'info' },
      { step: 'consent_poll', phase: 'start', url: 'https://ps/pending' },
      { step: 'consent_poll', phase: 'done', status: 200 },
      { step: 'consent_resolved', phase: 'info' },
      { step: 'auth_token_received', phase: 'info' },
      { step: 'retry_with_auth_token', phase: 'start', url: 'https://r', method: 'GET' },
      { step: 'retry_with_auth_token', phase: 'done', status: 200 },
    ])
    const kind = (o: Record<string, unknown>): string =>
      o.request !== undefined ? 'request' : o.response !== undefined ? 'response' : 'info'
    expect(objs.map((o) => [kind(o), o.step, o.description])).toEqual([
      ['request', 'agent_token_request', 'Call the resource with your agent token — self-asserted identity, no person authorization yet.'],
      ['response', 'agent_token_request', undefined],
      ['info', 'challenge', 'Parsed it — exchange the resource token for an auth token.'],
      ['request', 'ps_metadata', 'Ask your person server for its endpoints.'],
      ['response', 'ps_metadata', undefined],
      ['request', 'token_exchange', 'Send the resource token to the person server to mint an auth token.'],
      ['response', 'token_exchange', undefined],
      ['info', 'consent_required', 'Consent required — opening the approval URL for the person.'],
      ['info', 'consent_prompt', 'Waiting for the person to approve…'],
      ['request', 'consent_poll', 'Check whether the person has approved yet.'],
      ['response', 'consent_poll', undefined],
      ['info', 'consent_granted', 'The person approved.'],
      ['info', 'auth_token', 'Auth token received.'],
      ['request', 'auth_token_request', 'Call the resource with the person-authorized auth token.'],
      ['response', 'auth_token_request', undefined],
    ])
  })

  // The R3 entry step + the token_exchange 200 (consent already on file) branch.
  it('maps the R3 authorize_request entry and the cached-consent token_exchange', () => {
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
    expect(objs[2].step).toBe('token_exchange')
    expect(objs[2].description).toBe('Send the resource token to the person server to mint an auth token.')
    expect(objs[3].step).toBe('token_exchange')
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
    const lines: string[] = []
    const render = makeDebugRenderer((l) => lines.push(l), false)
    for (const e of events) render(e)
    return lines.map((l) => JSON.parse(l) as Record<string, unknown>)
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
      { step: 'consent_prompt', phase: 'info' },
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
