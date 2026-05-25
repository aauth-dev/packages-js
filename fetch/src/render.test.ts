import { describe, it, expect } from 'vitest'
import { colorizeJson, prettyJson, makeVerboseRenderer } from './render.js'
import { renderSkillListMarkdown } from './skill.js'
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

describe('makeVerboseRenderer', () => {
  function collect(events: AAuthEvent[]): Array<Record<string, unknown>> {
    const lines: string[] = []
    const render = makeVerboseRenderer((l) => lines.push(l), false)
    for (const e of events) render(e)
    return lines.map((l) => JSON.parse(l) as Record<string, unknown>)
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
    // signed_request → display step resource_request (named by target, not "signed")
    expect(objs[0]).toMatchObject({ type: 'request', step: 'resource_request', method: 'GET', url: 'https://x' })
    expect((objs[0].headers as Record<string, string>)['signature-key']).toContain('sig=jwt')
    expect(objs[1]).toMatchObject({ type: 'response', step: 'resource_request', status: 401 })
    expect((objs[1].headers as Record<string, string>)['aauth-requirement']).toBe('auth-token')
  })

  it('the initial call and its retry share step resource_request but differ in description', () => {
    const initial = collect([
      { step: 'signed_request', phase: 'start', url: 'https://x', method: 'GET' },
      { step: 'signed_request', phase: 'done', status: 401 },
    ])
    const retry = collect([
      { step: 'retry_with_auth_token', phase: 'start', url: 'https://x', method: 'GET' },
      { step: 'retry_with_auth_token', phase: 'done', status: 200 },
    ])
    expect(initial[0].step).toBe('resource_request')
    expect(retry[0].step).toBe('resource_request')
    expect(initial[0].description).not.toBe(retry[0].description)
    // success response says what came back, not "printed to stdout" / the status code
    expect(retry[1].description).toContain('Received')
    expect(retry[1].description).not.toContain('200')
  })

  it('renders info events with type:info and the display step name', () => {
    const objs = collect([{ step: 'ps_consent_pending', phase: 'info' }])
    expect(objs[0]).toMatchObject({ type: 'info', step: 'consent_required' })
    expect(typeof objs[0].description).toBe('string')
  })

  it('every event object carries a description', () => {
    const objs = collect([
      { step: 'signed_request', phase: 'start', url: 'https://x', method: 'GET' },
      { step: 'signed_request', phase: 'done', status: 200 },
      { step: 'challenge_received', phase: 'info', requirement: 'auth-token' },
    ])
    for (const o of objs) expect(o.description).toBeTruthy()
  })

  // Locks the whole vocabulary: a full default-flow consent trace maps each
  // internal step to its display name + description. If any wording or name
  // drifts, this snapshot fails.
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
    expect(objs.map((o) => [o.type, o.step, o.description])).toEqual([
      ['request', 'resource_request', 'Call the resource with your agent token — no person authorization yet.'],
      ['response', 'resource_request', 'The resource needs a person-authorized token — returns a challenge to exchange.'],
      ['info', 'challenge', 'Parsed it — exchange the resource token for an auth token.'],
      ['request', 'ps_metadata', 'Ask your person server for its endpoints.'],
      ['response', 'ps_metadata', "Received the person server's endpoints."],
      ['request', 'token_exchange', 'Send the resource token to the person server to mint an auth token.'],
      ['response', 'token_exchange', 'Consent required before an auth token is issued.'],
      ['info', 'consent_required', 'Consent required — opening the approval URL for the person.'],
      ['info', 'consent_prompt', 'Waiting for the person to approve…'],
      ['request', 'consent_poll', 'Check whether the person has approved yet.'],
      ['response', 'consent_poll', 'Not yet — still waiting.'],
      ['info', 'consent_granted', 'The person approved.'],
      ['info', 'auth_token', 'Auth token received.'],
      ['request', 'resource_request', 'Call the resource again, now with the person-authorized auth token.'],
      ['response', 'resource_request', "Received the resource's response."],
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
    expect(objs.map((o) => [o.type, o.step, o.description])).toEqual([
      ['request', 'authorize_request', "POST the requested operations to the resource's authorize endpoint, signed with your agent token."],
      ['response', 'authorize_request', 'Received a resource token scoped to those operations.'],
      ['request', 'token_exchange', 'Send the resource token to the person server to mint an auth token.'],
      ['response', 'token_exchange', 'Received the auth token — consent was already on file.'],
    ])
  })
})

describe('renderSkillListMarkdown', () => {
  it('renders ## headings per skill (markdown, not JSON)', () => {
    const md = renderSkillListMarkdown([
      { name: 'fetch', description: 'How to use fetch' },
    ])
    expect(md).toContain('# AAuth fetch skills')
    expect(md).toContain('## fetch')
    expect(md.trimStart().startsWith('[')).toBe(false)
  })

  it('folds the protocol spec URL into the list (no separate protocol skill)', () => {
    const md = renderSkillListMarkdown([{ name: 'fetch', description: 'How to use fetch' }])
    expect(md).toContain('## AAuth protocol spec')
    expect(md).toContain('draft-hardt-oauth-aauth-protocol.md')
  })
})
