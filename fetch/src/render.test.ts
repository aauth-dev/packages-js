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

  it('maps phase start+done to a request then a response, correlated by step', () => {
    const objs = collect([
      { step: 'signed_request', phase: 'start', url: 'https://x', method: 'GET' },
      {
        step: 'signed_request', phase: 'done', status: 401,
        request_headers: { 'signature-input': 'sig=(…)', 'signature-key': 'sig=jwt;jwt="eyJ…"' },
        response: { headers: { 'aauth-requirement': 'auth-token' } },
      },
    ])
    expect(objs).toHaveLength(2)
    expect(objs[0]).toMatchObject({ type: 'request', step: 'signed_request', method: 'GET', url: 'https://x' })
    expect((objs[0].headers as Record<string, string>)['signature-key']).toContain('sig=jwt')
    expect(objs[1]).toMatchObject({ type: 'response', step: 'signed_request', status: 401 })
    expect((objs[1].headers as Record<string, string>)['aauth-requirement']).toBe('auth-token')
  })

  it('renders info events with type:info', () => {
    const objs = collect([{ step: 'ps_consent_pending', phase: 'info' }])
    expect(objs[0]).toMatchObject({ type: 'info', step: 'ps_consent_pending' })
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
})

describe('renderSkillListMarkdown', () => {
  it('renders ## headings per skill (markdown, not JSON)', () => {
    const md = renderSkillListMarkdown([
      { name: 'fetch', description: 'How to use fetch' },
      { name: 'protocol', description: 'The AAuth protocol spec' },
    ])
    expect(md).toContain('# AAuth fetch skills')
    expect(md).toContain('## fetch')
    expect(md).toContain('## protocol')
    expect(md.trimStart().startsWith('[')).toBe(false)
  })
})
