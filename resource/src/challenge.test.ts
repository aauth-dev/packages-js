import { describe, it, expect } from 'vitest'
import {
  buildAAuthHeader,
  buildAAuthAccessHeader,
  parseCapabilitiesHeader,
  parseRequirementHeader,
} from './challenge.js'

describe('buildAAuthHeader', () => {
  it('builds requirement=person-token', () => {
    expect(buildAAuthHeader('person-token')).toBe('requirement=person-token')
  })

  it('builds requirement=agent-token', () => {
    expect(buildAAuthHeader('agent-token')).toBe('requirement=agent-token')
  })

  it('builds the parameterless requirements', () => {
    expect(buildAAuthHeader('approval')).toBe('requirement=approval')
    expect(buildAAuthHeader('clarification')).toBe('requirement=clarification')
    expect(buildAAuthHeader('claims')).toBe('requirement=claims')
  })

  it('builds requirement=auth-token with the resource token', () => {
    const header = buildAAuthHeader('auth-token', { resourceToken: 'eyJ.abc.def' })
    // RFC 8941 serialization: no space after the `;` introducing a parameter.
    expect(header).toBe('requirement=auth-token;resource-token="eyJ.abc.def"')
    expect(parseRequirementHeader(header)).toEqual({
      requirement: 'auth-token',
      resourceToken: 'eyJ.abc.def',
    })
  })

  it('builds requirement=interaction with url and code', () => {
    const header = buildAAuthHeader('interaction', {
      url: 'https://resource.example/interact',
      code: 'A1B2-C3D4',
    })
    expect(header).toContain('requirement=interaction')
    expect(header).toContain('url="https://resource.example/interact"')
    expect(header).toContain('code="A1B2-C3D4"')
  })

  it('rejects auth-token with no resource token', () => {
    expect(() =>
      (buildAAuthHeader as (r: string, p?: unknown) => string)('auth-token'),
    ).toThrow()
  })
})

describe('parseCapabilitiesHeader', () => {
  it('filters unrecognized values rather than throwing', () => {
    expect(parseCapabilitiesHeader('interaction, payment, telepathy')).toEqual([
      'interaction',
      'payment',
    ])
  })
})

describe('buildAAuthAccessHeader', () => {
  it('passes a token68 through', () => {
    expect(buildAAuthAccessHeader('abc-123_XY')).toBe('abc-123_XY')
  })

  it('rejects an empty or whitespace-bearing value', () => {
    expect(() => buildAAuthAccessHeader('')).toThrow()
    expect(() => buildAAuthAccessHeader('a b')).toThrow()
  })
})

describe('mission header helpers', () => {
  it('are gone — AAuth-Mission was removed in -11', async () => {
    const mod = await import('./index.js') as Record<string, unknown>
    expect(mod.buildMissionHeader).toBeUndefined()
    expect(mod.parseMissionHeader).toBeUndefined()
  })
})
