import { describe, it, expect } from 'vitest'
import {
  buildRequirementHeader,
  parseRequirementHeader,
  UnsupportedRequirementError,
  isRequirementValue,
  type AAuthChallenge,
} from './requirement.js'

describe('parseRequirementHeader — recognized values', () => {
  it('parses every -11 requirement value that takes no parameters', () => {
    for (const value of ['agent-token', 'person-token', 'approval', 'clarification', 'claims']) {
      expect(parseRequirementHeader(`requirement=${value}`)).toEqual({ requirement: value })
    }
  })

  it('parses auth-token with its resource-token', () => {
    expect(parseRequirementHeader('requirement=auth-token; resource-token="eyJhbGci.eyJzdWIi.sig"'))
      .toEqual({ requirement: 'auth-token', resourceToken: 'eyJhbGci.eyJzdWIi.sig' })
  })

  it('parses interaction with url and code', () => {
    expect(parseRequirementHeader('requirement=interaction; url="https://example.com/interact"; code="A1B2-C3D4"'))
      .toEqual({
        requirement: 'interaction',
        url: 'https://example.com/interact',
        code: 'A1B2-C3D4',
      })
  })

  it('accepts a folded header (the spec prints interaction across lines)', () => {
    const folded =
      'requirement=interaction;\n    url="https://example.com/interact";\n    code="A1B2-C3D4"'
    expect(parseRequirementHeader(folded).requirement).toBe('interaction')
    expect(parseRequirementHeader(folded).code).toBe('A1B2-C3D4')
  })

  it('ignores unknown parameters', () => {
    expect(parseRequirementHeader('requirement=approval; retry-hint="soon"; nonce=7'))
      .toEqual({ requirement: 'approval' })
  })

  it('does not split on a semicolon inside a quoted string', () => {
    expect(parseRequirementHeader('requirement=interaction; url="https://example.com/a;b"; code="XYZ"'))
      .toEqual({ requirement: 'interaction', url: 'https://example.com/a;b', code: 'XYZ' })
  })

  it('finds the requirement member among other dictionary members', () => {
    expect(parseRequirementHeader('other=1, requirement=approval')).toEqual({ requirement: 'approval' })
  })
})

describe('parseRequirementHeader — unrecognized values', () => {
  // Protocol -11: "An agent that does not recognize the requirement value MUST NOT
  // treat the response as satisfiable. It surfaces the unsupported requirement to
  // the caller as an error."
  it('throws UnsupportedRequirementError, not a generic Error', () => {
    expect(() => parseRequirementHeader('requirement=payment')).toThrow(UnsupportedRequirementError)
  })

  it('carries the raw value on the error so the caller can report it', () => {
    try {
      parseRequirementHeader('requirement=some-future-requirement; extra="x"')
      expect.unreachable('should have thrown')
    } catch (e) {
      expect(e).toBeInstanceOf(UnsupportedRequirementError)
      expect((e as UnsupportedRequirementError).value).toBe('some-future-requirement')
      expect((e as UnsupportedRequirementError).name).toBe('UnsupportedRequirementError')
      expect((e as Error).message).toContain('some-future-requirement')
    }
  })

  it('rejects the -10 spelling that -11 does not define', () => {
    expect(() => parseRequirementHeader('requirement=aauth-access-token')).toThrow(
      UnsupportedRequirementError,
    )
  })

  it('is case sensitive — Token values are', () => {
    expect(() => parseRequirementHeader('requirement=Approval')).toThrow(UnsupportedRequirementError)
  })
})

describe('parseRequirementHeader — malformed headers', () => {
  it('rejects an empty header', () => {
    expect(() => parseRequirementHeader('')).toThrow(/empty/i)
    expect(() => parseRequirementHeader('   ')).toThrow(/empty/i)
  })

  it('rejects a header with no requirement member', () => {
    expect(() => parseRequirementHeader('resource-token="eyJ..."')).toThrow(/no requirement member/i)
  })

  it('rejects an empty requirement value', () => {
    expect(() => parseRequirementHeader('requirement=')).toThrow(/empty requirement value/i)
  })

  it('rejects auth-token with no resource-token parameter', () => {
    expect(() => parseRequirementHeader('requirement=auth-token')).toThrow(/resource-token/)
    expect(() => parseRequirementHeader('requirement=auth-token; url="https://x.example"')).toThrow(
      /resource-token/,
    )
  })

  it('rejects interaction missing url, code, or both', () => {
    expect(() => parseRequirementHeader('requirement=interaction')).toThrow(/url or code/)
    expect(() => parseRequirementHeader('requirement=interaction; url="https://x.example"')).toThrow(
      /url or code/,
    )
    expect(() => parseRequirementHeader('requirement=interaction; code="A1B2"')).toThrow(/url or code/)
  })

  it('malformed-parameter errors are not UnsupportedRequirementError', () => {
    expect(() => parseRequirementHeader('requirement=auth-token')).not.toThrow(
      UnsupportedRequirementError,
    )
  })
})

describe('buildRequirementHeader', () => {
  it('builds the parameterless values', () => {
    expect(buildRequirementHeader({ requirement: 'approval' })).toBe('requirement=approval')
    expect(buildRequirementHeader({ requirement: 'agent-token' })).toBe('requirement=agent-token')
    expect(buildRequirementHeader({ requirement: 'person-token' })).toBe('requirement=person-token')
    expect(buildRequirementHeader({ requirement: 'clarification' })).toBe('requirement=clarification')
    expect(buildRequirementHeader({ requirement: 'claims' })).toBe('requirement=claims')
  })

  it('builds auth-token with a quoted resource-token', () => {
    expect(buildRequirementHeader({ requirement: 'auth-token', resourceToken: 'eyJ.a.b' })).toBe(
      'requirement=auth-token; resource-token="eyJ.a.b"',
    )
  })

  it('builds interaction with url and code', () => {
    expect(
      buildRequirementHeader({
        requirement: 'interaction',
        url: 'https://example.com/interact',
        code: 'A1B2-C3D4',
      }),
    ).toBe('requirement=interaction; url="https://example.com/interact"; code="A1B2-C3D4"')
  })

  it('throws when a required parameter is missing', () => {
    expect(() => buildRequirementHeader({ requirement: 'auth-token' })).toThrow(/resourceToken/)
    expect(() =>
      buildRequirementHeader({ requirement: 'interaction', url: 'https://x.example' }),
    ).toThrow(/url and code/)
  })

  it('throws UnsupportedRequirementError on a value it does not know', () => {
    expect(() =>
      buildRequirementHeader({ requirement: 'made-up' as never }),
    ).toThrow(UnsupportedRequirementError)
  })

  it('round-trips, including values needing escapes', () => {
    const challenges: AAuthChallenge[] = [
      { requirement: 'approval' },
      { requirement: 'agent-token' },
      { requirement: 'person-token' },
      { requirement: 'clarification' },
      { requirement: 'claims' },
      { requirement: 'auth-token', resourceToken: 'eyJhbGciOiJFZDI1NTE5In0.eyJpc3MiOiJ4In0.sig' },
      { requirement: 'interaction', url: 'https://example.com/i', code: 'A1B2-C3D4' },
      { requirement: 'interaction', url: 'https://example.com/a"b\\c', code: 'ZZZZ' },
    ]
    for (const challenge of challenges) {
      expect(parseRequirementHeader(buildRequirementHeader(challenge))).toEqual(challenge)
    }
  })
})

describe('isRequirementValue', () => {
  it('accepts all seven -11 values and nothing else', () => {
    const all = [
      'agent-token',
      'person-token',
      'auth-token',
      'approval',
      'interaction',
      'clarification',
      'claims',
    ]
    for (const v of all) expect(isRequirementValue(v)).toBe(true)
    for (const v of ['payment', 'session-token', 'per-call', '', 'APPROVAL']) {
      expect(isRequirementValue(v)).toBe(false)
    }
  })
})
