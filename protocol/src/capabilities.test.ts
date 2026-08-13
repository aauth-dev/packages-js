import { describe, it, expect } from 'vitest'
import { buildCapabilitiesHeader, parseCapabilitiesHeader, isCapability } from './capabilities.js'

describe('buildCapabilitiesHeader', () => {
  it('renders an RFC 8941 List of Tokens', () => {
    expect(buildCapabilitiesHeader(['interaction', 'clarification', 'payment'])).toBe(
      'interaction, clarification, payment',
    )
  })

  it('renders a single capability', () => {
    expect(buildCapabilitiesHeader(['interaction'])).toBe('interaction')
  })

  it('renders the empty list as an empty string', () => {
    expect(buildCapabilitiesHeader([])).toBe('')
  })

  it('passes through values it does not recognize', () => {
    // The agent unions its own capabilities with the ones its PS reports at
    // mission approval; the PS may name a capability newer than this library.
    expect(buildCapabilitiesHeader(['interaction', 'future-capability'])).toBe(
      'interaction, future-capability',
    )
  })

  it('drops empty entries', () => {
    expect(buildCapabilitiesHeader(['interaction', '', '  ', 'payment'])).toBe('interaction, payment')
  })

  // Capability values are Tokens. A value that is not one would produce a
  // header no RFC 8941 parser could read, so it is refused rather than emitted.
  it('refuses a value that is not a valid Token', () => {
    expect(() => buildCapabilitiesHeader(['inter action'])).toThrow(TypeError)
    expect(() => buildCapabilitiesHeader(['"quoted"'])).toThrow(TypeError)
    expect(() => buildCapabilitiesHeader(['1payment'])).toThrow(TypeError)
  })
})

describe('parseCapabilitiesHeader', () => {
  it('parses the full list', () => {
    expect(parseCapabilitiesHeader('interaction, clarification, payment')).toEqual([
      'interaction',
      'clarification',
      'payment',
    ])
  })

  it('tolerates missing and extra whitespace', () => {
    expect(parseCapabilitiesHeader('interaction,clarification')).toEqual([
      'interaction',
      'clarification',
    ])
    expect(parseCapabilitiesHeader('  interaction ,  payment  ')).toEqual(['interaction', 'payment'])
  })

  // "Recipients MUST ignore unrecognized capability values."
  it('filters unrecognized values and never throws', () => {
    expect(parseCapabilitiesHeader('interaction, quantum-consent, payment')).toEqual([
      'interaction',
      'payment',
    ])
  })

  it('returns an empty array when nothing is recognized', () => {
    expect(parseCapabilitiesHeader('quantum-consent, telepathy')).toEqual([])
  })

  it('returns an empty array for an empty header value', () => {
    expect(parseCapabilitiesHeader('')).toEqual([])
    expect(parseCapabilitiesHeader('   ')).toEqual([])
  })

  it('never throws on garbage', () => {
    for (const junk of [',,,', '"', 'a=b; c', '\t', 'interaction;q=1']) {
      expect(() => parseCapabilitiesHeader(junk)).not.toThrow()
    }
  })

  // A List that does not parse is ignored whole rather than surfaced: the spec
  // says recipients MUST ignore values they do not recognize, and an absent
  // header and an unreadable one lead to the same place.
  it('returns an empty array for a malformed List', () => {
    expect(parseCapabilitiesHeader('interaction, ,')).toEqual([])
    expect(parseCapabilitiesHeader('interaction, "unterminated')).toEqual([])
    expect(parseCapabilitiesHeader('interaction,')).toEqual([])
  })

  it('is case sensitive', () => {
    expect(parseCapabilitiesHeader('Interaction, PAYMENT')).toEqual([])
  })

  it('round-trips the recognized values', () => {
    const caps = ['interaction', 'clarification', 'payment']
    expect(parseCapabilitiesHeader(buildCapabilitiesHeader(caps))).toEqual(caps)
  })
})

describe('isCapability', () => {
  it('accepts the three defined values and nothing else', () => {
    for (const v of ['interaction', 'clarification', 'payment']) expect(isCapability(v)).toBe(true)
    for (const v of ['approval', 'claims', '', 'Payment']) expect(isCapability(v)).toBe(false)
  })
})
