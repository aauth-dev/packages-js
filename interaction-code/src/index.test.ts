import { describe, it, expect } from 'vitest'
import { generateCode, canonicalizeCode, CROCKFORD32 } from './index.js'

describe('generateCode', () => {
  it('returns XXXX-XXXX format', () => {
    const code = generateCode()
    expect(code).toMatch(/^[0-9A-Z]{4}-[0-9A-Z]{4}$/)
  })

  it('uses only Crockford base32 symbols (no I, L, O, U)', () => {
    const codes = Array.from({ length: 1000 }, generateCode)
    const allChars = codes.join('').replace(/-/g, '')
    for (const ch of allChars) {
      expect(CROCKFORD32).toContain(ch)
      expect('ILOU').not.toContain(ch)
    }
  })

  it('generates unique codes', () => {
    const codes = new Set(Array.from({ length: 100 }, generateCode))
    expect(codes.size).toBe(100)
  })
})

describe('canonicalizeCode', () => {
  it('is idempotent on canonical codes', () => {
    const code = generateCode()
    expect(canonicalizeCode(code)).toBe(code)
    expect(canonicalizeCode(canonicalizeCode(code))).toBe(code)
  })

  it('strips and reinserts the hyphen', () => {
    expect(canonicalizeCode('A1B2C3D4')).toBe('A1B2-C3D4')
  })

  it('uppercases lowercase input', () => {
    expect(canonicalizeCode('a1b2-c3d4')).toBe('A1B2-C3D4')
  })

  it('folds I and L to 1', () => {
    expect(canonicalizeCode('I1L1-I1L1')).toBe('1111-1111')
    expect(canonicalizeCode('i1l1i1l1')).toBe('1111-1111')
  })

  it('folds O to 0', () => {
    expect(canonicalizeCode('O0O0-O0O0')).toBe('0000-0000')
    expect(canonicalizeCode('o0o0o0o0')).toBe('0000-0000')
  })

  it('handles mixed mangled input', () => {
    expect(canonicalizeCode('a1b2c3d4')).toBe('A1B2-C3D4')
    expect(canonicalizeCode('A1B2-C3D4')).toBe('A1B2-C3D4')
    expect(canonicalizeCode('a1b2-c3d4')).toBe('A1B2-C3D4')
  })
})
