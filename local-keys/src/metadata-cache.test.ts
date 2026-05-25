import { describe, it, expect, afterEach, vi } from 'vitest'
import {
  readCachedMetadata,
  writeCachedMetadata,
  evictCachedMetadata,
  parseMaxAge,
} from './metadata-cache.js'

// A host unlikely to collide with a real cached PS. Round-trips go through the
// real ~/.aauth/cache/, so every test evicts its entry afterwards.
const HOST = 'cache-test.invalid'
const doc = { token_endpoint: 'https://cache-test.invalid/aauth/token', jwks_uri: 'x', issuer: 'y' }

afterEach(() => {
  evictCachedMetadata(HOST)
  vi.useRealTimers()
})

describe('parseMaxAge', () => {
  it('extracts max-age seconds', () => {
    expect(parseMaxAge('max-age=3600')).toBe(3600)
    expect(parseMaxAge('public, max-age=120, must-revalidate')).toBe(120)
    expect(parseMaxAge('max-age = 90')).toBe(90)
    expect(parseMaxAge('Max-Age=42')).toBe(42)
  })

  it('returns undefined when absent or unparseable', () => {
    expect(parseMaxAge(null)).toBeUndefined()
    expect(parseMaxAge(undefined)).toBeUndefined()
    expect(parseMaxAge('no-store')).toBeUndefined()
    expect(parseMaxAge('s-maxage=60')).toBeUndefined() // not max-age
  })
})

describe('metadata cache round-trip', () => {
  it('writes then reads back the exact doc', () => {
    writeCachedMetadata(HOST, doc, 3600)
    expect(readCachedMetadata(HOST)).toEqual(doc)
  })

  it('returns null after the entry expires', () => {
    vi.useFakeTimers()
    vi.setSystemTime(new Date('2026-01-01T00:00:00Z'))
    writeCachedMetadata(HOST, doc, 100) // expires_at = now + 100s
    expect(readCachedMetadata(HOST)).toEqual(doc)
    vi.setSystemTime(new Date('2026-01-01T00:01:41Z')) // +101s
    expect(readCachedMetadata(HOST)).toBeNull()
  })

  it('returns null for an unknown host', () => {
    expect(readCachedMetadata('never-cached.invalid')).toBeNull()
  })

  it('evict removes the entry', () => {
    writeCachedMetadata(HOST, doc, 3600)
    evictCachedMetadata(HOST)
    expect(readCachedMetadata(HOST)).toBeNull()
  })
})
