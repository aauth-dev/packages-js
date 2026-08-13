import { describe, it, expect, afterEach, vi } from 'vitest'
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs'
import { join } from 'node:path'
import { homedir } from 'node:os'
import {
  readCachedMetadata,
  writeCachedMetadata,
  evictCachedMetadata,
  parseMaxAge,
  isPersonServerMetadata,
  missingPersonServerMembers,
  CACHE_SCHEMA_VERSION,
  PS_METADATA_FILE,
} from './metadata-cache.js'

// A host unlikely to collide with a real cached PS. Round-trips go through the
// real ~/.aauth/cache/, so every test evicts its entry afterwards.
const HOST = 'cache-test.invalid'

/** A valid AAuth -11 person server metadata document (#ps-metadata). */
const doc = {
  issuer: 'https://cache-test.invalid',
  auth_token_endpoint: 'https://cache-test.invalid/aauth/token/auth',
  person_token_endpoint: 'https://cache-test.invalid/aauth/token/person',
  jwks_uri: 'https://cache-test.invalid/.well-known/jwks.json',
}

/** What a pre-11 entry looks like: `token_endpoint`, no person token endpoint. */
const legacyDoc = {
  issuer: 'https://cache-test.invalid',
  token_endpoint: 'https://cache-test.invalid/aauth/token',
  jwks_uri: 'https://cache-test.invalid/.well-known/jwks.json',
}

const CACHE_DIR = join(homedir(), '.aauth', 'cache')
const INDEX_FILE = join(CACHE_DIR, 'index.json')
const hostDir = join(CACHE_DIR, HOST.replace(/\./g, '-'))

/** Plant an entry exactly as a pre-11 @aauth/local-keys would have written it. */
function plantLegacyEntry(): void {
  mkdirSync(hostDir, { recursive: true })
  writeFileSync(join(hostDir, PS_METADATA_FILE), JSON.stringify(legacyDoc, null, 2) + '\n')
  let index: Record<string, unknown> = {}
  try {
    index = JSON.parse(readFileSync(INDEX_FILE, 'utf-8'))
  } catch { /* no index yet */ }
  // No `schema` member — that is what makes it pre-11.
  index[`${HOST.replace(/\./g, '-')}/${PS_METADATA_FILE}`] = {
    expires_at: Math.floor(Date.now() / 1000) + 3600,
  }
  mkdirSync(CACHE_DIR, { recursive: true })
  writeFileSync(INDEX_FILE, JSON.stringify(index, null, 2) + '\n')
}

function indexEntry(): { expires_at: number; schema?: number } | undefined {
  try {
    const index = JSON.parse(readFileSync(INDEX_FILE, 'utf-8'))
    return index[`${HOST.replace(/\./g, '-')}/${PS_METADATA_FILE}`]
  } catch {
    return undefined
  }
}

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

describe('person server metadata shape (-11)', () => {
  it('accepts a document with both token endpoints', () => {
    expect(isPersonServerMetadata(doc)).toBe(true)
    expect(missingPersonServerMembers(doc)).toEqual([])
  })

  it('rejects a pre-11 document carrying token_endpoint', () => {
    expect(isPersonServerMetadata(legacyDoc)).toBe(false)
    expect(missingPersonServerMembers(legacyDoc)).toEqual([
      'auth_token_endpoint',
      'person_token_endpoint',
    ])
  })

  it('rejects a document with auth_token_endpoint but no person_token_endpoint', () => {
    const { person_token_endpoint, ...rest } = doc
    void person_token_endpoint
    expect(isPersonServerMetadata(rest)).toBe(false)
    expect(missingPersonServerMembers(rest)).toEqual(['person_token_endpoint'])
  })

  it('rejects non-objects', () => {
    expect(isPersonServerMetadata(null)).toBe(false)
    expect(isPersonServerMetadata('nope')).toBe(false)
    expect(missingPersonServerMembers(undefined)).toHaveLength(4)
  })
})

describe('metadata cache round-trip', () => {
  it('writes then reads back the exact doc', () => {
    writeCachedMetadata(HOST, doc, 3600)
    expect(readCachedMetadata(HOST)).toEqual(doc)
  })

  it('preserves members it does not know about', () => {
    const extended = { ...doc, mission_endpoint: 'https://cache-test.invalid/m', future_member: 1 }
    writeCachedMetadata(HOST, extended, 3600)
    expect(readCachedMetadata(HOST)).toEqual(extended)
  })

  it('stamps the current schema version on write', () => {
    writeCachedMetadata(HOST, doc, 3600)
    expect(indexEntry()?.schema).toBe(CACHE_SCHEMA_VERSION)
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

describe('-11 cache invalidation', () => {
  it('reports a miss for a pre-11 entry rather than reading token_endpoint', () => {
    plantLegacyEntry()
    // The entry is unexpired and the doc parses; only the shape is stale.
    expect(readCachedMetadata(HOST)).toBeNull()
  })

  it('evicts the pre-11 entry so the miss is not permanent', () => {
    plantLegacyEntry()
    readCachedMetadata(HOST)
    expect(indexEntry()).toBeUndefined()

    // A refetch repopulates it in the -11 shape.
    writeCachedMetadata(HOST, doc, 3600)
    expect(readCachedMetadata(HOST)).toEqual(doc)
  })

  it('evicts an entry stamped with a future schema version', () => {
    writeCachedMetadata(HOST, doc, 3600)
    const index = JSON.parse(readFileSync(INDEX_FILE, 'utf-8'))
    index[`${HOST.replace(/\./g, '-')}/${PS_METADATA_FILE}`].schema = CACHE_SCHEMA_VERSION + 1
    writeFileSync(INDEX_FILE, JSON.stringify(index, null, 2) + '\n')

    expect(readCachedMetadata(HOST)).toBeNull()
    expect(indexEntry()).toBeUndefined()
  })

  it('misses on a current-schema entry whose body is not -11 metadata', () => {
    // Belt and braces: the schema stamp says 2 but the body is pre-11.
    writeCachedMetadata(HOST, doc, 3600)
    writeFileSync(join(hostDir, PS_METADATA_FILE), JSON.stringify(legacyDoc, null, 2) + '\n')

    expect(readCachedMetadata(HOST)).toBeNull()
    expect(indexEntry()).toBeUndefined()
  })
})

describe('write rejects non-conforming PS metadata', () => {
  it('names the -10 → -11 rename when the doc carries token_endpoint', () => {
    expect(() => writeCachedMetadata(HOST, legacyDoc, 3600)).toThrow(
      /pre-11 'token_endpoint', renamed to 'auth_token_endpoint'/,
    )
    expect(readCachedMetadata(HOST)).toBeNull()
  })

  it('rejects a PS with no person_token_endpoint', () => {
    const { person_token_endpoint, ...rest } = doc
    void person_token_endpoint
    expect(() => writeCachedMetadata(HOST, rest, 3600)).toThrow(/missing person_token_endpoint/)
  })

  it('does not validate the shape of other cached files', () => {
    const other = { anything: true }
    writeCachedMetadata(HOST, other, 3600, 'aauth-resource.json')
    expect(readCachedMetadata(HOST, 'aauth-resource.json')).toEqual(other)
    evictCachedMetadata(HOST, 'aauth-resource.json')
  })
})
