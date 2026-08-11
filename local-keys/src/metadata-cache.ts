import { readFileSync, writeFileSync, mkdirSync, renameSync, rmSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { homedir } from 'node:os'
import { randomUUID } from 'node:crypto'

/**
 * On-disk cache for fetched discovery metadata (e.g. a person server's
 * `aauth-person.json`). This is *public* metadata, not a secret — tokens are
 * never cached here.
 *
 * Layout (`~/.aauth/cache/`, alongside `config.json`):
 *   cache/<host dots→dashes>/aauth-person.json   ← the raw fetched doc
 *   cache/index.json                              ← { "<host>/<file>": { expires_at, schema } }
 *
 * Freshness is purely time-based: use the cached doc while `now < expires_at`,
 * otherwise refetch. `expires_at` = fetch time + the server's `Cache-Control:
 * max-age` if it sent one, else a 1-day default. No etag/revalidation.
 *
 * ## Schema version — AAuth -11
 *
 * -11 renamed the PS metadata field `token_endpoint` to `auth_token_endpoint`
 * and added `person_token_endpoint` as REQUIRED (#ps-metadata). Entries written
 * before -11 therefore hold a document whose auth token endpoint is under a name
 * no -11 reader looks at, and which has no person token endpoint at all.
 *
 * Those entries are **invalidated, not migrated**. Migration is not possible in
 * the direction that matters: `person_token_endpoint` is REQUIRED and there is
 * nothing in a pre-11 document to derive it from, so a "migrated" entry would be
 * a document that still fails -11 validation while now looking current. The
 * rename alone is mechanical, but half a migration is worse than none — the
 * whole point is that a cache holding `token_endpoint` must never read back as a
 * PS with no auth token endpoint. The cache is a latency optimization over a
 * public document, so the cost of invalidating is one HTTP GET per PS.
 *
 * Two independent gates enforce that:
 *
 *  1. every entry carries `schema`, and a read at any other version evicts the
 *     entry and reports a miss; and
 *  2. reads and writes of `aauth-person.json` validate the document shape, so an
 *     entry that somehow carries the right version but the wrong body is still a
 *     miss.
 */

const CACHE_DIR = join(homedir(), '.aauth', 'cache')
const INDEX_FILE = join(CACHE_DIR, 'index.json')
const DEFAULT_TTL_SECONDS = 24 * 60 * 60

/** Standard filename for person-server metadata. */
export const PS_METADATA_FILE = 'aauth-person.json'

/**
 * Stored-shape version. Bumped to 2 for AAuth -11 (`auth_token_endpoint` +
 * `person_token_endpoint`). Entries at any other version are evicted on read.
 */
export const CACHE_SCHEMA_VERSION = 2

/**
 * Person Server metadata, `/.well-known/aauth-person.json` (AAuth -11
 * #ps-metadata). Unknown members are preserved verbatim — the cache stores what
 * the server sent.
 */
export interface PersonServerMetadata {
  /** REQUIRED. The PS's HTTPS URL; the `iss` of tokens it issues. */
  issuer: string
  /** REQUIRED. Where agents send token requests. Renamed from `token_endpoint` in -11. */
  auth_token_endpoint: string
  /** REQUIRED, new in -11. Where agents request a person token for a resource. */
  person_token_endpoint: string
  /** REQUIRED. The PS's JWKS. */
  jwks_uri: string

  name?: string
  description?: string
  logo_uri?: string
  logo_dark_uri?: string
  documentation_uri?: string
  tos_uri?: string
  policy_uri?: string
  mission_endpoint?: string
  permission_endpoint?: string
  audit_endpoint?: string
  interaction_endpoint?: string
  mission_control_endpoint?: string
  revocation_endpoint?: string
  scopes_supported?: string[]
  claims_supported?: string[]

  [member: string]: unknown
}

/** The members #ps-metadata marks REQUIRED. */
const PS_REQUIRED_MEMBERS = [
  'issuer',
  'auth_token_endpoint',
  'person_token_endpoint',
  'jwks_uri',
] as const

interface CacheIndexEntry {
  expires_at: number
  /** {@link CACHE_SCHEMA_VERSION} at write time. Absent on pre-11 entries. */
  schema?: number
}

interface CacheIndex {
  [key: string]: CacheIndexEntry
}

/** Hostname → cache dir segment, dots→dashes: `person.hello.coop` → `person-hello-coop`. */
function hostSegment(host: string): string {
  return host.replace(/\./g, '-')
}

function entryKey(host: string, file: string): string {
  return `${hostSegment(host)}/${file}`
}

function docPath(host: string, file: string): string {
  return join(CACHE_DIR, hostSegment(host), file)
}

/** Write via a temp file in the same dir + rename, so readers never see a partial file. */
function atomicWrite(path: string, data: string): void {
  mkdirSync(dirname(path), { recursive: true })
  const tmp = `${path}.${randomUUID()}.tmp`
  writeFileSync(tmp, data)
  renameSync(tmp, path)
}

function readIndex(): CacheIndex {
  try {
    return JSON.parse(readFileSync(INDEX_FILE, 'utf-8')) as CacheIndex
  } catch {
    return {}
  }
}

function writeIndex(index: CacheIndex): void {
  atomicWrite(INDEX_FILE, JSON.stringify(index, null, 2) + '\n')
}

/** Parse `max-age` (seconds) from a `Cache-Control` header value, if present. */
export function parseMaxAge(cacheControl: string | null | undefined): number | undefined {
  if (!cacheControl) return undefined
  const m = /(?:^|[,\s])max-age\s*=\s*(\d+)/i.exec(cacheControl)
  return m ? parseInt(m[1], 10) : undefined
}

/**
 * Members of {@link PS_REQUIRED_MEMBERS} the document is missing. Empty when the
 * document is a valid -11 PS metadata document.
 */
export function missingPersonServerMembers(doc: unknown): string[] {
  if (!doc || typeof doc !== 'object') return [...PS_REQUIRED_MEMBERS]
  const d = doc as Record<string, unknown>
  return PS_REQUIRED_MEMBERS.filter((m) => typeof d[m] !== 'string' || d[m] === '')
}

/** Type guard for a document that satisfies -11 #ps-metadata. */
export function isPersonServerMetadata(doc: unknown): doc is PersonServerMetadata {
  return missingPersonServerMembers(doc).length === 0
}

/**
 * Throw a diagnosis for a document that is not valid -11 PS metadata, calling
 * out the -10 → -11 rename when the document still carries `token_endpoint`.
 */
function rejectPersonServerDoc(doc: unknown, missing: string[], what: string): never {
  const legacy =
    doc && typeof doc === 'object' && typeof (doc as Record<string, unknown>).token_endpoint === 'string'
      ? " — it carries the pre-11 'token_endpoint', renamed to 'auth_token_endpoint' in AAuth -11"
      : ''
  throw new Error(
    `${what} is not valid AAuth -11 person server metadata: missing ${missing.join(', ')}${legacy}`,
  )
}

/**
 * The cached doc if present, current-schema, unexpired and well-formed, else
 * null. A stale-schema or malformed entry is evicted so the next fetch replaces
 * it rather than the miss recurring forever.
 */
export function readCachedMetadata<T = PersonServerMetadata>(
  host: string,
  file = PS_METADATA_FILE,
): T | null {
  const entry = readIndex()[entryKey(host, file)]
  if (!entry) return null

  // Gate 1: stored shape. Pre-11 entries have no `schema` at all.
  if (entry.schema !== CACHE_SCHEMA_VERSION) {
    evictCachedMetadata(host, file)
    return null
  }

  if (Math.floor(Date.now() / 1000) >= entry.expires_at) return null

  let doc: unknown
  try {
    doc = JSON.parse(readFileSync(docPath(host, file), 'utf-8'))
  } catch {
    return null
  }

  // Gate 2: document shape, for the one file whose shape this package knows.
  if (file === PS_METADATA_FILE && !isPersonServerMetadata(doc)) {
    evictCachedMetadata(host, file)
    return null
  }

  return doc as T
}

/**
 * Persist a fetched doc + its expiry (server `max-age` if given, else the 1-day
 * default).
 *
 * Writing `aauth-person.json` throws when the document is not valid -11 PS
 * metadata: a PS without a `person_token_endpoint` is not one this stack can
 * use, and caching it would only defer the failure to a later read.
 */
export function writeCachedMetadata(
  host: string,
  doc: unknown,
  maxAgeSeconds?: number,
  file = PS_METADATA_FILE,
): void {
  if (file === PS_METADATA_FILE) {
    const missing = missingPersonServerMembers(doc)
    if (missing.length > 0) {
      rejectPersonServerDoc(doc, missing, `Person server metadata for ${host}`)
    }
  }

  atomicWrite(docPath(host, file), JSON.stringify(doc, null, 2) + '\n')
  const index = readIndex()
  const ttl = maxAgeSeconds && maxAgeSeconds > 0 ? maxAgeSeconds : DEFAULT_TTL_SECONDS
  index[entryKey(host, file)] = {
    expires_at: Math.floor(Date.now() / 1000) + ttl,
    schema: CACHE_SCHEMA_VERSION,
  }
  writeIndex(index)
}

/** Drop a cached entry (used by the self-heal path when an endpoint goes stale). */
export function evictCachedMetadata(host: string, file = PS_METADATA_FILE): void {
  const index = readIndex()
  delete index[entryKey(host, file)]
  writeIndex(index)
  try { rmSync(docPath(host, file)) } catch { /* already gone */ }
}
