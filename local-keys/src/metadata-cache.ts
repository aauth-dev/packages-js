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
 *   cache/index.json                              ← { "<host>/<file>": { expires_at } }
 *
 * Freshness is purely time-based: use the cached doc while `now < expires_at`,
 * otherwise refetch. `expires_at` = fetch time + the server's `Cache-Control:
 * max-age` if it sent one, else a 1-day default. No etag/revalidation.
 */

const CACHE_DIR = join(homedir(), '.aauth', 'cache')
const INDEX_FILE = join(CACHE_DIR, 'index.json')
const DEFAULT_TTL_SECONDS = 24 * 60 * 60

/** Standard filename for person-server metadata. */
export const PS_METADATA_FILE = 'aauth-person.json'

interface CacheIndex {
  [key: string]: { expires_at: number }
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

/** The cached doc if present and not expired, else null. */
export function readCachedMetadata(host: string, file = PS_METADATA_FILE): unknown | null {
  const entry = readIndex()[entryKey(host, file)]
  if (!entry || Math.floor(Date.now() / 1000) >= entry.expires_at) return null
  try {
    return JSON.parse(readFileSync(docPath(host, file), 'utf-8'))
  } catch {
    return null
  }
}

/** Persist a fetched doc + its expiry (server `max-age` if given, else the 1-day default). */
export function writeCachedMetadata(host: string, doc: unknown, maxAgeSeconds?: number, file = PS_METADATA_FILE): void {
  atomicWrite(docPath(host, file), JSON.stringify(doc, null, 2) + '\n')
  const index = readIndex()
  const ttl = maxAgeSeconds && maxAgeSeconds > 0 ? maxAgeSeconds : DEFAULT_TTL_SECONDS
  index[entryKey(host, file)] = { expires_at: Math.floor(Date.now() / 1000) + ttl }
  writeIndex(index)
}

/** Drop a cached entry (used by the self-heal path when an endpoint goes stale). */
export function evictCachedMetadata(host: string, file = PS_METADATA_FILE): void {
  const index = readIndex()
  delete index[entryKey(host, file)]
  writeIndex(index)
  try { rmSync(docPath(host, file)) } catch { /* already gone */ }
}
