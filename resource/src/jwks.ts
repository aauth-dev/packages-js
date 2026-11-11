import type { JSONWebKeySet } from 'jose'
import {
  BoundedTtlCache,
  createKeyResolver,
  type KeyResolver,
  type KeyStoreEntry,
} from '@hellocoop/httpsig'
import { AAuthTokenError } from './errors.js'

/**
 * Key discovery per I-D.hardt-httpbis-signature-key: the `dwk` claim names the
 * issuer's well-known metadata document, fetched from `{iss}/.well-known/{dwk}`.
 * The document either carries `jwks_uri` or embeds `jwks` inline.
 *
 * The fetching and caching are `@hellocoop/httpsig`'s key resolver: a
 * timeout, a one-minute refetch floor that also holds after a failed fetch,
 * `Cache-Control: max-age` honored down to that floor, and one fetch shared
 * by concurrent lookups. Pass your own resolver (`keyResolver`) to supply
 * the cache store, the fetch, and an `onFetch` hook that logs every fetch;
 * pass the same one to `@hellocoop/httpsig` `verify()` so a server request
 * signed through the `jwks_uri` scheme and a token from the same issuer
 * share one cache.
 */

export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>

const DEFAULT_TTL_MS = 600_000 // 10 minutes

// The store behind discovery when the caller passes no resolver. Bounded:
// its keys are URLs taken from tokens that have not been verified yet.
const defaultStore = new BoundedTtlCache<KeyStoreEntry>()

// A resolver holds the in-flight table, so it has to outlive the call. One
// per injected fetch, all on the shared store.
const resolversByFetch = new WeakMap<FetchLike, Map<number, KeyResolver>>()
const resolversForGlobalFetch = new Map<number, KeyResolver>()

function defaultResolver(fetch: FetchLike | undefined, ttlMs: number): KeyResolver {
  let byTtl = fetch ? resolversByFetch.get(fetch) : resolversForGlobalFetch
  if (!byTtl) {
    byTtl = new Map()
    resolversByFetch.set(fetch as FetchLike, byTtl)
  }
  let resolver = byTtl.get(ttlMs)
  if (!resolver) {
    if (byTtl.size >= 8) byTtl.clear()
    resolver = createKeyResolver({
      store: defaultStore,
      maxTtlMs: ttlMs,
      ...(fetch ? { fetch } : {}),
    })
    byTtl.set(ttlMs, resolver)
  }
  return resolver
}

/**
 * Empty the built-in discovery cache. For tests and for operators that
 * rotate keys out of band. Does not touch a resolver you supplied.
 */
export function clearMetadataCache(): void {
  defaultStore.clear()
}

export interface DiscoverOptions {
  iss: string
  dwk: string
  /** Injectable fetch. Ignored when `keyResolver` is given. */
  fetch?: FetchLike
  /**
   * Longest a fetched document is treated as fresh (default 10 minutes).
   * Ignored when `keyResolver` is given.
   */
  cacheTtlMs?: number
  errorCode?: string
  /**
   * The resolver to discover through, from `createKeyResolver()` in
   * `@hellocoop/httpsig`. Supplies the store, the fetch, the timeout and the
   * `onFetch` logging hook.
   */
  keyResolver?: KeyResolver
  /** The `kid` being looked up, reported to the resolver's `onFetch`. */
  kid?: string
  /**
   * Fetch again even though a fresh copy is cached, subject to the resolver's
   * refetch floor. `verifyToken` does this once for an unknown `kid`.
   */
  refresh?: 'unknown_kid' | 'verify_failed'
}

export async function discoverJwks(options: DiscoverOptions): Promise<JSONWebKeySet> {
  const { iss, dwk, kid, refresh } = options
  const code = options.errorCode ?? 'jwks_discovery_failed'
  const resolver =
    options.keyResolver ?? defaultResolver(options.fetch, options.cacheTtlMs ?? DEFAULT_TTL_MS)

  // AAuth metadata may embed its JWKS, and is not required to repeat `issuer`.
  const lookup = { requireIssuer: false, allowInlineJwks: true, kid, refresh }
  const metadataUrl = `${iss}/.well-known/${dwk}`

  let metadata: Record<string, unknown>
  try {
    metadata = await resolver.getMetadata(iss, dwk, lookup)
  } catch (err) {
    throw new AAuthTokenError(
      'metadata_fetch_failed',
      `Failed to fetch metadata from ${metadataUrl}: ${(err as Error).message}`,
    )
  }

  const inline = metadata.jwks as { keys?: unknown } | undefined
  const hasInline = !!inline && Array.isArray(inline.keys)
  if (!hasInline && typeof metadata.jwks_uri !== 'string') {
    throw new AAuthTokenError(
      'metadata_fetch_failed',
      `No jwks_uri or jwks in metadata from ${metadataUrl}`,
    )
  }

  let jwks: { keys: unknown[] }
  try {
    jwks = await resolver.getJwks(iss, dwk, lookup)
  } catch (err) {
    throw new AAuthTokenError(
      code,
      `Failed to fetch JWKS from ${String(metadata.jwks_uri)}: ${(err as Error).message}`,
    )
  }

  if (!jwks || !Array.isArray(jwks.keys)) {
    throw new AAuthTokenError(code, `Malformed JWKS for ${iss}`)
  }
  return jwks as JSONWebKeySet
}
