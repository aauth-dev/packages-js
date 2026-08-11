import type { JSONWebKeySet } from 'jose'
import { AAuthTokenError } from './errors.js'

/**
 * Key discovery per I-D.hardt-httpbis-signature-key: the `dwk` claim names the
 * issuer's well-known metadata document, fetched from `{iss}/.well-known/{dwk}`.
 * The document either carries `jwks_uri` or embeds `jwks` inline.
 */

export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>

interface CacheEntry {
  jwks: JSONWebKeySet
  fetchedAt: number
}

const jwksCache = new Map<string, CacheEntry>()
const DEFAULT_TTL_MS = 600_000 // 10 minutes

/** Exposed for tests and for operators that rotate keys out of band. */
export function clearMetadataCache(): void {
  jwksCache.clear()
}

export interface DiscoverOptions {
  iss: string
  dwk: string
  fetch?: FetchLike
  cacheTtlMs?: number
  errorCode?: string
}

export async function discoverJwks(options: DiscoverOptions): Promise<JSONWebKeySet> {
  const { iss, dwk } = options
  const doFetch = options.fetch ?? ((input, init) => globalThis.fetch(input, init))
  const ttl = options.cacheTtlMs ?? DEFAULT_TTL_MS
  const code = options.errorCode ?? 'jwks_discovery_failed'

  const metadataUrl = `${iss}/.well-known/${dwk}`
  const cached = jwksCache.get(metadataUrl)
  if (cached && Date.now() - cached.fetchedAt < ttl) return cached.jwks

  const res = await doFetch(metadataUrl)
  if (!res.ok) {
    throw new AAuthTokenError(
      'metadata_fetch_failed',
      `Failed to fetch metadata from ${metadataUrl}: ${res.status}`,
    )
  }
  const metadata = await res.json() as { jwks_uri?: string; jwks?: JSONWebKeySet }

  let jwks: JSONWebKeySet
  if (metadata.jwks && Array.isArray(metadata.jwks.keys)) {
    jwks = metadata.jwks
  } else if (metadata.jwks_uri) {
    const jwksRes = await doFetch(metadata.jwks_uri)
    if (!jwksRes.ok) {
      throw new AAuthTokenError(
        code,
        `Failed to fetch JWKS from ${metadata.jwks_uri}: ${jwksRes.status}`,
      )
    }
    jwks = await jwksRes.json() as JSONWebKeySet
  } else {
    throw new AAuthTokenError(
      'metadata_fetch_failed',
      `No jwks_uri or jwks in metadata from ${metadataUrl}`,
    )
  }

  if (!jwks || !Array.isArray(jwks.keys)) {
    throw new AAuthTokenError(code, `Malformed JWKS for ${iss}`)
  }

  jwksCache.set(metadataUrl, { jwks, fetchedAt: Date.now() })
  return jwks
}
