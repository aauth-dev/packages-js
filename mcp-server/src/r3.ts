import { R3Error } from './errors.js'
import { sha256Base64url, timingSafeEqualString, randomToken, nowSeconds } from './util.js'

/**
 * AAuth Rich Resource Requests (R3) — resource side.
 *
 * The two rules that everything here exists to enforce:
 *
 *  1. **Content addressing has no canonicalization step.** `r3_s256` is the
 *     SHA-256 of the bytes as served. Serialize once, store the bytes, serve
 *     those exact bytes on every request for the same `r3_uri`. Any
 *     re-stringify — middleware that parses and re-encodes JSON, a framework
 *     `json()` helper, CDN minification — changes the bytes and breaks hash
 *     verification at the PS and AS.
 *
 *  2. **Agents must never read an R3 document.** Only the AS named in the
 *     `aud` of a resource token carrying that `r3_uri`, and the PS named by the
 *     `ps` claim of the agent token the agent presented, may fetch it. Agent
 *     opacity — the agent carries the hash of a document it cannot read —
 *     depends entirely on this.
 */

// --- Document shape (AAuth-R3 §R3 Document) ---

export interface R3Display {
  /** REQUIRED when `display` is present. Short plain-language consent line. */
  summary: string
  implications?: string
  data_accessed?: string
  irreversible?: string
  /** Per-call proposals only: Markdown detail for the approval screen. */
  detail?: string
}

/**
 * A parameter value represented by a digest instead of inline, for a large or
 * sensitive payload. The full bytes travel agent → resource at call time; only
 * the hash and a short excerpt reach the PS.
 */
export interface R3ParameterDigest {
  /** `BASE64URL(SHA-256(value-bytes))` of the value as presented at call time. */
  s256: string
  excerpt?: string
  media_type?: string
}

export type R3ParameterValue =
  | string | number | boolean | null
  | R3ParameterDigest
  | unknown[]
  | Record<string, unknown>

/** `{ vocabulary, operations }` — the shape shared by an R3 document's
 *  `operations`, the agent's `r3_operations` request, and the auth token's
 *  `r3_granted` / `r3_per_call` claims. */
export interface R3OperationSet {
  vocabulary: string
  operations: unknown[]
}

export interface R3Document {
  /** REQUIRED. Vocabulary URI; MUST be one the resource advertises in
   *  `r3_vocabularies`. */
  vocabulary: string
  /** REQUIRED. Operations covered, in the vocabulary's structure. */
  operations: unknown[]
  /** Present when the authorization request carried an `account`. */
  account?: string
  display?: R3Display
  /** REQUIRED on a per-call proposal, absent on a class document. */
  parameters?: Record<string, R3ParameterValue>
}

// R3 -02 removed the `version` field. Do not add it back; it changes the bytes
// and therefore the hash, and no verifier reads it.

// --- Store (supplied by the caller) ---

/**
 * The persisted form of one R3 document.
 *
 * `body` is the authoritative artifact: the exact serialized JSON text whose
 * SHA-256 is `s256`. Serve it verbatim. Never parse it and re-serialize it
 * on the way out.
 */
export interface R3Record {
  /** The `r3_uri` this record is served at. */
  uri: string
  /** `BASE64URL(SHA-256(body))`, unpadded — the `r3_s256` claim value. */
  s256: string
  /** The exact bytes to serve, as a UTF-8 string. */
  body: string
  /**
   * Server identifiers entitled to fetch this document: the `aud` of the
   * resource token carrying this `r3_uri` (the PS in three-party, the AS in
   * four-party), plus the agent's PS from the agent token's `ps` claim.
   * Compared by exact string equality. Every other signer is rejected.
   */
  authorized: string[]
  createdAt: number
  /** Unix seconds. Advisory — a store with native TTL should also expire it. */
  expiresAt?: number
}

/**
 * The store a caller supplies. Two methods, both keyed by opaque string.
 *
 * `aauth-proxy` backs this with Workers KV (`put(key, JSON.stringify(record),
 * { expirationTtl })`), `notes` with its own KV namespace, tests with a `Map`.
 * `MemoryR3Store` below is a conforming implementation.
 *
 * A record is written under two keys: its `s256` and its `uri`. Lookups by
 * hash (the per-call retry path, which has only `r3_s256` from the auth token)
 * and by URI (the fetch path) both resolve.
 */
export interface R3Store {
  get(key: string): Promise<R3Record | null>
  put(key: string, record: R3Record, ttlSeconds?: number): Promise<void>
}

/** In-memory `R3Store`, for tests and single-process deployments. */
export class MemoryR3Store implements R3Store {
  private map = new Map<string, { record: R3Record; expiresAt?: number }>()

  async get(key: string): Promise<R3Record | null> {
    const entry = this.map.get(key)
    if (!entry) return null
    if (entry.expiresAt !== undefined && nowSeconds() > entry.expiresAt) {
      this.map.delete(key)
      return null
    }
    return entry.record
  }

  async put(key: string, record: R3Record, ttlSeconds?: number): Promise<void> {
    this.map.set(key, {
      record,
      expiresAt: ttlSeconds === undefined ? undefined : nowSeconds() + ttlSeconds,
    })
  }

  get size(): number {
    return this.map.size
  }
}

// --- Serialization and content addressing ---

/** Media type R3 documents are served with. */
export const R3_MEDIA_TYPE = 'application/json'

/** Default document lifetime in the store, in seconds. */
export const R3_DEFAULT_TTL_SECONDS = 600

export interface SerializedR3 {
  /** The exact bytes. Serve verbatim. */
  body: string
  /** `BASE64URL(SHA-256(body))`, unpadded. */
  s256: string
}

/**
 * Serialize an R3 document once and hash the bytes.
 *
 * Call this exactly once per document. Hashing a re-serialization of the same
 * object is not guaranteed to produce the same bytes, and the hash the PS and
 * AS compute is over what the resource actually sends.
 */
export async function serializeR3Document(document: R3Document): Promise<SerializedR3> {
  assertValidR3Document(document)
  const body = JSON.stringify(document)
  return { body, s256: await sha256Base64url(body) }
}

/** `BASE64URL(SHA-256(body))` over bytes already serialized elsewhere. */
export async function computeR3Hash(body: string | Uint8Array): Promise<string> {
  return sha256Base64url(body)
}

function assertValidR3Document(document: R3Document): void {
  if (!document || typeof document !== 'object') {
    throw new R3Error('invalid_r3_document', 'R3 document must be an object')
  }
  if (typeof document.vocabulary !== 'string' || !document.vocabulary) {
    throw new R3Error('invalid_r3_document', 'R3 document requires a `vocabulary`')
  }
  if (!Array.isArray(document.operations) || document.operations.length === 0) {
    throw new R3Error('invalid_r3_document', 'R3 document requires a non-empty `operations`')
  }
  if (document.display && typeof document.display.summary !== 'string') {
    throw new R3Error('invalid_r3_document', 'R3 `display` requires a `summary`')
  }
  if ('version' in (document as unknown as Record<string, unknown>)) {
    throw new R3Error('invalid_r3_document', 'R3 -02 removed the `version` field')
  }
}

// --- Publication ---

export interface PublishR3Options {
  document: R3Document
  /** Base for the generated URI, e.g. `https://resource.example/r3`. The
   *  document is published at `{baseUri}/{r3_s256}`, so the same bytes always
   *  resolve to the same URI. Ignored when `uri` is given. */
  baseUri?: string
  /** Explicit `r3_uri`, when the resource has its own URI scheme. */
  uri?: string
  store: R3Store
  /**
   * Server identifiers entitled to fetch this document. Pass the `aud` of the
   * resource token you are about to mint, and the agent's PS (the agent
   * token's `ps` claim, or the person token's `iss`). Duplicates collapse.
   */
  authorized: Array<string | undefined>
  ttlSeconds?: number
}

export interface PublishedR3 {
  r3_uri: string
  r3_s256: string
  /** The exact bytes now in the store. */
  body: string
}

/**
 * Serialize, hash, and persist an R3 document, returning the `r3_uri` and
 * `r3_s256` to put in the resource token.
 *
 * The record is written under both its hash and its URI so that the per-call
 * retry (which knows only `r3_s256`) and the document fetch (which knows only
 * `r3_uri`) both resolve.
 */
export async function publishR3Document(options: PublishR3Options): Promise<PublishedR3> {
  const { document, store, ttlSeconds = R3_DEFAULT_TTL_SECONDS } = options
  const { body, s256 } = await serializeR3Document(document)

  const uri = options.uri ?? (options.baseUri
    ? `${options.baseUri.replace(/\/$/, '')}/${s256}`
    : undefined)
  if (!uri) {
    throw new R3Error('invalid_r3_uri', 'publishR3Document requires `uri` or `baseUri`')
  }
  if (!uri.startsWith('https://') && !uri.startsWith('http://localhost')) {
    throw new R3Error('invalid_r3_uri', 'An R3 document MUST be served over HTTPS')
  }

  const authorized = [...new Set(options.authorized.filter((v): v is string => !!v))]
  if (authorized.length === 0) {
    throw new R3Error(
      'invalid_r3_authorization',
      'publishR3Document requires at least one authorized fetcher — an R3 document ' +
      'with no entitled party can never be read, and one that skips the check is ' +
      'readable by the agent',
    )
  }

  const record: R3Record = {
    uri,
    s256,
    body,
    authorized,
    createdAt: nowSeconds(),
    expiresAt: nowSeconds() + ttlSeconds,
  }

  await store.put(s256, record, ttlSeconds)
  if (uri !== s256) await store.put(uri, record, ttlSeconds)

  return { r3_uri: uri, r3_s256: s256, body }
}

/** Generate an opaque R3 identifier, for a resource that does not want its URIs
 *  to be the content hash. */
export function generateR3Id(): string {
  return randomToken(16)
}

// --- Retrieval ---

export async function getR3ByUri(store: R3Store, uri: string): Promise<R3Record | null> {
  return store.get(uri)
}

export async function getR3ByHash(store: R3Store, s256: string): Promise<R3Record | null> {
  return store.get(s256)
}

/** Parse the stored bytes back into a document. Use for inspection and
 *  per-call parameter comparison only — never to re-serve. */
export function parseR3Record(record: R3Record): R3Document {
  return JSON.parse(record.body) as R3Document
}

// --- Fetch authorization (AAuth-R3 §R3 Document Access Restriction) ---

export interface R3FetchAuthorization {
  /**
   * The server identifier of the party that signed the fetch, established from
   * the verified HTTP Message Signature (its key's `iss`/issuer URL). This is
   * NOT taken from a header the caller controls.
   */
  signer: string
}

/**
 * True when `signer` is entitled to this document. Entitlement is the exact
 * string equality of `signer` against one of the identifiers recorded at
 * publication: the resource token's `aud`, or the agent's PS.
 */
export function isAuthorizedR3Fetcher(record: R3Record, signer: string): boolean {
  if (typeof signer !== 'string' || signer.length === 0) return false
  return record.authorized.some(a => a === signer)
}

export interface ServeR3Options {
  store: R3Store
  /** The requested `r3_uri`, or the bare `r3_s256` / id it ends with. */
  key: string
  /** Identifier of the party whose HTTP Message Signature verified. Pass
   *  `undefined` for an unsigned request — it is rejected. */
  signer: string | undefined
}

export interface R3Response {
  status: number
  headers: Record<string, string>
  /** The exact stored bytes on 200; a JSON error body otherwise. */
  body: string
}

/**
 * Build the response for a GET of an R3 document URI.
 *
 * Returns `401` for an unsigned request, `403` for a signer that is not the
 * entitled AS or PS, `404` when the document is unknown or expired, and `200`
 * with the exact stored bytes otherwise.
 *
 * The 200 body MUST be written to the wire as-is. Do not pass it through a
 * JSON response helper.
 */
export async function serveR3Document(options: ServeR3Options): Promise<R3Response> {
  const { store, key, signer } = options
  const noStore = { 'Cache-Control': 'no-store' }

  if (!signer) {
    return {
      status: 401,
      headers: { ...noStore, 'Content-Type': 'application/json' },
      body: JSON.stringify({ error: 'signature_required' }),
    }
  }

  const record = await store.get(key)
  if (!record) {
    return {
      status: 404,
      headers: { ...noStore, 'Content-Type': 'application/json' },
      body: JSON.stringify({ error: 'not_found' }),
    }
  }
  if (record.expiresAt !== undefined && nowSeconds() > record.expiresAt) {
    return {
      status: 404,
      headers: { ...noStore, 'Content-Type': 'application/json' },
      body: JSON.stringify({ error: 'not_found' }),
    }
  }

  if (!isAuthorizedR3Fetcher(record, signer)) {
    // Deliberately not "which party would be allowed" — an agent probing this
    // endpoint learns nothing about the document or its audience.
    return {
      status: 403,
      headers: { ...noStore, 'Content-Type': 'application/json' },
      body: JSON.stringify({ error: 'forbidden' }),
    }
  }

  return {
    status: 200,
    headers: {
      'Content-Type': R3_MEDIA_TYPE,
      // Content-addressed: the bytes at this URI never change.
      'Cache-Control': 'private, max-age=600',
      ETag: `"${record.s256}"`,
    },
    body: record.body,
  }
}

/** Throwing form of the entitlement check, for callers routing their own
 *  responses. */
export function assertAuthorizedR3Fetcher(record: R3Record, signer: string | undefined): void {
  if (!signer) {
    throw new R3Error('signature_required', 'R3 document fetch MUST carry an HTTP Message Signature')
  }
  if (!isAuthorizedR3Fetcher(record, signer)) {
    throw new R3Error(
      'r3_fetch_forbidden',
      `${signer} is not entitled to this R3 document`,
    )
  }
}

/** Verify fetched bytes against a claimed `r3_s256`. */
export async function verifyR3Hash(body: string | Uint8Array, expected: string): Promise<boolean> {
  return timingSafeEqualString(await sha256Base64url(body), expected)
}

export { R3Error } from './errors.js'
