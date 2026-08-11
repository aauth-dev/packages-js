/**
 * Runtime helpers. Everything here uses only globals that Cloudflare workerd
 * provides (`crypto`, `crypto.subtle`, `TextEncoder`, `fetch`) — no `node:*`
 * imports, so the package loads on Workers with or without `nodejs_compat`.
 */

const encoder = new TextEncoder()

export type Bytes = string | Uint8Array | ArrayBuffer

export function toBytes(value: Bytes): Uint8Array {
  if (typeof value === 'string') return encoder.encode(value)
  if (value instanceof Uint8Array) return value
  return new Uint8Array(value)
}

export function base64url(bytes: ArrayBuffer | Uint8Array): string {
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes)
  let binary = ''
  for (let i = 0; i < view.length; i++) binary += String.fromCharCode(view[i])
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/** `BASE64URL(SHA-256(value))`, unpadded — the encoding every `*_s256` claim uses. */
export async function sha256Base64url(value: Bytes): Promise<string> {
  const bytes = toBytes(value)
  const buf = new Uint8Array(bytes).buffer as ArrayBuffer
  const digest = await crypto.subtle.digest('SHA-256', buf)
  return base64url(digest)
}

/** Constant-time-ish comparison for hash and thumbprint equality. */
export function timingSafeEqualString(a: string, b: string): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i)
  return diff === 0
}

export function randomId(): string {
  return crypto.randomUUID()
}

export function randomToken(byteLength = 16): string {
  const bytes = new Uint8Array(byteLength)
  crypto.getRandomValues(bytes)
  return base64url(bytes)
}

export function nowSeconds(): number {
  return Math.floor(Date.now() / 1000)
}

/**
 * Server Identifier requirements, AAuth Protocol §Server Identifiers:
 * https scheme, host only (no port, path, query, fragment), no trailing slash,
 * lowercase. Comparison of two identifiers is exact string equality.
 */
export function isServerIdentifier(value: unknown): value is string {
  if (typeof value !== 'string' || value.length === 0) return false
  if (value !== value.toLowerCase()) return false
  if (value.endsWith('/')) return false
  let url: URL
  try {
    url = new URL(value)
  } catch {
    return false
  }
  if (url.protocol !== 'https:') return false
  if (url.port !== '') return false
  if (url.search !== '' || url.hash !== '') return false
  if (url.pathname !== '/' && url.pathname !== '') return false
  // `new URL('https://a.example')` normalizes pathname to '/', so reject only a
  // literal trailing slash in the input (already handled above) or any deeper path.
  return value === `${url.protocol}//${url.host}`
}

/** Deep structural equality. Object key order is ignored; array order is not. */
export function deepEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true
  if (typeof a !== typeof b) return false
  if (a === null || b === null) return false
  if (Array.isArray(a) || Array.isArray(b)) {
    if (!Array.isArray(a) || !Array.isArray(b) || a.length !== b.length) return false
    return a.every((item, i) => deepEqual(item, b[i]))
  }
  if (typeof a === 'object') {
    const ao = a as Record<string, unknown>
    const bo = b as Record<string, unknown>
    const ak = Object.keys(ao)
    const bk = Object.keys(bo)
    if (ak.length !== bk.length) return false
    return ak.every(k => Object.prototype.hasOwnProperty.call(bo, k) && deepEqual(ao[k], bo[k]))
  }
  return false
}
