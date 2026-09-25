// The aauth.call record, built from what one end of a call knows. Pure:
// no I/O, no clock beyond what the caller passes. The shape is
// aauth-dev/monitor plan/CALL_RECORD.md; the reference reader is the
// monitor's client/calls.js.
//
// Tokens are logged as { type, payload } — the `typ` header and the claims —
// wherever they appear: in `signed` and in place of the JWT string in a
// body, at any depth. Never the JWT, so no log holds a presentable token.

export type Role = 'agent' | 'resource' | 'ps' | 'as'
export type Side = 'caller' | 'callee' | 'person'

export interface Token {
  type: string
  payload: Record<string, unknown>
}

export type Signed =
  | { scheme: 'jwt'; token?: Token }
  | { scheme: 'jwks_uri'; id?: string; dwk?: string; kid?: string }
  | { scheme: 'hwk'; jkt?: string }

export interface Part {
  body?: unknown
  params?: Record<string, unknown>
  content_type?: string
  size?: number
}

export interface CallRecord {
  event: 'aauth.call'
  side: Side
  call_id: string
  parent?: string
  from?: string
  from_role?: Role
  to: string
  to_role?: Role
  agent?: string
  action?: string
  method?: string
  path?: string
  query?: string
  status?: number
  started_at: string
  duration_ms?: number
  signed?: Signed
  request?: Part
  response?: Part
  error?: string
  truncated?: true
  /** 30, 40 or 50 — see levelOf. */
  level: number
  msg: string
}

/** A wallet_events entry is capped at 32 KB (Wallet #4285); every party keeps to it. */
export const MAX_RECORD_BYTES = 32 * 1024 - 2048

const ROLE_BY_DWK: Record<string, Role> = {
  'aauth-person.json': 'ps',
  'aauth-access.json': 'as',
  'aauth-resource.json': 'resource',
  'aauth-agent.json': 'agent',
}
const AGENT_TOKEN_TYPES = new Set(['aa-agent+jwt'])
const PARAM_HEADERS: Record<string, string> = {
  'aauth-requirement': 'AAuth-Requirement',
  'signature-error': 'Signature-Error',
  'aauth-budget': 'AAuth-Budget',
}

// ── base64url, SHA-256 ──

const encoder = new TextEncoder()

function b64url(bytes: Uint8Array): string {
  let s = ''
  for (const b of bytes) s += String.fromCharCode(b)
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function b64urlJson(part: string): Record<string, unknown> | null {
  try {
    const padded = part + '='.repeat((4 - (part.length % 4)) % 4)
    const bin = atob(padded.replace(/-/g, '+').replace(/_/g, '/'))
    const bytes = new Uint8Array(bin.length)
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i)
    const json: unknown = JSON.parse(new TextDecoder().decode(bytes))
    return json && typeof json === 'object' && !Array.isArray(json) ? (json as Record<string, unknown>) : null
  } catch {
    return null
  }
}

/**
 * `call_id`: base64url SHA-256 of the Signature header. Both ends hold the
 * header, so their records join with no new header on the wire.
 */
export async function callIdOf(signatureHeader: string | null | undefined): Promise<string> {
  if (!signatureHeader) return crypto.randomUUID()
  const digest = await crypto.subtle.digest('SHA-256', encoder.encode(signatureHeader))
  return b64url(new Uint8Array(digest))
}

// ── Tokens ──

/** A compact JWS string as { type, payload }, or null. A JWE (five parts) stays as it is. */
export function tokenOf(value: unknown): Token | null {
  if (typeof value !== 'string' || value.length < 20) return null
  const parts = value.split('.')
  if (parts.length !== 3) return null
  const header = b64urlJson(parts[0])
  if (!header || typeof header.alg !== 'string') return null
  const payload = b64urlJson(parts[1])
  if (!payload) return null
  return { type: typeof header.typ === 'string' ? header.typ : 'jwt', payload }
}

/** A value with every token string, at any depth, replaced by { type, payload }. */
export function tokenize(value: unknown, depth = 0): unknown {
  if (depth > 12) return value
  const token = tokenOf(value)
  if (token) return token
  if (Array.isArray(value)) return value.map((v) => tokenize(v, depth + 1))
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {}
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) out[k] = tokenize(v, depth + 1)
    return out
  }
  return value
}

// ── Signature-Key ──

// An RFC 8941 dictionary with one member whose bare value is the scheme and
// whose parameters are strings or tokens — the only shape Signature-Key
// takes. Enough parser for that; anything else is null.
function parseSignatureKey(header: string): { scheme: string; params: Record<string, string> } | null {
  const m = /^\s*([A-Za-z*][\w.*-]*)\s*=\s*([A-Za-z*][\w:/.*-]*)\s*((?:;\s*[^;]*)*)$/.exec(header)
  if (!m) return null
  const params: Record<string, string> = {}
  for (const raw of m[3].split(';')) {
    const p = raw.trim()
    if (!p) continue
    const eq = p.indexOf('=')
    if (eq < 0) return null
    const key = p.slice(0, eq).trim()
    let value = p.slice(eq + 1).trim()
    if (value.startsWith('"')) {
      if (!value.endsWith('"')) return null
      value = value.slice(1, -1).replace(/\\(["\\])/g, '$1')
    }
    params[key] = value
  }
  return { scheme: m[2], params }
}

export interface Signer {
  signed?: Signed
  from?: string
  from_role?: Role
  agent?: string
}

/**
 * What signed a request, from its Signature-Key header, and who that makes
 * the caller — as far as the header says, with no verification, so a
 * refused call still names its caller.
 */
export function signerOf(signatureKeyHeader: string | null | undefined): Signer {
  if (!signatureKeyHeader) return {}
  const parsed = parseSignatureKey(signatureKeyHeader)
  if (!parsed) return {}
  const { scheme, params } = parsed
  if (scheme === 'jwt') {
    const token = tokenOf(params.jwt)
    if (!token) return { signed: { scheme: 'jwt' } }
    const { payload } = token
    // An agent token names the agent in `sub`; a person or auth token in
    // `agent_id` (the Hellō PS) or `agent` (the fleet's access server).
    const named = [payload.agent_id, payload.agent].find((v): v is string => typeof v === 'string')
    const agent = AGENT_TOKEN_TYPES.has(token.type) && typeof payload.sub === 'string' ? payload.sub : named
    return { signed: { scheme: 'jwt', token }, from: agent, from_role: agent ? 'agent' : undefined, agent }
  }
  if (scheme === 'jwks_uri') {
    const { id, dwk, kid } = params
    return { signed: { scheme: 'jwks_uri', id, dwk, kid }, from: id, from_role: dwk ? ROLE_BY_DWK[dwk] : undefined }
  }
  if (scheme === 'hwk') return { signed: { scheme: 'hwk' } }
  return {}
}

// ── Response headers with protocol meaning ──

// `requirement=interaction; url="…"; code="…"`, `error=revoked_jwt`,
// `cost=2; remaining=98; unit="credits"`: key=value pairs, quotes dropped.
function parseParamHeader(value: string): Record<string, string> | string {
  const out: Record<string, string> = {}
  for (const pair of value.split(';')) {
    const m = /^\s*([A-Za-z0-9_.-]+)\s*=\s*(.*?)\s*$/.exec(pair)
    if (!m) return value
    const raw = m[2]
    out[m[1]] = raw.startsWith('"') && raw.endsWith('"') ? raw.slice(1, -1).replace(/\\(["\\])/g, '$1') : raw
  }
  return Object.keys(out).length ? out : value
}

type HeadersLike = Headers | Record<string, string | string[] | undefined>

function header(headers: HeadersLike, name: string): string | undefined {
  const v = typeof (headers as Headers).get === 'function' ? (headers as Headers).get(name) : (headers as Record<string, string | string[] | undefined>)[name]
  const one = Array.isArray(v) ? v[0] : v
  return typeof one === 'string' && one ? one : undefined
}

/** AAuth-Requirement, Signature-Error and AAuth-Budget parsed; Location as is. */
export function paramsOf(headers: HeadersLike | null | undefined): Record<string, unknown> | undefined {
  if (!headers) return undefined
  const out: Record<string, unknown> = {}
  for (const [name, shown] of Object.entries(PARAM_HEADERS)) {
    const v = header(headers, name)
    if (v) out[shown] = parseParamHeader(v)
  }
  const location = header(headers, 'location')
  if (location) out.Location = location
  return Object.keys(out).length ? out : undefined
}

/** The error code of a refusal: the Signature-Error `error`, else the body's. */
export function errorOf(params: Record<string, unknown> | undefined, body: unknown): string | undefined {
  const sigErr = (params?.['Signature-Error'] as { error?: unknown } | undefined)?.error
  if (typeof sigErr === 'string') return sigErr
  if (body && typeof body === 'object') {
    const err = (body as { error?: unknown }).error
    if (typeof err === 'string') return err.slice(0, 64)
    const message = (err as { message?: unknown } | undefined)?.message
    if (typeof message === 'string') return message.slice(0, 64)
  }
  return undefined
}

const isChallenge = (r: { status?: number; response?: Part }) =>
  (r.status === 401 || r.status === 202) && !!r.response?.params?.['AAuth-Requirement']

/**
 * 30; 40 for a 4xx that is not a challenge, a peer's 5xx, or a fetch that
 * threw; 50 only for a 5xx the logging party answered itself.
 */
export function levelOf(r: { side: Side; status?: number; response?: Part }): number {
  if (r.side === 'callee' && r.status !== undefined && r.status >= 500) return 50
  if (r.status === undefined || (r.status >= 400 && !isChallenge(r))) return 40
  return 30
}

// ── Bodies and the cap ──

const JSON_TYPES = /json/i

/** What a body becomes in the record: JSON under the cap as a value, anything else as its type and size. */
export async function partOf(
  body: { text: () => Promise<string>; headers: HeadersLike } | null | undefined,
  params?: Record<string, unknown>,
): Promise<Part | undefined> {
  const out: Part = {}
  if (params) out.params = params
  if (body) {
    const content_type = header(body.headers, 'content-type')
    const length = Number(header(body.headers, 'content-length'))
    const size = Number.isFinite(length) && length > 0 ? length : undefined
    if (content_type && JSON_TYPES.test(content_type) && (size === undefined || size <= MAX_RECORD_BYTES * 4)) {
      try {
        const text = await body.text()
        if (text) {
          try {
            out.body = tokenize(JSON.parse(text))
          } catch {
            out.content_type = content_type
            out.size = encoder.encode(text).length
          }
        }
      } catch {
        if (content_type) out.content_type = content_type
      }
    } else if (content_type) {
      out.content_type = content_type
      if (size !== undefined) out.size = size
    }
  }
  return Object.keys(out).length ? out : undefined
}

/** Cut the larger body to text until the record fits the cap; say so. */
export function cap<T extends { request?: Part; response?: Part }>(input: T): T & { truncated?: true } {
  const record = input as T & { truncated?: true }
  const size = () => encoder.encode(JSON.stringify(record)).length
  let bytes = size()
  if (bytes <= MAX_RECORD_BYTES) return record
  const bodies = (['request', 'response'] as const)
    .filter((k) => record[k]?.body !== undefined)
    .map((k) => ({ k, text: JSON.stringify(record[k]!.body) }))
    .sort((a, b) => b.text.length - a.text.length)
  for (const { k, text } of bodies) {
    let room = Math.max(256, text.length - (bytes - MAX_RECORD_BYTES) - 64)
    for (;;) {
      record[k] = { ...record[k], body: text.slice(0, room) }
      record.truncated = true
      bytes = size()
      if (bytes <= MAX_RECORD_BYTES || room <= 256) break
      room = Math.max(256, room - (bytes - MAX_RECORD_BYTES) - 64)
    }
    if (bytes <= MAX_RECORD_BYTES) break
  }
  return record
}

// ── The record ──

export type RecordFields = Omit<CallRecord, 'event' | 'level' | 'msg' | 'truncated'>

/** Fields in, a finished record out: level, message, nothing undefined, under the cap. */
export function buildRecord(fields: RecordFields): CallRecord {
  const clean = (obj: Record<string, unknown>) => {
    for (const k of Object.keys(obj)) if (obj[k] === undefined || obj[k] === null) delete obj[k]
    return obj
  }
  const record = clean({ event: 'aauth.call', ...fields }) as unknown as CallRecord
  if (record.request) record.request = clean({ ...record.request }) as Part
  if (record.response) record.response = clean({ ...record.response }) as Part
  record.level = levelOf(record)
  record.msg =
    record.side === 'person'
      ? `Person ${record.action ?? 'acted'}`
      : `${record.side} ${record.method ?? ''} ${record.to}${record.path ?? ''} → ${record.status ?? 'failed'}`
  return cap(record)
}

/** `https://host/path?q` → { to, path, query }. */
export function targetOf(url: string): { to: string; path?: string; query?: string } {
  try {
    const u = new URL(url)
    return { to: u.origin, path: u.pathname, query: u.search.slice(1) || undefined }
  } catch {
    return { to: url }
  }
}
