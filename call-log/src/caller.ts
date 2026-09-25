// The caller side: a fetch that logs itself. Two shapes of signed fetch
// exist in the fleet, so there are two wrappers over one core:
//
//   loggedFetch(makeFetch, host, call)   @aauth/agent createSignedFetch, which
//                                         reports the on-wire request through
//                                         `onSigned`. `makeFetch(onSigned)`
//                                         builds one signed fetch per call, so
//                                         concurrent calls cannot swap reports.
//   loggedHttpsigFetch(fetch, host, call) @hellocoop/httpsig fetch, called with
//                                         `returnSent: true`.
//
// The record is written once the response body has been read from a clone —
// off the caller's path, through host.defer. `parent` is the call being
// handled (AsyncLocalStorage) unless the caller passes one.

import { callIdOf, signerOf, paramsOf, errorOf, partOf, buildRecord, tokenize, targetOf, type Role, type Signed } from './record.js'
import { parentFromContext, currentCall } from './context.js'
import { emit, defer, type CallLogHost } from './host.js'

export interface CallOptions {
  /** The callee's role, when the caller knows it. */
  to_role?: Role
  /** The agent the call is for, when the caller knows it; else the one being handled. */
  agent?: string
  /** The call this one is made inside; else the one being handled. */
  parent?: string
}

export interface SentLike {
  headers: Headers | Record<string, string>
}

type Init = RequestInit & { body?: BodyInit | null }

const headerOf = (h: SentLike['headers'] | undefined, name: string): string | undefined => {
  if (!h) return undefined
  if (typeof (h as Headers).get === 'function') return (h as Headers).get(name) ?? undefined
  const rec = h as Record<string, string>
  return rec[name] ?? rec[name.toLowerCase()] ?? rec[name.replace(/(^|-)([a-z])/g, (m) => m.toUpperCase())]
}

async function record(
  host: CallLogHost,
  call: CallOptions,
  url: string,
  init: Init | undefined,
  started: Date,
  sent: SentLike | undefined,
  outcome: { response: Response; clone: Response } | { error: unknown },
): Promise<void> {
  const parent = call.parent ?? parentFromContext()
  const agent = call.agent ?? currentCall()?.agent
  const signer: { signed?: Signed } = sent ? signerOf(headerOf(sent.headers, 'signature-key')) : {}
  const call_id = await callIdOf(sent ? headerOf(sent.headers, 'signature') : undefined)
  const requestBody = typeof init?.body === 'string' ? safeJson(init.body) : undefined
  const base = {
    side: 'caller' as const,
    call_id,
    parent,
    from: host.origin,
    from_role: host.role,
    to_role: call.to_role,
    agent,
    method: (init?.method ?? 'GET').toUpperCase(),
    started_at: started.toISOString(),
    signed: signer.signed,
    request: requestBody === undefined ? undefined : { body: tokenize(requestBody) },
    ...targetOf(url),
  }
  if ('error' in outcome) {
    const err = outcome.error as { name?: string; message?: string } | undefined
    emit(host, buildRecord({ ...base, duration_ms: Date.now() - started.getTime(), error: err?.name === 'TimeoutError' || err?.name === 'AbortError' ? 'timeout' : `fetch: ${err?.message ?? String(outcome.error)}` }))
    return
  }
  const { response, clone } = outcome
  const duration_ms = Date.now() - started.getTime()
  const params = paramsOf(response.headers)
  const responsePart = await partOf(clone, params)
  emit(host, buildRecord({ ...base, status: response.status, duration_ms, response: responsePart, error: response.status >= 400 ? errorOf(params, responsePart?.body) : undefined }))
}

function safeJson(text: string): unknown {
  try {
    return JSON.parse(text)
  } catch {
    return text
  }
}

export type FetchLike = (url: string, init?: Init) => Promise<Response>

/**
 * For @aauth/agent's createSignedFetch. `makeFetch` is called once per call
 * with an `onSigned` to pass into createSignedFetch's options.
 */
export function loggedFetch(makeFetch: (onSigned: (sent: SentLike) => void) => FetchLike, host: CallLogHost, call: CallOptions = {}): FetchLike {
  return async (url, init) => {
    const started = new Date()
    let sent: SentLike | undefined
    const inner = makeFetch((s) => { sent = s })
    let response: Response
    try {
      response = await inner(url, init)
    } catch (error) {
      defer(host, record(host, call, url, init, started, sent, { error }))
      throw error
    }
    // Clone now, before the caller reads the body; the record reads the clone later.
    defer(host, record(host, call, url, init, started, sent, { response, clone: response.clone() }))
    return response
  }
}

export interface HttpsigFetchLike {
  (url: string, options: Record<string, unknown>): Promise<Response | { response: Response; sent: { headers: Headers } }>
}

/**
 * For @hellocoop/httpsig's fetch: the same options, plus the record. The
 * wrapper adds `returnSent: true` and unwraps the result.
 */
export function loggedHttpsigFetch(httpsigFetch: HttpsigFetchLike, host: CallLogHost, call: CallOptions = {}) {
  return async (url: string, options: Record<string, unknown>): Promise<Response> => {
    const started = new Date()
    const init = options as Init
    let result: Awaited<ReturnType<HttpsigFetchLike>>
    try {
      result = await httpsigFetch(url, { ...options, returnSent: true })
    } catch (error) {
      defer(host, record(host, call, url, init, started, undefined, { error }))
      throw error
    }
    const { response, sent } = 'response' in result ? result : { response: result, sent: undefined }
    defer(host, record(host, call, url, init, started, sent, { response, clone: response.clone() }))
    return response
  }
}

/** A fetch that failed or was refused, when the caller cannot wrap the fetch itself. */
export function failedFetch(host: CallLogHost, args: { url: string; method?: string; to_role?: Role; started?: Date; status?: number; error?: string; parent?: string }): void {
  const started = args.started ?? new Date()
  emit(
    host,
    buildRecord({
      side: 'caller',
      call_id: crypto.randomUUID(),
      parent: args.parent ?? parentFromContext(),
      from: host.origin,
      from_role: host.role,
      to_role: args.to_role,
      method: (args.method ?? 'GET').toUpperCase(),
      ...targetOf(args.url),
      status: args.status,
      started_at: started.toISOString(),
      duration_ms: args.started ? Date.now() - args.started.getTime() : undefined,
      error: args.error,
    }),
  )
}
