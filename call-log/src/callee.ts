// The callee side: a Hono-shaped middleware. It names the call before the
// handler runs (so the handler's outbound calls carry it as `parent`), then
// writes the record once the response is known, reading the cloned bodies
// off the request path.
//
// Typed against the little of Hono it uses, so the package depends on
// nothing: `c.req.raw` (a Request), `c.res` (a Response after `next()`),
// `c.executionCtx.waitUntil` when there is one.

import { callIdOf, signerOf, withThumbprint, paramsOf, errorOf, partOf, buildRecord } from './record.js'
import { runInCall, currentCall, type CallContext } from './context.js'
import { emit, defer, type CallLogHost } from './host.js'

export interface ContextLike {
  req: { raw: Request }
  res: Response
  executionCtx?: { waitUntil(p: Promise<unknown>): void }
}
export type Next = () => Promise<void>

export interface CalleeOptions {
  /** Paths (or a test) that are not calls between roles: metadata, health, an SSE stream. */
  skip?: (request: Request) => boolean
}

const skipByDefault = (request: Request) => {
  if (request.method === 'OPTIONS' || request.method === 'HEAD') return true
  const path = new URL(request.url).pathname
  return path.startsWith('/.well-known/') || path === '/health' || path === '/openapi.json'
}

// A request body is read once by the handler. Clone before `next()` only
// when it is worth logging: JSON, and small. Cloning tees the stream, and a
// tee that nobody drains holds the bytes.
const worthCloning = (request: Request) => {
  if (!request.body) return false
  const type = request.headers.get('content-type') ?? ''
  if (!/json/i.test(type)) return false
  const length = Number(request.headers.get('content-length'))
  return !(Number.isFinite(length) && length > 256 * 1024)
}

/**
 * `app.use('*', callLogMiddleware(host))`, before the routes. Every request
 * not skipped gets one callee record.
 */
export function callLogMiddleware(host: CallLogHost, options: CalleeOptions = {}) {
  const skip = options.skip ?? skipByDefault
  return async (c: ContextLike, next: Next): Promise<void> => {
    const request = c.req.raw
    if (skip(request)) return next()
    const started = new Date()
    const callId = await callIdOf(request.headers.get('signature'))
    const requestClone = worthCloning(request) ? request.clone() : null
    const context: CallContext = { callId }
    await runInCall(context, next)
    const response = c.res
    const ended = Date.now()
    const responseClone = response.clone()
    const hostWithCtx: CallLogHost = c.executionCtx?.waitUntil
      ? { ...host, defer: host.defer ?? ((p) => c.executionCtx!.waitUntil(p)) }
      : host
    defer(
      hostWithCtx,
      (async () => {
        const signer = await withThumbprint(signerOf(request.headers.get('signature-key')))
        const agent = context.agent ?? signer.agent
        const params = paramsOf(response.headers)
        const url = new URL(request.url)
        const requestPart = await partOf(requestClone)
        const responsePart = await partOf(responseClone, params)
        emit(
          hostWithCtx,
          buildRecord({
            side: 'callee',
            call_id: callId,
            from: signer.from ?? agent,
            from_role: signer.from_role ?? (agent ? 'agent' : undefined),
            to: host.origin,
            to_role: host.role,
            agent,
            method: request.method,
            path: url.pathname,
            query: url.search.slice(1) || undefined,
            status: response.status,
            started_at: started.toISOString(),
            duration_ms: ended - started.getTime(),
            signed: signer.signed,
            request: requestPart,
            response: responsePart,
            error: response.status >= 400 ? errorOf(params, responsePart?.body) : undefined,
          }),
        )
      })(),
    )
  }
}

/** The call being handled, for a handler that wants to know: its id. */
export const currentCallId = (): string | undefined => currentCall()?.callId
