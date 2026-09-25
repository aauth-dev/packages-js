// @aauth/call-log — one log record per HTTP call between AAuth roles, at
// each end. Spec: aauth-dev/monitor plan/CALL_RECORD.md.
//
//   callee   callLogMiddleware(host)           a Hono-shaped middleware
//   caller   loggedFetch / loggedHttpsigFetch  a fetch that logs itself
//   parent   AsyncLocalStorage: the call being handled, found by any logged
//            fetch in its async continuation; nameAgent tells the record
//            which agent a verified call is for.

export type { CallRecord, RecordFields, Role, Side, Token, Signed, Part, Signer } from './record.js'
export { callIdOf, tokenOf, tokenize, signerOf, thumbprintOf, withThumbprint, paramsOf, errorOf, levelOf, partOf, cap, buildRecord, targetOf, MAX_RECORD_BYTES } from './record.js'
export type { CallLogHost } from './host.js'
export { emit } from './host.js'
export type { CallContext } from './context.js'
export { runInCall, currentCall, parentFromContext, nameAgent } from './context.js'
export type { ContextLike, Next, CalleeOptions } from './callee.js'
export { callLogMiddleware, currentCallId } from './callee.js'
export type { CallOptions, SentLike, FetchLike, HttpsigFetchLike } from './caller.js'
export { loggedFetch, loggedHttpsigFetch, failedFetch } from './caller.js'
