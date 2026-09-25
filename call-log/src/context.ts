// The call being handled, for the calls made while handling it: `parent`.
//
// Carried in AsyncLocalStorage (decided 2026-09-25), so a logged fetch made
// anywhere in the async continuation of the middleware finds it without an
// argument. `node:async_hooks` is there under Cloudflare's `nodejs_compat`
// flag and in Node. Where the chain is deliberately broken — a queue
// consumer, an alarm, a promise created outside the request — there is no
// store, and a caller passes `parent` itself.

import { AsyncLocalStorage } from 'node:async_hooks'

export interface CallContext {
  callId: string
  /** The agent this call is for, once a verifier has said (nameAgent). */
  agent?: string
}

const storage = new AsyncLocalStorage<CallContext>()

export const runInCall = <T>(context: CallContext, fn: () => T): T => storage.run(context, fn)

export const currentCall = (): CallContext | undefined => storage.getStore()

/** The `parent` for a call made now: the call being handled, if any. */
export const parentFromContext = (): string | undefined => storage.getStore()?.callId

/**
 * A verifier that learned which agent the call is for tells the record (a
 * person token names its agent only in the issuer's records). No-op outside
 * a logged call.
 */
export function nameAgent(agent: string | null | undefined): void {
  const store = storage.getStore()
  if (store && typeof agent === 'string' && agent) store.agent = agent
}
