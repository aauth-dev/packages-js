// What the host supplies: who it is, and where records go.

import type { CallRecord, Role } from './record.js'

export interface CallLogHost {
  /** This party's server identifier, `https://host`: `to` on the callee side, `from` on the caller side. */
  origin: string
  /** This party's role. */
  role: Role
  /**
   * The sink. Called once per record, never awaited, wrapped in try/catch.
   * The host adds its envelope (service, timestamp, event_id) and sends it
   * where its other events go — a Cloudflare queue by `ctx.waitUntil`, a
   * Pino logger, console.
   */
  log: (record: CallRecord) => void | Promise<void>
  /**
   * Where deferred work goes: reading a cloned body after the response has
   * been sent, hashing the Signature. In a Worker, `(p) => ctx.waitUntil(p)`.
   * Without one the work is simply not awaited.
   */
  defer?: (work: Promise<unknown>) => void
}

/** Send a record to the host, never throwing into a request. */
export function emit(host: CallLogHost, record: CallRecord): void {
  try {
    const result = host.log(record)
    if (result && typeof (result as Promise<void>).catch === 'function') (result as Promise<void>).catch(() => {})
  } catch {
    /* logging never fails a request */
  }
}

export function defer(host: CallLogHost, work: Promise<unknown>): void {
  const guarded = work.catch(() => {})
  if (host.defer) {
    try {
      host.defer(guarded)
    } catch {
      /* no execution context: the promise runs on its own */
    }
  }
}
