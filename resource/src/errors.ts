/**
 * Error raised by token verification.
 *
 * `code` is the stable identifier — callers MUST branch on `code`, never on
 * `message`. The messages are for logs and may change.
 */
export class AAuthTokenError extends Error {
  constructor(public code: string, message: string) {
    super(message)
    this.name = 'AAuthTokenError'
  }
}

/** Error raised by R3 document publication, fetch authorization, and per-call
 *  proposal verification. */
export class R3Error extends Error {
  constructor(public code: string, message: string) {
    super(message)
    this.name = 'R3Error'
  }
}
