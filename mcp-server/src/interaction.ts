import { randomBytes } from 'node:crypto'
import { buildAAuthHeader } from './aauth-header.js'

export interface PendingRequest<T = unknown> {
  id: string
  code: string
  createdAt: number
  resolve: (value: T) => void
  reject: (reason: unknown) => void
  promise: Promise<T>
}

export interface InteractionManagerOptions {
  baseUrl: string
  interactionUrl: string  // the interaction endpoint URL for AAuth-Requirement header
  pendingPath?: string   // default: '/pending'
  codeLength?: number    // default: 8
  ttl?: number           // default: 600s
}

const DEFAULT_PENDING_PATH = '/pending'
const DEFAULT_CODE_LENGTH = 8
const DEFAULT_TTL = 600

/**
 * Manages pending requests for the resource side of 202 interactions.
 *
 * - Generates interaction codes
 * - Tracks pending requests in memory
 * - Builds Location + AAuth headers for 202 responses
 * - Provides resolve/reject for when user completes interaction
 */
export class InteractionManager {
  private pending = new Map<string, PendingRequest>()
  private baseUrl: string
  private interactionUrl: string
  private pendingPath: string
  private codeLength: number
  private ttl: number

  constructor(options: InteractionManagerOptions) {
    this.baseUrl = options.baseUrl.replace(/\/$/, '')
    this.interactionUrl = options.interactionUrl.replace(/\/$/, '')
    this.pendingPath = options.pendingPath ?? DEFAULT_PENDING_PATH
    this.codeLength = options.codeLength ?? DEFAULT_CODE_LENGTH
    this.ttl = options.ttl ?? DEFAULT_TTL
  }

  /**
   * Create a pending request. Returns 202 response headers and the pending handle.
   */
  createPending<T = unknown>(): { headers: Record<string, string>; pending: PendingRequest<T> } {
    const id = randomBytes(16).toString('hex')
    const code = generateCode(this.codeLength)

    let resolve!: (value: T) => void
    let reject!: (reason: unknown) => void
    const promise = new Promise<T>((res, rej) => {
      resolve = res
      reject = rej
    })

    const pending: PendingRequest<T> = {
      id,
      code,
      createdAt: Date.now(),
      resolve,
      reject,
      promise,
    }

    this.pending.set(id, pending as PendingRequest)

    const locationUrl = `${this.baseUrl}${this.pendingPath}/${id}`
    const headers: Record<string, string> = {
      Location: locationUrl,
      'Retry-After': '0',
      'Cache-Control': 'no-store',
      'AAuth-Requirement': buildAAuthHeader('interaction', { url: this.interactionUrl, code }),
    }

    return { headers, pending }
  }

  /**
   * Look up a pending request by ID (for GET /pending/:id handler).
   */
  getPending(id: string): PendingRequest | undefined {
    return this.pending.get(id)
  }

  /**
   * Resolve a pending request (after user completes interaction).
   */
  resolve(id: string, value: unknown): void {
    const pending = this.pending.get(id)
    if (!pending) {
      throw new Error(`No pending request with id: ${id}`)
    }
    pending.resolve(value)
    this.pending.delete(id)
  }

  /**
   * Reject/expire a pending request.
   */
  reject(id: string, error: string): void {
    const pending = this.pending.get(id)
    if (!pending) {
      throw new Error(`No pending request with id: ${id}`)
    }
    pending.reject(new Error(error))
    this.pending.delete(id)
  }

  /**
   * Cleanup expired pending requests.
   */
  cleanup(): void {
    const now = Date.now()
    const ttlMs = this.ttl * 1000
    for (const [id, pending] of this.pending) {
      if (now - pending.createdAt > ttlMs) {
        pending.reject(new Error('Pending request expired'))
        this.pending.delete(id)
      }
    }
  }

  /**
   * Get count of pending requests (useful for tests/monitoring).
   */
  get size(): number {
    return this.pending.size
  }
}

function generateCode(length: number): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
  const bytes = randomBytes(length)
  let code = ''
  for (let i = 0; i < length; i++) {
    code += chars[bytes[i] % chars.length]
  }
  return code
}
