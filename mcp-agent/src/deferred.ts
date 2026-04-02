import { parseAAuthHeader } from './aauth-header.js'
import type { FetchLike } from './types.js'

export interface DeferredOptions {
  signedFetch: FetchLike
  locationUrl: string
  interactionUrl?: string
  interactionCode?: string
  onInteraction?: (url: string, code: string) => void
  onClarification?: (question: string) => Promise<string>
  maxPollDuration?: number // total timeout in seconds, default 300
}

export interface AAuthError {
  error: string
  error_description?: string
  error_uri?: string
}

export interface DeferredResult {
  response: Response
  error?: AAuthError
}

const DEFAULT_MAX_POLL_DURATION = 300
const DEFAULT_PREFER_WAIT = 45

/**
 * Poll a 202 Location URL until a terminal response is received.
 *
 * Terminal: 200, 400, 401, 403, 408, 410, 500
 * Transient: 202 (continue polling), 503 (backoff then retry)
 *
 * On 202 with clarification body: calls onClarification, POSTs response back.
 * On 202 with AAuth-Requirement: requirement=interaction header: calls onInteraction.
 */
export async function pollDeferred(options: DeferredOptions): Promise<DeferredResult> {
  const {
    signedFetch,
    locationUrl,
    interactionUrl,
    interactionCode,
    onInteraction,
    onClarification,
    maxPollDuration = DEFAULT_MAX_POLL_DURATION,
  } = options

  const deadline = Date.now() + maxPollDuration * 1000

  // Notify about initial interaction url and code if present
  if (interactionUrl && interactionCode && onInteraction) {
    onInteraction(interactionUrl, interactionCode)
  }

  let backoffMs = 1000
  let pollUrl = locationUrl

  while (Date.now() < deadline) {
    const response = await signedFetch(pollUrl, {
      method: 'GET',
      headers: {
        Prefer: `wait=${DEFAULT_PREFER_WAIT}`,
      },
    })

    const status = response.status

    // Terminal responses
    if (status === 200 || status === 400 || status === 401 || status === 403 || status === 408 || status === 410 || status === 500) {
      return { response, error: await parseErrorBody(response) }
    }

    if (status === 202) {
      // Check for clarification in body
      const contentType = response.headers.get('content-type') || ''
      if (contentType.includes('application/json') && onClarification) {
        try {
          const body = await response.json() as Record<string, unknown>
          if (body.clarification) {
            const answer = await onClarification(body.clarification as string)
            // POST clarification response back to the poll URL
            await signedFetch(pollUrl, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ clarification_response: answer }),
            })
          }
        } catch {
          // Malformed JSON — skip clarification, continue polling
        }
      }

      // Check for interaction in AAuth-Requirement header
      const aauthHeader = response.headers.get('aauth-requirement')
      if (aauthHeader && onInteraction) {
        try {
          const challenge = parseAAuthHeader(aauthHeader)
          if (challenge.requirement === 'interaction' && challenge.url && challenge.code) {
            onInteraction(challenge.url, challenge.code)
          }
        } catch {
          // Not a valid AAuth-Requirement header — ignore
        }
      }

      const waitMs = getRetryDelay(response, backoffMs)
      await sleep(waitMs)
      backoffMs = Math.min(backoffMs * 2, 5000)
      continue
    }

    if (status === 503) {
      const waitMs = getRetryDelay(response, backoffMs)
      await sleep(waitMs)
      backoffMs = Math.min(backoffMs * 2, 30000)
      continue
    }

    // Unexpected status — treat as terminal error
    return { response, error: await parseErrorBody(response) }
  }

  throw new Error(`Polling timed out after ${maxPollDuration}s`)
}

function getRetryDelay(response: Response, fallbackMs: number): number {
  const retryAfter = response.headers.get('retry-after')
  if (retryAfter == null) return fallbackMs
  const seconds = parseInt(retryAfter, 10)
  // Retry-After: 0 means retry immediately — yield to event loop
  return isNaN(seconds) ? fallbackMs : seconds * 1000
}

async function parseErrorBody(response: Response): Promise<AAuthError | undefined> {
  if (response.status === 200) return undefined
  const contentType = response.headers.get('content-type') || ''
  if (!contentType.includes('application/json')) return undefined
  try {
    const body = await response.clone().json() as Record<string, unknown>
    if (body.error && typeof body.error === 'string') {
      return {
        error: body.error,
        error_description: typeof body.error_description === 'string' ? body.error_description : undefined,
        error_uri: typeof body.error_uri === 'string' ? body.error_uri : undefined,
      }
    }
  } catch {
    // Malformed JSON — no error to parse
  }
  return undefined
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}
