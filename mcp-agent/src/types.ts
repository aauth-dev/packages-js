export interface SignatureKeyJwt {
  type: 'jwt'
  jwt: string
}

export interface SignatureKeyJktJwt {
  type: 'jkt-jwt'
  jwt: string
}

export interface SignatureKeyHwk {
  type: 'hwk'
}

export interface KeyMaterial {
  signingKey: JsonWebKey
  signatureKey: SignatureKeyJwt | SignatureKeyJktJwt | SignatureKeyHwk
}

export type GetKeyMaterial = () => Promise<KeyMaterial>

export type FetchLike = (url: string | URL, init?: RequestInit) => Promise<Response>

export interface AAuthEvent {
  step: string
  phase: 'start' | 'done' | 'info'
  /**
   * Real request headers from the on-the-wire signed request, captured via
   * @hellocoop/httpsig's returnSent option. Added to `:done` events for
   * signed exchanges so log renderers can show actual Signature,
   * Signature-Input, Signature-Key, Content-Type, etc.
   */
  request_headers?: Record<string, string>
  /** Raw request body (POST/PUT bodies). String form for readability. */
  request_body?: string
  [key: string]: unknown
}

export type OnEvent = (event: AAuthEvent) => void

/**
 * The signed request that was sent. Mirrors @hellocoop/httpsig's SentRequest
 * but uses a plain Record for headers so it survives JSON serialisation.
 */
export interface CapturedSent {
  method: string
  url: string
  headers: Record<string, string>
  body?: string
}
