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
  [key: string]: unknown
}

export type OnEvent = (event: AAuthEvent) => void
