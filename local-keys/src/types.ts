import type { JWK } from 'jose'

// === Key Backend Types ===

export type KeyBackend = 'software' | 'yubikey-piv' | 'secure-enclave'
export type KeyAlgorithm = 'EdDSA' | 'ES256' | 'RS256'

export interface BackendInfo {
  backend: KeyBackend
  description: string
  algorithms: KeyAlgorithm[]
  deviceId: string
}

export interface KeyReference {
  backend: KeyBackend
  algorithm: KeyAlgorithm
  /** For software: kid in keychain. For PIV: slot (e.g. "9e"). For SE: label */
  keyId: string
  publicJwk: JWK
}

export interface KeyBackendDriver {
  discover(): BackendInfo | null
  generateKey(algorithm: KeyAlgorithm): Promise<KeyReference>
  signHash(keyId: string, hash: Buffer): Promise<{ signature: Buffer; algorithm: KeyAlgorithm }>
  listKeys(): Promise<KeyReference[]>
  getPublicKey(keyId: string): Promise<JWK>
  /** Auto-derived device label for this backend */
  getDeviceLabel(): string
}

// === Public JWK with AAuth metadata ===

export interface AAuthJwkMetadata {
  device: string
  created: string
}

export interface AAuthPublicJwk extends JWK {
  aauth?: AAuthJwkMetadata
}

// === Resolved key ready for signing ===

export interface ResolvedKey {
  backend: KeyBackend
  keyId: string
  kid: string
  algorithm: KeyAlgorithm
  publicJwk: JWK
}

// === Config Types ===

export interface LocalKeyMeta {
  backend: KeyBackend
  algorithm: KeyAlgorithm
  /** Backend-specific ID: slot for PIV, label for SE, kid for software */
  keyId: string
  /** Auto-derived device label */
  deviceLabel: string
}

export interface AgentHosting {
  /** Hosting platform: github-pages, cloudflare-pages, netlify, s3, custom */
  platform: string
  /** For github-pages: "username/username.github.io". For s3: bucket name. etc. */
  repo?: string
}

export interface AgentConfig {
  personServerUrl?: string
  hosting?: AgentHosting
  keys: Record<string, LocalKeyMeta>  // kid → local metadata
}

export interface AAuthConfig {
  agents: Record<string, AgentConfig>  // agent URL → agent config
}

// === Keychain Types (existing, for software backend) ===

export interface KeychainData {
  current: string
  keys: Record<string, JWK>
}

export interface GeneratedKeyPair {
  privateJwk: JWK
  publicJwk: JWK
}

// === Agent Token Types ===

export interface SignAgentTokenOptions {
  agentUrl: string
  delegateUrl: string
  lifetime?: number
}

export interface SignatureKeyJwt {
  type: 'jwt'
  jwt: string
}

export interface AgentTokenResult {
  signingKey: JWK
  signatureKey: SignatureKeyJwt
}

export interface CreateAgentTokenOptions {
  /** Agent URL. If omitted, uses first configured agent from ~/.aauth/config.json or keychain. */
  agentUrl?: string
  delegate: string
  tokenLifetime?: number
}
