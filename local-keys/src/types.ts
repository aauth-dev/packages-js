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
  /**
   * Permanently remove a key from this keystore.
   * Backends that cannot delete programmatically (e.g. YubiKey PIV today)
   * throw a {@link KeyDeletionUnsupportedError} so callers can report the
   * manual step instead.
   */
  deleteKey?(keyId: string): Promise<void>
}

/**
 * Thrown by a backend's `deleteKey` when the keystore can't remove a key
 * programmatically. Carries a hint with the manual command to run.
 */
export class KeyDeletionUnsupportedError extends Error {
  constructor(public readonly hint: string) {
    super(hint)
    this.name = 'KeyDeletionUnsupportedError'
  }
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

/**
 * Cached person-server metadata (from `{personServerUrl}/.well-known/aauth-person.json`),
 * saved at bootstrap so fetch doesn't re-fetch it on every token exchange.
 */
export interface PersonServerMetadata {
  issuer?: string
  token_endpoint: string
  jwks_uri?: string
  authorization_endpoint?: string
}

export interface AgentConfig {
  /** Agent identifier, e.g. aauth:local@dickhardt.github.io */
  agentId?: string
  personServerUrl?: string
  /** Cached PS metadata so fetch can skip the runtime /.well-known/aauth-person.json fetch */
  personServerMetadata?: PersonServerMetadata
  /** The agent server metadata URL, e.g. https://me.github.io/.well-known/aauth-agent.json */
  agentServerUrl?: string
  /** Cached jwks_uri from the agent server metadata */
  jwksUri?: string
  hosting?: AgentHosting
  keys: Record<string, LocalKeyMeta>  // kid → local metadata
}

export interface AAuthConfig {
  /**
   * agent-provider URL → its config. The on-disk key stays `agents` (the CLI
   * surfaces these as "agent providers" in output/flags, but the stored config
   * format is unchanged).
   */
  agents: Record<string, AgentConfig>
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
  /** Agent identifier for the sub claim, e.g. aauth:local@domain */
  sub: string
  lifetime?: number
  /** Override ps claim without writing to config (used by bootstrap before config is finalized) */
  personServerUrl?: string
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
  /** Full agent identifier (sub claim), e.g. aauth:claude@domain. Overrides local + config. */
  agentId?: string
  /** Local part of agent identifier, e.g. "claude" → aauth:claude@domain. Overrides config. */
  local?: string
  tokenLifetime?: number
}
