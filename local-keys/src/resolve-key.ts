import { calculateJwkThumbprint } from 'jose'
import type { JWK } from 'jose'
import { getAgentConfig } from './config.js'
import { discoverBackends, getBackend } from './backends/index.js'
import type { ResolvedKey, KeyBackend } from './types.js'

/**
 * Resolve a signing key for an agent URL.
 *
 * 1. Fetch {agentUrl}/.well-known/aauth-agent.json → jwks_uri → JWKS
 * 2. Discover all local keys (hardware + software)
 * 3. Match local thumbprints against JWKS, prefer hardware
 * 4. Fall back to config-registered keys
 * 5. Fall back to OS keychain (backward compat)
 * 6. Fall back to any available hardware key (bootstrap)
 *
 * Each step tolerates failure and falls through to the next.
 */
export async function resolveKey(agentUrl: string): Promise<ResolvedKey> {
  // Step 1: Try to fetch the published JWKS
  const jwksKeys = await fetchAgentJwks(agentUrl)

  // Step 2: Discover all local keys
  const localKeys = await discoverLocalKeys()

  // Step 3: Match against JWKS — prefer hardware
  if (jwksKeys.length > 0 && localKeys.length > 0) {
    const match = await matchJwksToLocal(jwksKeys, localKeys)
    if (match) return match
  }

  // Step 4: Fall back to config
  const agentConfig = getAgentConfig(agentUrl)
  if (agentConfig && Object.keys(agentConfig.keys).length > 0) {
    const configMatch = await resolveFromConfig(agentConfig.keys, localKeys)
    if (configMatch) return configMatch
  }

  // Step 5: Fall back to any local hardware key (bootstrap — just generated, not yet published)
  const hardwareKeys = localKeys.filter((k) => k.backend !== 'software')
  if (hardwareKeys.length > 0) {
    return hardwareKeys[0]
  }

  // Step 6: Fall back to any local software key
  if (localKeys.length > 0) {
    return localKeys[0]
  }

  throw new Error(
    `No signing key found for ${agentUrl}. ` +
    `Run 'npx @aauth/local-keys generate' to create one.`,
  )
}

// === JWKS Fetching ===

async function fetchAgentJwks(agentUrl: string): Promise<JWK[]> {
  try {
    // Fetch aauth-agent.json to find jwks_uri
    const metaUrl = `${agentUrl.replace(/\/$/, '')}/.well-known/aauth-agent.json`
    const metaResp = await fetch(metaUrl, { signal: AbortSignal.timeout(5000) })
    if (!metaResp.ok) return []

    const meta = (await metaResp.json()) as { jwks_uri?: string }
    if (!meta.jwks_uri) return []

    // Fetch the JWKS
    const jwksResp = await fetch(meta.jwks_uri, { signal: AbortSignal.timeout(5000) })
    if (!jwksResp.ok) return []

    const jwks = (await jwksResp.json()) as { keys?: JWK[] }
    return jwks.keys || []
  } catch {
    // Network error, timeout, parse error — all fine, fall through
    return []
  }
}

// === Local Key Discovery ===

interface LocalKey {
  backend: KeyBackend
  keyId: string
  kid: string
  algorithm: 'EdDSA' | 'ES256' | 'RS256'
  publicJwk: JWK
  thumbprint: string
}

async function discoverLocalKeys(): Promise<LocalKey[]> {
  const keys: LocalKey[] = []
  const backends = discoverBackends()

  for (const info of backends) {
    const driver = getBackend(info.backend)
    try {
      const backendKeys = await driver.listKeys()
      for (const k of backendKeys) {
        if (!k.publicJwk || !k.publicJwk.kty) continue
        try {
          const thumbprint = await calculateJwkThumbprint(k.publicJwk, 'sha256')
          keys.push({
            backend: k.backend,
            keyId: k.keyId,
            kid: k.publicJwk.kid || k.keyId,
            algorithm: k.algorithm,
            publicJwk: k.publicJwk,
            thumbprint,
          })
        } catch {
          // Skip keys we can't compute thumbprints for
        }
      }
    } catch {
      // Backend unavailable, skip
    }
  }

  return keys
}

// === Matching ===

/**
 * Match JWKS keys against local keys. Prefers hardware over software.
 */
async function matchJwksToLocal(
  jwksKeys: JWK[],
  localKeys: LocalKey[],
): Promise<ResolvedKey | null> {
  let softwareMatch: ResolvedKey | null = null

  for (const jwk of jwksKeys) {
    if (!jwk.kty) continue
    try {
      const remoteThumbprint = await calculateJwkThumbprint(jwk, 'sha256')
      const match = localKeys.find((k) => k.thumbprint === remoteThumbprint)
      if (match) {
        const resolved: ResolvedKey = {
          backend: match.backend,
          keyId: match.keyId,
          kid: jwk.kid || match.kid,
          algorithm: match.algorithm,
          publicJwk: match.publicJwk,
        }
        // Hardware key — return immediately
        if (match.backend !== 'software') {
          return resolved
        }
        // Software key — remember it but keep looking for hardware
        if (!softwareMatch) {
          softwareMatch = resolved
        }
      }
    } catch {
      // Skip malformed JWKs
    }
  }

  return softwareMatch
}

/**
 * Try to resolve a key from config entries against discovered local keys.
 * Prefers hardware over software. Skips keys whose backend is unavailable
 * (e.g. YubiKey unplugged).
 */
async function resolveFromConfig(
  configKeys: Record<string, { backend: KeyBackend; keyId: string; algorithm: 'EdDSA' | 'ES256' | 'RS256' }>,
  localKeys: LocalKey[],
): Promise<ResolvedKey | null> {
  const backends = discoverBackends()
  let softwareMatch: ResolvedKey | null = null
  let lazyHardwareMatch: ResolvedKey | null = null

  for (const [kid, meta] of Object.entries(configKeys)) {
    // Is this backend even present right now?
    const backendAvailable = backends.some((b) => b.backend === meta.backend)
    if (!backendAvailable) continue

    // Match against discovered local keys (fast path)
    const local = localKeys.find(
      (k) => k.backend === meta.backend && k.keyId === meta.keyId,
    )
    if (local) {
      const resolved: ResolvedKey = { ...local, kid }
      if (local.backend !== 'software') return resolved
      if (!softwareMatch) softwareMatch = resolved
      continue
    }

    // Key not in discovery but backend is available (e.g. SE with lazy public key)
    // Verify the key actually exists by trying to load it
    if (meta.backend !== 'software' && !lazyHardwareMatch) {
      try {
        const driver = getBackend(meta.backend)
        const pubJwk = await driver.getPublicKey(meta.keyId)
        if (pubJwk && pubJwk.kty) {
          lazyHardwareMatch = {
            backend: meta.backend,
            keyId: meta.keyId,
            kid,
            algorithm: meta.algorithm,
            publicJwk: pubJwk,
          }
        }
      } catch {
        // Key doesn't exist on this backend — skip
      }
    }
  }

  return lazyHardwareMatch || softwareMatch
}

/**
 * Check which JWKS keys are available locally vs potentially stale.
 */
export async function checkKeyAvailability(jwksKeys: JWK[]): Promise<{
  available: Array<{ jwk: JWK; backend: KeyBackend; keyId: string }>
  unavailable: JWK[]
}> {
  const localKeys = await discoverLocalKeys()
  const available: Array<{ jwk: JWK; backend: KeyBackend; keyId: string }> = []
  const unavailable: JWK[] = []

  for (const jwk of jwksKeys) {
    if (!jwk.kty) continue
    try {
      const thumbprint = await calculateJwkThumbprint(jwk, 'sha256')
      const match = localKeys.find((k) => k.thumbprint === thumbprint)
      if (match) {
        available.push({ jwk, backend: match.backend, keyId: match.keyId })
      } else {
        unavailable.push(jwk)
      }
    } catch {
      unavailable.push(jwk)
    }
  }

  return { available, unavailable }
}
