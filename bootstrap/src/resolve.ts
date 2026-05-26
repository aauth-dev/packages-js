import type { KeyAlgorithm, KeyBackend } from '@aauth/local-keys'

/**
 * Pure resolution helpers shared by the commands. Kept side-effect-free (config
 * lookups are passed in) so every flag-precedence branch is unit-testable.
 */

/** Pick the agent provider: explicit flag wins, else the sole configured one. */
export function resolveProvider(
  explicit: string | undefined,
  providers: string[],
): { url?: string; error?: string } {
  if (explicit) return { url: explicit }
  if (providers.length === 1) return { url: providers[0] }
  if (providers.length === 0) {
    return { error: 'No agent provider configured. Run `create <agent-provider-url>` first.' }
  }
  return { error: 'Multiple agent providers configured. Pass --agent-provider <url>.' }
}

/** Keystore + algorithm with defaults: software→EdDSA, any hardware keystore→ES256. */
export function resolveKeystoreAlgorithm(
  keystoreFlag: string | undefined,
  algorithmFlag: string | undefined,
): { keystore: KeyBackend; algorithm: KeyAlgorithm } {
  const keystore = (keystoreFlag ?? 'software') as KeyBackend
  const algorithm = (algorithmFlag ?? (keystore === 'software' ? 'EdDSA' : 'ES256')) as KeyAlgorithm
  return { keystore, algorithm }
}

/** Agent id precedence: explicit `--agent-id` > `--local`@host > config. */
export function resolveAgentId(opts: {
  explicit?: string
  local?: string
  host: string
  configAgentId?: string
}): string | undefined {
  if (opts.explicit) return opts.explicit
  if (opts.local) return `aauth:${opts.local}@${opts.host}`
  return opts.configAgentId
}

/** Token lifetime in seconds; default 3600, ignoring a non-numeric flag. */
export function resolveLifetime(flag: string | undefined): number {
  if (flag === undefined) return 3600
  const n = parseInt(flag, 10)
  return Number.isFinite(n) ? n : 3600
}
