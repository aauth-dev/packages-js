/**
 * TEMPORARY — delete at integration.
 *
 * `@aauth/protocol` (WP-1) does not exist in this worktree yet, so `vitest.config.ts`
 * aliases the specifier here when the real package is absent. This implements only
 * the `access_mode` slice of the contract that `src/annotations.ts` uses, exactly as
 * the AAuth -11 package contract specifies it. Once `protocol/src/index.ts` exists in
 * the workspace the alias resolves there instead and this file is dead — remove it
 * along with the `protocol` branch in `vitest.config.ts`.
 */

export type KnownAccessMode =
  | 'agent-token' | 'person-token' | 'session-token' | 'auth-token' | 'per-call'

export interface AgentSetup {
  hasPersonServer: boolean
}

export type AccessModePlan =
  | { kind: 'undeclared' }
  | { kind: 'satisfiable'; mode: KnownAccessMode }
  | { kind: 'unsatisfiable'; mode: KnownAccessMode; reason: string }

const KNOWN: readonly KnownAccessMode[] = [
  'agent-token', 'person-token', 'session-token', 'auth-token', 'per-call',
]

/** Modes the agent cannot complete without a person server. */
const NEEDS_PERSON_SERVER: readonly KnownAccessMode[] = ['person-token', 'auth-token', 'per-call']

export function planAccessMode(declared: string | undefined, setup: AgentSetup): AccessModePlan {
  if (declared === undefined) return { kind: 'undeclared' }
  const mode = KNOWN.find((m) => m === declared)
  // `access_mode` is an IANA registry: an unrecognized value is not an error, it is
  // simply no declaration — call the resource and read the AAuth-Requirement.
  if (!mode) return { kind: 'undeclared' }
  if (!setup.hasPersonServer && NEEDS_PERSON_SERVER.includes(mode)) {
    return { kind: 'unsatisfiable', mode, reason: 'this agent has no person server' }
  }
  return { kind: 'satisfiable', mode }
}
