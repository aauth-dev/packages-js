/**
 * `access_mode` planning (resource metadata, §Resource Metadata).
 *
 * `access_mode` is advisory. The runtime `AAuth-Requirement` is authoritative:
 * a resource MAY return any requirement regardless of what it declared, and MAY
 * apply different modes to different endpoints. So an unrecognized value is
 * never an error — the agent proceeds as it would with no declaration at all.
 */

/** The `access_mode` values this library recognizes. */
export type KnownAccessMode =
  | 'agent-token'
  | 'person-token'
  | 'session-token'
  | 'auth-token'
  | 'per-call'

const KNOWN_ACCESS_MODES: readonly KnownAccessMode[] = [
  'agent-token',
  'person-token',
  'session-token',
  'auth-token',
  'per-call',
]

/** What the agent can do, for deciding whether a declared mode is reachable. */
export interface AgentSetup {
  /** false when the agent token carries no `ps` claim. */
  hasPersonServer: boolean
}

export type AccessModePlan =
  /**
   * Absent, or a value not in KnownAccessMode. Call the resource and read the
   * `AAuth-Requirement` it returns. NEVER an error — the value space is a
   * registry, and stopping on an unknown value breaks on every new entry.
   */
  | { kind: 'undeclared' }
  | { kind: 'satisfiable'; mode: KnownAccessMode }
  /**
   * Recognized, and this agent cannot complete it. Skip the resource, state
   * why. With no person server that is `person-token`, `auth-token` and
   * `per-call` — every mode whose flow reaches a PS.
   */
  | { kind: 'unsatisfiable'; mode: KnownAccessMode; reason: string }

/** Is `value` an `access_mode` this library recognizes? */
export function isKnownAccessMode(value: string): value is KnownAccessMode {
  return (KNOWN_ACCESS_MODES as readonly string[]).includes(value)
}

/**
 * The three modes an agent with no person server cannot complete, and what to
 * tell the caller. `agent-token` and `session-token` are absent: neither has a
 * PS anywhere in its flow.
 */
const NO_PERSON_SERVER_REASON: Partial<Record<KnownAccessMode, string>> = {
  'person-token':
    'Resource declares access_mode="person-token", so the agent must sign with a person ' +
    'token obtained from its person server. This agent token carries no "ps" claim, so there ' +
    'is no person server to obtain one from.',
  'auth-token':
    'Resource declares access_mode="auth-token", so the agent must exchange the resource ' +
    'token for an auth token at its person server. This agent token carries no "ps" claim, ' +
    'so it cannot complete the flow — and the initial call would need a person token it ' +
    'also cannot obtain.',
  'per-call':
    'Resource declares access_mode="per-call", which terminates in an auth token: the agent ' +
    'takes the resource token to its person server, and the grant arrives as the ' +
    '"r3_per_call" auth token claim. This agent token carries no "ps" claim, so there is no ' +
    'person server to grant it.',
}

/**
 * Decide what a declared `access_mode` means for this agent.
 *
 * Three outcomes, and only three:
 *  - absent or unrecognized -> `undeclared`, call the resource anyway
 *  - recognized and reachable -> `satisfiable`
 *  - recognized and unreachable -> `unsatisfiable`, with a reason to show
 */
export function planAccessMode(declared: string | undefined, setup: AgentSetup): AccessModePlan {
  if (declared === undefined || declared === null) {
    return { kind: 'undeclared' }
  }

  const mode = declared.trim()
  if (!isKnownAccessMode(mode)) {
    return { kind: 'undeclared' }
  }

  if (!setup.hasPersonServer) {
    const reason = NO_PERSON_SERVER_REASON[mode]
    if (reason !== undefined) {
      return { kind: 'unsatisfiable', mode, reason }
    }
  }

  return { kind: 'satisfiable', mode }
}
