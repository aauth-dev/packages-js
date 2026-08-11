import { planAccessMode } from '@aauth/protocol'
import type { AccessModePlan, AgentSetup, KnownAccessMode } from '@aauth/protocol'

/**
 * R3 -02 operation access annotations, read out of a fetched OpenAPI document.
 *
 * An agent cannot read a resource's R3 document, so R3 by itself tells it nothing
 * about what any one operation needs. The vocabulary — here the OpenAPI spec, which
 * the agent has to parse to make the call at all — carries that per operation:
 * `x-aauth-access-mode` and `x-aauth-budget` on the Operation Object
 * (AAuth R3 §Operation Access Annotations, §Vocabulary Encodings).
 *
 * These are ADVISORY. A resource MAY return any `AAuth-Requirement` at runtime
 * regardless of what it published, so nothing here is ever enforced: fetch reads
 * the annotations, prints them, and still makes whatever call it was asked to make.
 */

/** The OpenAPI extension keys R3 §Vocabulary Encodings defines for the Operation Object. */
const ACCESS_MODE_KEY = 'x-aauth-access-mode'
const BUDGET_KEY = 'x-aauth-budget'

/** HTTP methods that make a Path Item Object's value an Operation Object. */
const HTTP_METHODS = ['get', 'put', 'post', 'delete', 'options', 'head', 'patch', 'trace']

export interface OperationAnnotation {
  /** OpenAPI `operationId`; falls back to `METHOD path` when the spec omits it. */
  operationId: string
  method: string
  path: string
  /** `x-aauth-access-mode` exactly as published (undefined when absent). */
  declared?: string
  /** `x-aauth-budget === true`. */
  budget: boolean
  /** What the agent should plan for, after the R3 budget rules below. */
  plan: AccessModePlan
  /** Why `plan` differs from `declared`, when it does. */
  note?: string
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

/**
 * True when `doc` looks like an OpenAPI (or Swagger 2.0) description — a version
 * string plus a `paths` or `webhooks` object. Cheap and conservative: fetch only
 * annotates a body it is confident about, and prints nothing otherwise.
 */
export function isOpenApiDocument(doc: unknown): doc is Record<string, unknown> {
  if (!isRecord(doc)) return false
  const versioned = typeof doc.openapi === 'string' || typeof doc.swagger === 'string'
  return versioned && (isRecord(doc.paths) || isRecord(doc.webhooks))
}

/**
 * Resolve the access mode an agent should plan for, applying R3 §Budget Annotation:
 *
 *  - `session-token` MUST NOT appear on an operation (a resource that manages its own
 *    authorization does so for the whole resource) — treat it as no annotation.
 *  - a budget annotation with no access mode implies `auth-token` (a budget rides in
 *    the auth token's `budget` claim).
 *  - a resource MUST NOT combine `x-aauth-budget: true` with `agent-token` or
 *    `person-token`; an agent that meets that combination MUST treat it as `auth-token`.
 *
 * Anything left unrecognized is handed to `planAccessMode`, which reports it as
 * `undeclared` — `access_mode` is an IANA registry, so an unknown value means
 * "call the resource and read the `AAuth-Requirement` it returns", never an error.
 */
function resolveMode(declared: string | undefined, budget: boolean): { mode?: string; note?: string } {
  let mode = declared
  let note: string | undefined

  if (mode === 'session-token') {
    mode = undefined
    note = '`session-token` is not valid on an operation (R3 §Access Mode Annotation) — ignored'
  }

  if (budget) {
    if (mode === undefined) {
      mode = 'auth-token'
      note = note ?? 'budget implies `auth-token`; a budget rides in the auth token'
    } else if (mode === 'agent-token' || mode === 'person-token') {
      note = `budget with \`${mode}\` is invalid; R3 requires \`auth-token\``
      mode = 'auth-token'
    }
  }

  return note === undefined ? { mode } : { mode, note }
}

/**
 * Walk an OpenAPI document's Operation Objects and return the annotated ones,
 * each planned against this agent's setup. Operations with neither annotation are
 * omitted: annotations are sparse, and an unannotated operation simply takes the
 * resource's own `access_mode`.
 */
export function readOperationAnnotations(doc: unknown, setup: AgentSetup): OperationAnnotation[] {
  if (!isOpenApiDocument(doc)) return []
  const out: OperationAnnotation[] = []

  for (const container of [doc.paths, doc.webhooks]) {
    if (!isRecord(container)) continue
    for (const [path, pathItem] of Object.entries(container)) {
      if (!isRecord(pathItem)) continue
      for (const method of HTTP_METHODS) {
        const operation = pathItem[method]
        if (!isRecord(operation)) continue

        const declaredRaw = operation[ACCESS_MODE_KEY]
        const declared = typeof declaredRaw === 'string' ? declaredRaw : undefined
        const budget = operation[BUDGET_KEY] === true
        if (declared === undefined && !budget) continue

        const { mode, note } = resolveMode(declared, budget)
        out.push({
          operationId: typeof operation.operationId === 'string'
            ? operation.operationId
            : `${method.toUpperCase()} ${path}`,
          method: method.toUpperCase(),
          path,
          ...(declared !== undefined ? { declared } : {}),
          budget,
          plan: planAccessMode(mode, setup),
          ...(note !== undefined ? { note } : {}),
        })
      }
    }
  }

  return out
}

/** The JSON form carried on the `operation_annotations` event (snake_case for spec fields). */
export function annotationsAsJson(annotations: OperationAnnotation[]): Array<Record<string, unknown>> {
  return annotations.map((a) => ({
    operationId: a.operationId,
    method: a.method,
    path: a.path,
    ...(a.declared !== undefined ? { access_mode: a.declared } : {}),
    budget: a.budget,
    plan: a.plan.kind,
    ...(a.plan.kind !== 'undeclared' ? { planned_access_mode: a.plan.mode } : {}),
    ...(a.plan.kind === 'unsatisfiable' ? { reason: a.plan.reason } : {}),
    ...(a.note !== undefined ? { note: a.note } : {}),
  }))
}

/** Render order, and what each mode costs the agent. */
const GROUPS: Array<{ mode: KnownAccessMode | 'undeclared'; label: string }> = [
  { mode: 'agent-token', label: 'your agent token alone — no person involved' },
  { mode: 'person-token', label: 'a person token from your person server' },
  { mode: 'session-token', label: 'a session token the resource issues (resource-managed)' },
  { mode: 'auth-token', label: 'an auth token — costs one authorization round trip' },
  { mode: 'per-call', label: 'authorized per invocation — will stop and wait for a person' },
  { mode: 'undeclared', label: 'not a recognized access mode — call it and read the AAuth-Requirement it returns' },
]

function groupOf(a: OperationAnnotation): KnownAccessMode | 'undeclared' {
  return a.plan.kind === 'undeclared' ? 'undeclared' : a.plan.mode
}

/**
 * The human view, for stderr. Grouped by the credential each operation needs, in
 * increasing order of what it costs the agent, so a reader can see at a glance
 * which operations are free, which cost a round trip, and which will block on a
 * person. Returns '' when there is nothing annotated.
 */
export function renderOperationAnnotations(annotations: OperationAnnotation[]): string {
  if (!annotations.length) return ''
  const width = Math.max(...annotations.map((a) => a.operationId.length))
  const lines = [
    'Operation access annotations (advisory — the resource may return any AAuth-Requirement at runtime):',
  ]

  for (const { mode, label } of GROUPS) {
    const group = annotations.filter((a) => groupOf(a) === mode)
    if (!group.length) continue
    lines.push('')
    lines.push(`  ${mode} — ${label}`)
    // planAccessMode reports the same reason for every operation in a group (it is a
    // property of the agent's setup, not of the operation), so state it once.
    const blocked = group.find((a) => a.plan.kind === 'unsatisfiable')
    if (blocked && blocked.plan.kind === 'unsatisfiable') {
      lines.push(`    not satisfiable with your setup: ${blocked.plan.reason}`)
    }
    for (const a of group) {
      const marks = [a.budget ? '[budget]' : '', a.note ? `— ${a.note}` : ''].filter(Boolean).join(' ')
      lines.push(`    ${a.operationId.padEnd(width)}  ${a.method} ${a.path}${marks ? `  ${marks}` : ''}`)
    }
  }

  return lines.join('\n')
}
