import { describe, it, expect } from 'vitest'
import {
  isOpenApiDocument,
  readOperationAnnotations,
  annotationsAsJson,
  renderOperationAnnotations,
} from './annotations.js'

const withPs = { hasPersonServer: true }
const noPs = { hasPersonServer: false }

/** An OpenAPI 3.1 doc whose operations carry the R3 -02 access annotations. */
function doc(operations: Record<string, Record<string, unknown>>): unknown {
  const paths: Record<string, unknown> = {}
  for (const [operationId, op] of Object.entries(operations)) {
    paths[`/${operationId}`] = { post: { operationId, ...op } }
  }
  return { openapi: '3.1.0', info: { title: 't', version: '1' }, paths }
}

describe('isOpenApiDocument', () => {
  it('accepts OpenAPI 3.x and Swagger 2.0 documents', () => {
    expect(isOpenApiDocument({ openapi: '3.1.0', paths: {} })).toBe(true)
    expect(isOpenApiDocument({ swagger: '2.0', paths: {} })).toBe(true)
    expect(isOpenApiDocument({ openapi: '3.1.0', webhooks: {} })).toBe(true)
  })

  it('rejects anything else — an ordinary body is never annotated', () => {
    expect(isOpenApiDocument({ data: 'ok' })).toBe(false)
    expect(isOpenApiDocument({ paths: {} })).toBe(false) // no version
    expect(isOpenApiDocument({ openapi: '3.1.0' })).toBe(false) // no operations
    expect(isOpenApiDocument('a string')).toBe(false)
    expect(isOpenApiDocument(null)).toBe(false)
    expect(isOpenApiDocument([{ openapi: '3.1.0', paths: {} }])).toBe(false)
  })
})

describe('readOperationAnnotations', () => {
  it('reads x-aauth-access-mode and x-aauth-budget off the Operation Object', () => {
    const [a] = readOperationAnnotations(
      doc({ purchaseDataset: { 'x-aauth-access-mode': 'per-call', 'x-aauth-budget': true } }),
      withPs,
    )
    expect(a).toMatchObject({
      operationId: 'purchaseDataset',
      method: 'POST',
      path: '/purchaseDataset',
      declared: 'per-call',
      budget: true,
      plan: { kind: 'satisfiable', mode: 'per-call' },
    })
  })

  it('carries every registered access mode through', () => {
    const anns = readOperationAnnotations(
      doc({
        a: { 'x-aauth-access-mode': 'agent-token' },
        b: { 'x-aauth-access-mode': 'person-token' },
        c: { 'x-aauth-access-mode': 'auth-token' },
        d: { 'x-aauth-access-mode': 'per-call' },
      }),
      withPs,
    )
    expect(anns.map((x) => x.plan)).toEqual([
      { kind: 'satisfiable', mode: 'agent-token' },
      { kind: 'satisfiable', mode: 'person-token' },
      { kind: 'satisfiable', mode: 'auth-token' },
      { kind: 'satisfiable', mode: 'per-call' },
    ])
  })

  // access_mode is an IANA registry, not a closed list: an unrecognized value is
  // not an error and not a declaration — call the resource and read what it returns.
  it('treats an unrecognized access mode as no declaration at all', () => {
    const [a] = readOperationAnnotations(doc({ x: { 'x-aauth-access-mode': 'quantum-token' } }), withPs)
    expect(a.declared).toBe('quantum-token')
    expect(a.plan).toEqual({ kind: 'undeclared' })
  })

  // R3 §Access Mode Annotation: a resource that manages its own authorization does
  // so for the whole resource, so session-token cannot appear on an operation.
  it('ignores session-token on an operation and says why', () => {
    const [a] = readOperationAnnotations(doc({ x: { 'x-aauth-access-mode': 'session-token' } }), withPs)
    expect(a.plan).toEqual({ kind: 'undeclared' })
    expect(a.note).toMatch(/not valid on an operation/)
  })

  // R3 §Budget Annotation: a budget rides in the auth token, so a budget annotation
  // implies auth-token, and MUST NOT be combined with agent-token or person-token.
  it('a budget annotation alone implies auth-token', () => {
    const [a] = readOperationAnnotations(doc({ x: { 'x-aauth-budget': true } }), withPs)
    expect(a.declared).toBeUndefined()
    expect(a.budget).toBe(true)
    expect(a.plan).toEqual({ kind: 'satisfiable', mode: 'auth-token' })
    expect(a.note).toMatch(/budget implies `auth-token`/)
  })

  it('upgrades a budgeted agent-token/person-token operation to auth-token', () => {
    for (const declared of ['agent-token', 'person-token']) {
      const [a] = readOperationAnnotations(
        doc({ x: { 'x-aauth-access-mode': declared, 'x-aauth-budget': true } }),
        withPs,
      )
      expect(a.declared).toBe(declared)
      expect(a.plan).toEqual({ kind: 'satisfiable', mode: 'auth-token' })
      expect(a.note).toMatch(/R3 requires `auth-token`/)
    }
  })

  // Annotations are sparse — an unannotated operation takes the resource's own
  // access_mode and has nothing to surface.
  it('omits operations with neither annotation', () => {
    expect(readOperationAnnotations(doc({ plain: { summary: 'nothing to see' } }), withPs)).toEqual([])
  })

  it('reports what this agent cannot complete, without erroring', () => {
    const anns = readOperationAnnotations(
      doc({
        free: { 'x-aauth-access-mode': 'agent-token' },
        gated: { 'x-aauth-access-mode': 'auth-token' },
      }),
      noPs,
    )
    expect(anns[0].plan).toEqual({ kind: 'satisfiable', mode: 'agent-token' })
    expect(anns[1]).toMatchObject({ plan: { kind: 'unsatisfiable', mode: 'auth-token' } })
  })

  it('falls back to METHOD path when the spec omits operationId', () => {
    const [a] = readOperationAnnotations(
      { openapi: '3.1.0', paths: { '/x': { get: { 'x-aauth-access-mode': 'agent-token' } } } },
      withPs,
    )
    expect(a.operationId).toBe('GET /x')
  })

  it('reads 3.1 webhooks as well as paths', () => {
    const anns = readOperationAnnotations(
      { openapi: '3.1.0', webhooks: { onEvent: { post: { operationId: 'onEvent', 'x-aauth-access-mode': 'auth-token' } } } },
      withPs,
    )
    expect(anns.map((a) => a.operationId)).toEqual(['onEvent'])
  })
})

describe('annotationsAsJson', () => {
  it('emits the declared mode, the planned mode, and the blocking reason', () => {
    const json = annotationsAsJson(
      readOperationAnnotations(doc({ gated: { 'x-aauth-access-mode': 'auth-token' } }), noPs),
    )
    expect(json[0]).toMatchObject({
      operationId: 'gated',
      access_mode: 'auth-token',
      budget: false,
      plan: 'unsatisfiable',
      planned_access_mode: 'auth-token',
    })
    expect(typeof json[0].reason).toBe('string')
  })
})

describe('renderOperationAnnotations', () => {
  const annotations = readOperationAnnotations(
    doc({
      getHealth: { 'x-aauth-access-mode': 'agent-token' },
      getMe: { 'x-aauth-access-mode': 'person-token' },
      listDatasets: { 'x-aauth-access-mode': 'auth-token' },
      purchaseDataset: { 'x-aauth-access-mode': 'per-call', 'x-aauth-budget': true },
      experimental: { 'x-aauth-access-mode': 'quantum-token' },
    }),
    withPs,
  )

  it('groups by credential, cheapest first, and marks budgeted operations', () => {
    const text = renderOperationAnnotations(annotations)
    const order = ['agent-token', 'person-token', 'auth-token', 'per-call', 'undeclared']
      .map((m) => text.indexOf(`  ${m} —`))
    expect(order).toEqual([...order].sort((a, b) => a - b))
    expect(order.every((i) => i > -1)).toBe(true)
    expect(text).toMatch(/purchaseDataset.*\[budget\]/)
    expect(text).toMatch(/per-call — .*stop and wait for a person/)
  })

  it('leads with the advisory caveat — the runtime requirement is authoritative', () => {
    expect(renderOperationAnnotations(annotations).split('\n')[0])
      .toMatch(/advisory — the resource may return any AAuth-Requirement at runtime/)
  })

  it('states an unsatisfiable group once, not once per operation', () => {
    const text = renderOperationAnnotations(
      readOperationAnnotations(
        doc({ a: { 'x-aauth-access-mode': 'auth-token' }, b: { 'x-aauth-access-mode': 'auth-token' } }),
        noPs,
      ),
    )
    expect(text.match(/not satisfiable with your setup/g)).toHaveLength(1)
  })

  it('renders nothing when there is nothing annotated', () => {
    expect(renderOperationAnnotations([])).toBe('')
  })
})
