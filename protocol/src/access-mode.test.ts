import { describe, it, expect } from 'vitest'
import {
  planAccessMode,
  isKnownAccessMode,
  type AgentSetup,
  type KnownAccessMode,
} from './access-mode.js'

const withPS: AgentSetup = { hasPersonServer: true }
const noPS: AgentSetup = { hasPersonServer: false }

describe('planAccessMode — undeclared', () => {
  it('is undeclared when access_mode is absent', () => {
    expect(planAccessMode(undefined, withPS)).toEqual({ kind: 'undeclared' })
    expect(planAccessMode(undefined, noPS)).toEqual({ kind: 'undeclared' })
  })

  // The value space is a registry (AAuth Access Mode Value Registry). An agent
  // that errors on an unknown value breaks every time a new value is registered.
  it('is undeclared — never an error — for a value registered after this release', () => {
    expect(planAccessMode('quantum-attestation', withPS)).toEqual({ kind: 'undeclared' })
    expect(planAccessMode('quantum-attestation', noPS)).toEqual({ kind: 'undeclared' })
  })

  it('is undeclared for the -10 spelling of session-token', () => {
    expect(planAccessMode('aauth-access-token', withPS)).toEqual({ kind: 'undeclared' })
  })

  it('is undeclared for an empty or whitespace value', () => {
    expect(planAccessMode('', withPS)).toEqual({ kind: 'undeclared' })
    expect(planAccessMode('   ', withPS)).toEqual({ kind: 'undeclared' })
  })

  it('is case sensitive — a miscased value is simply unrecognized', () => {
    expect(planAccessMode('Auth-Token', noPS)).toEqual({ kind: 'undeclared' })
  })

  it('never throws, whatever it is handed', () => {
    for (const v of ['', '   ', '!!', 'agent token', 'per-call ', undefined]) {
      expect(() => planAccessMode(v, noPS)).not.toThrow()
    }
  })
})

// The whole 5 x 2 matrix, per the contract's decision table. Without a person
// server exactly three of the five modes are unsatisfiable: every mode whose
// flow reaches a PS. agent-token is identity only; session-token is
// resource-managed, and the resource issues its own credential.
const MATRIX: Array<{ mode: KnownAccessMode; withPS: 'satisfiable'; noPS: 'satisfiable' | 'unsatisfiable' }> = [
  { mode: 'agent-token', withPS: 'satisfiable', noPS: 'satisfiable' },
  { mode: 'session-token', withPS: 'satisfiable', noPS: 'satisfiable' },
  { mode: 'person-token', withPS: 'satisfiable', noPS: 'unsatisfiable' },
  { mode: 'auth-token', withPS: 'satisfiable', noPS: 'unsatisfiable' },
  { mode: 'per-call', withPS: 'satisfiable', noPS: 'unsatisfiable' },
]

describe('planAccessMode — every known mode against both setups', () => {
  it('covers all five KnownAccessMode values', () => {
    expect(MATRIX.map((r) => r.mode).sort()).toEqual(
      ['agent-token', 'auth-token', 'per-call', 'person-token', 'session-token'],
    )
  })

  it.each(MATRIX)('$mode with a person server is $withPS', ({ mode }) => {
    expect(planAccessMode(mode, withPS)).toEqual({ kind: 'satisfiable', mode })
  })

  it.each(MATRIX)('$mode with no person server is $noPS', ({ mode, noPS: expected }) => {
    const plan = planAccessMode(mode, noPS)
    expect(plan.kind).toBe(expected)
    expect(plan).toMatchObject({ mode })
  })

  it('trims surrounding whitespace before matching', () => {
    expect(planAccessMode('  auth-token  ', withPS)).toEqual({
      kind: 'satisfiable',
      mode: 'auth-token',
    })
  })
})

describe('planAccessMode — unsatisfiable', () => {
  const unsatisfiable = MATRIX.filter((r) => r.noPS === 'unsatisfiable')

  it.each(unsatisfiable)('$mode names itself and the missing ps claim', ({ mode }) => {
    const plan = planAccessMode(mode, noPS)
    if (plan.kind !== 'unsatisfiable') throw new Error('expected unsatisfiable')
    expect(plan.mode).toBe(mode)
    expect(plan.reason).toContain(mode)
    expect(plan.reason).toContain('"ps"')
    expect(plan.reason).toMatch(/person server/)
  })

  it.each(unsatisfiable)('$mode reason is human readable, not a code', ({ mode }) => {
    const plan = planAccessMode(mode, noPS)
    if (plan.kind !== 'unsatisfiable') throw new Error('expected unsatisfiable')
    expect(plan.reason.length).toBeGreaterThan(40)
    expect(plan.reason).not.toMatch(/^[A-Z_]+$/)
  })

  // Spec: "a PS-less agent (no `ps` claim in its agent token) cannot complete
  // the auth-token flow." per-call terminates in an auth token too — the grant
  // arrives as the r3_per_call auth token claim — so it fails for the same reason.
  it('per-call explains that it terminates in an auth token', () => {
    const plan = planAccessMode('per-call', noPS)
    if (plan.kind !== 'unsatisfiable') throw new Error('expected unsatisfiable')
    expect(plan.reason).toMatch(/auth token/)
    expect(plan.reason).toContain('r3_per_call')
  })

  it('gives each mode its own reason', () => {
    const reasons = unsatisfiable.map(({ mode }) => {
      const plan = planAccessMode(mode, noPS)
      if (plan.kind !== 'unsatisfiable') throw new Error('expected unsatisfiable')
      return plan.reason
    })
    expect(new Set(reasons).size).toBe(reasons.length)
  })
})

describe('isKnownAccessMode', () => {
  it('accepts the five modes and nothing else', () => {
    for (const v of ['agent-token', 'person-token', 'session-token', 'auth-token', 'per-call']) {
      expect(isKnownAccessMode(v)).toBe(true)
    }
    for (const v of ['approval', 'interaction', 'aauth-access-token', '', 'Per-Call']) {
      expect(isKnownAccessMode(v)).toBe(false)
    }
  })
})
