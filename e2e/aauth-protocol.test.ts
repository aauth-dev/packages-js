/**
 * AAuth -11 cross-package end-to-end suite.
 *
 * The only test in the wave that runs the packages together, against a real
 * person server: **mockin** (WP-19), started as a child process. Nothing here
 * stubs the protocol — every JWT is signed by the party the spec says signs it,
 * every request is a real signed HTTP request, and every rejection is the real
 * implementation rejecting it.
 *
 * Packages under test: `@aauth/protocol`, `@aauth/agent`, `@aauth/resource`,
 * and `@hellocoop/httpsig` underneath all three.
 *
 * ---------------------------------------------------------------------------
 * WHAT THIS SUITE CANNOT PROVE — read before assuming coverage
 * ---------------------------------------------------------------------------
 *
 * **`mission_endpoint` is unimplemented by agreement, so every mission
 * constraint except equality is unverifiable.** mockin accepts *any* string as
 * a `mission_s256`: there is no mission document to look up, so §Resource Token
 * Verification step 7 (mission active, current time before `expires_at`) is
 * never evaluated, and no `expires_at` reaches any issuer. That means
 * `clampToMission` and `missionExpiresAt` in `@aauth/resource`, and the "no
 * token carrying `mission_s256` may outlive the mission" rule generally, have
 * **unit coverage only**. The mission tests below prove exactly one thing —
 * that a `mission_s256` survives the person token -> resource token -> auth
 * token path unchanged, and that changing it in either direction is caught.
 *
 * **`upstream_token` / call chaining** is rejected at both mockin endpoints and
 * unimplemented in `@aauth/agent`, so there is nothing to exercise.
 *
 * **`revocation_endpoint` and `mission_control_endpoint`** are not published by
 * mockin.
 *
 * **mockin does not check that a resource token's `iss` equals the `aud` of the
 * person token it names.** Its jti store records the `aud` and never compares
 * it. So "resource A redeems a person token minted for resource B" is not a
 * rejection this suite can assert against mockin.
 *
 * **One person only.** `login_hint`, `prompt` and `domain_hint` are validated
 * and recorded but select nothing, so nothing here tests choosing between
 * people. `tenant` is different — mockin acts on it, so §9's tenant tests
 * drive the real request parameter.
 *
 * **No PS classifies operations into `r3_per_call`.** mockin's `autoGrantR3`
 * grants the whole fetched document every time — there is no classifier, no
 * risk heuristic and no consent screen, so `r3_per_call` exists only when the
 * `r3_grants` mock switch puts it there. §9 uses that switch to stand in for
 * the person's decision and proves the resource and agent halves of the
 * per-call round trip. Whether a PS routes the right operations to `r3_per_call`
 * is untested, and not testable here.
 *
 * **"You may only propose what you were granted in principle" is unverified.**
 * mockin does not remember the class R3 document between exchanges, does not
 * require a proposal's operations to be a subset of what it granted, and
 * connects the two `POST /aauth/token` calls in no way at all. A resource that
 * proposed an operation the person never granted as `r3_per_call` would be
 * approved. §9 has the rest of the R3 limits at its head.
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest'
import {
  requestPersonToken,
  exchangeToken,
  createSignedFetch,
  fetchAuthServerMetadata,
  PersonTokenError,
  TokenExchangeError,
  PS_COMPONENTS_BODY,
} from '@aauth/agent'
import { planAccessMode, TOKEN_TYP, DWK, SIGNING_ALG } from '@aauth/protocol'
import type { KnownAccessMode } from '@aauth/protocol'
import { clearMetadataCache, computeR3Hash, digestParameter } from '@aauth/resource'

import {
  LoopbackRouter,
  startMockin,
  startResource,
  createAgent,
  callResource,
  resourceTokenFrom,
  requirementOf,
  claimsOf,
  headerOf,
  forgeToken,
  serverSignedFetch,
  R3_VOCABULARY,
  PER_CALL_OPERATION,
  PS,
  RESOURCE,
  AGENT,
  AGENT_ID,
} from './helpers.js'
import type { Mockin, TestAgent, TestResource } from './helpers.js'

const router = new LoopbackRouter()
let mockin: Mockin
let resource: TestResource
let agent: TestAgent

/** An agent whose token carries no `ps` claim — it has no person server. */
let psLessAgent: TestAgent

beforeAll(async () => {
  // `@hellocoop/httpsig`'s verify() resolves a `sig=jwks_uri` Signature-Key on
  // the global fetch, with no injection point, so identifier resolution has to
  // be global for the R3 fetch-authorization path to run.
  router.install()
  mockin = await startMockin(router)
  resource = await startResource({ router, personServer: PS })
  // Order matters: every agent publishes at the same identifier, so the last
  // one created owns the route. `psLessAgent` is only ever read as claims, so
  // the real agent must be created after it.
  psLessAgent = await createAgent({ router })
  agent = await createAgent({ router, personServer: PS })
  mockin.trust(AGENT, agent.jwks)
  mockin.trust(RESOURCE, resource.jwks)
  await mockin.reset()
}, 60_000)

afterAll(async () => {
  await resource?.stop()
  await agent?.stop()
  await psLessAgent?.stop()
  await mockin?.stop()
  router.uninstall()
})

beforeEach(async () => {
  // `DELETE /mock` empties the person-token `jti` store, the pending map and
  // the entity cache, and restores every switch to its default. A person token
  // minted by an earlier test is dead after this, which is the isolation we
  // want: each test mints its own.
  await mockin.reset()
  resource.mint = {}
  resource.accept = ['agent', 'person', 'auth']
  resource.accessMode = undefined
  resource.scopeGateReached = false
  resource.resetR3()
})

// ---------------------------------------------------------------------------
// A named walk of the flow, so each test can join it at the step it cares about
// ---------------------------------------------------------------------------

interface Chain {
  personToken: string
  resourceToken: string
  authToken: string
}

async function getPersonToken(
  options: { missionS256?: string; tenant?: string; agentUnder?: TestAgent } = {},
): Promise<string> {
  const who = options.agentUnder ?? agent
  const { personToken } = await requestPersonToken({
    signedFetch: who.psFetch,
    personServerUrl: PS,
    resource: RESOURCE,
    ...(options.missionS256 ? { missionS256: options.missionS256 } : {}),
    ...(options.tenant ? { tenant: options.tenant } : {}),
  })
  return personToken
}

/** Present a person token at the resource and take the resource token out of
 *  the `401 requirement=auth-token` challenge it answers with. */
async function getResourceToken(personToken: string): Promise<string> {
  const challenged = await callResource(agent.presenting(personToken))
  expect(challenged.status).toBe(401)
  return resourceTokenFrom(challenged.headers)
}

async function getAuthToken(resourceToken: string): Promise<string> {
  const { authToken } = await exchangeToken({
    signedFetch: agent.psFetch,
    authServerUrl: PS,
    resourceToken,
  })
  return authToken
}

/**
 * Redeem a resource token and capture the PS's refusal.
 *
 * `exchangeToken` now parses the error body on the direct path too, so the
 * error code and explanation the PS sent are on the thrown
 * `TokenExchangeError` — no wire-reading helper needed.
 */
async function redeemExpectingRefusal(resourceToken: string): Promise<TokenExchangeError> {
  try {
    await getAuthToken(resourceToken)
  } catch (err) {
    if (err instanceof TokenExchangeError) return err
    throw err
  }
  throw new Error('expected the PS to refuse this resource token')
}

async function walkTheChain(
  options: { missionS256?: string; tenant?: string } = {},
): Promise<Chain> {
  const personToken = await getPersonToken(options)
  const resourceToken = await getResourceToken(personToken)
  const authToken = await getAuthToken(resourceToken)
  return { personToken, resourceToken, authToken }
}

// ===========================================================================
// 1. The full chain, end to end
// ===========================================================================

describe('the three-party flow, end to end', () => {
  it('agent token -> person token -> resource token -> auth token -> 200', async () => {
    // The agent has only its own identity. A resource that needs to know who
    // the person is answers `requirement=person-token`.
    const cold = await callResource(agent.resourceFetch)
    expect(cold.status).toBe(401)
    expect(requirementOf(cold.headers)?.requirement).toBe('person-token')

    // --- Person token, from the PS's person_token_endpoint ---
    const personToken = await getPersonToken()
    const person = claimsOf(personToken)
    expect(headerOf(personToken)).toMatchObject({ typ: TOKEN_TYP.person, alg: SIGNING_ALG })
    expect(person).toMatchObject({
      iss: PS,
      dwk: DWK.person,
      aud: RESOURCE,
    })
    expect(typeof person.sub).toBe('string')
    expect(typeof person.jti).toBe('string')
    // `cnf.jwk` is the agent's HTTP-signing key, so possession is provable.
    expect((person.cnf as { jwk: { x: string } }).jwk.x)
      .toBe((agent.signingKey.publicJwk as { x: string }).x)
    // A person token conveys identity, never authorization.
    expect(person.scope).toBeUndefined()
    expect(person.account).toBeUndefined()
    // exp <= 1 hour.
    expect((person.exp as number) - (person.iat as number)).toBeLessThanOrEqual(3600)

    // --- Resource token, minted by @aauth/resource ---
    const resourceToken = await getResourceToken(personToken)
    const rt = claimsOf(resourceToken)
    expect(headerOf(resourceToken)).toMatchObject({ typ: TOKEN_TYP.resource, alg: SIGNING_ALG })
    expect(rt).toMatchObject({
      iss: RESOURCE,
      dwk: DWK.resource,
      aud: PS,
      // ps, sub and person_token_jti are copied from the person token — this is
      // what lets the PS resolve which person token this resource verified.
      ps: person.iss,
      sub: person.sub,
      person_token_jti: person.jti,
      agent_jkt: agent.signingKey.thumbprint,
      scope: 'read',
    })
    // Removed in -11: no delegation claims anywhere in the chain.
    expect(rt.agent).toBeUndefined()
    expect(rt.mission).toBeUndefined()
    expect(rt.approver).toBeUndefined()
    // SHOULD NOT exceed 5 minutes.
    expect((rt.exp as number) - (rt.iat as number)).toBeLessThanOrEqual(300)

    // --- Auth token, from the PS's auth_token_endpoint ---
    const authToken = await getAuthToken(resourceToken)
    const at = claimsOf(authToken)
    expect(headerOf(authToken)).toMatchObject({ typ: TOKEN_TYP.auth, alg: SIGNING_ALG })
    expect(at).toMatchObject({
      iss: PS,
      dwk: DWK.person,
      aud: RESOURCE,
      ps: PS,
      // The PS's directed identifier for this person at this resource is the
      // same value in both tokens. If these ever diverge, a resource cannot
      // recognize a returning person.
      sub: person.sub,
    })
    expect(at.agent).toBeUndefined()
    expect(at.act).toBeUndefined()

    // --- And the call the whole thing existed to make ---
    const answered = await callResource(agent.presenting(authToken))
    expect(answered.status).toBe(200)
    expect(answered.body).toMatchObject({ ok: true, ps: PS, sub: person.sub, scope: 'read' })
  }, 30_000)

  it('clamps the person token to the agent token that asked for it', async () => {
    // §Person Token Structure: exp is not beyond the agent token presented at
    // request time. A short-lived agent token must produce a short-lived
    // person token even though the PS's own ceiling is an hour.
    const shortLived = await createAgent({ router, personServer: PS, lifetimeSeconds: 120 })
    try {
      mockin.trust(AGENT, shortLived.jwks)
      await mockin.reset()
      const personToken = await getPersonToken({ agentUnder: shortLived })
      const person = claimsOf(personToken)
      const agentExp = claimsOf(shortLived.agentToken).exp as number
      expect(person.exp as number).toBeLessThanOrEqual(agentExp)
      expect((person.exp as number) - (person.iat as number)).toBeLessThanOrEqual(120)
    } finally {
      await shortLived.stop()
      mockin.trust(AGENT, agent.jwks)
      router.register(AGENT, agent.origin)
    }
  }, 30_000)

  it('rejects a resource token naming a person token this PS never issued', async () => {
    // The jti store is what makes step 6 of §Resource Token Verification
    // possible at all. Clearing it is the same as a PS restart.
    const personToken = await getPersonToken()
    resource.mint = { forgePersonTokenJti: '00000000-0000-0000-0000-000000000000' }
    const resourceToken = await getResourceToken(personToken)

    const refused = await redeemExpectingRefusal(resourceToken)
    expect(refused.status).toBe(400)
    expect(refused.error).toBe('invalid_resource_token')
    expect(refused.detail).toMatch(/names no person token/)
  }, 30_000)
})

// ===========================================================================
// 2. The 202 deferred path — the common path, not an edge case
// ===========================================================================

describe('deferred person tokens (202)', () => {
  it('auto-approved: requestPersonToken polls the 202 through to a token', async () => {
    // A PS defers on first contact with a resource the person has not used.
    // `person_requirement` defers the *person* token independently of the auth
    // token, which is the only way to exercise this path.
    await mockin.configure({ person_requirement: 'interaction' })

    const interactions: Array<{ url: string; code: string }> = []
    const { personToken } = await requestPersonToken({
      signedFetch: agent.psFetch,
      personServerUrl: PS,
      resource: RESOURCE,
      onInteraction: (url, code) => { interactions.push({ url, code }) },
    })

    // The 202 carried the interaction url and code, and the agent surfaced them.
    expect(interactions).toHaveLength(1)
    expect(interactions[0].url).toBe(`${PS}/aauth/consent`)
    expect(interactions[0].code).toMatch(/^[A-Za-z0-9]{8}$/)

    expect(headerOf(personToken)).toMatchObject({ typ: TOKEN_TYP.person })
    expect(claimsOf(personToken)).toMatchObject({ aud: RESOURCE })
  }, 60_000)

  it('the raw 202: Location, Retry-After and requirement=interaction', async () => {
    // Asserted at the HTTP level, because everything above depends on the shape
    // of this response and `@aauth/agent` hides it.
    await mockin.configure({ person_requirement: 'interaction', auto_approve: false })

    const deferred = await agent.psFetch(`${PS}/aauth/person`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ resource: RESOURCE }),
    })
    expect(deferred.status).toBe(202)
    const location = deferred.headers.get('location')
    expect(location).toMatch(new RegExp(`^${PS}/aauth/pending/`))
    expect(deferred.headers.get('retry-after')).toBe('0')

    const challenge = requirementOf(deferred.headers)
    expect(challenge?.requirement).toBe('interaction')
    expect(challenge?.url).toBe(`${PS}/aauth/consent`)
    const code = challenge!.code!

    // Poll before consent: still pending.
    const pending = await agent.psFetch(location!, { method: 'GET' })
    expect(pending.status).toBe(202)
    expect(pending.headers.get('retry-after')).toBe('5')

    // The person approves in a browser.
    const consented = await mockin.consent(code)
    expect(consented.status).toBe(200)

    // Poll after consent: the token.
    const done = await agent.psFetch(location!, { method: 'GET' })
    expect(done.status).toBe(200)
    const body = await done.json() as { person_token: string; expires_in: number }
    expect(headerOf(body.person_token)).toMatchObject({ typ: TOKEN_TYP.person })
    expect(body.expires_in).toBeGreaterThan(0)
  }, 60_000)

  it('a real interaction: the agent polls 202 until the consent URL is visited', async () => {
    await mockin.configure({ person_requirement: 'interaction', auto_approve: false })

    // Count the polls, so a pass proves `pollDeferred` took its 202 branch and
    // came back — not that consent happened to win a race.
    let polls = 0
    const counting: typeof agent.psFetch = (url, init) => {
      if ((init?.method ?? 'GET') === 'GET' && String(url).includes('/aauth/pending/')) polls++
      return agent.psFetch(url, init)
    }

    let consentedCode: string | undefined
    const { personToken } = await requestPersonToken({
      signedFetch: counting,
      personServerUrl: PS,
      resource: RESOURCE,
      // What an agent with the `interaction` capability does: open the URL.
      // Delayed, so the first poll is guaranteed to find the request still
      // pending — a person takes longer than a round trip.
      onInteraction: (_url, code) => {
        consentedCode = code
        setTimeout(() => { void mockin.consent(code) }, 250)
      },
    })

    expect(consentedCode).toMatch(/^[A-Za-z0-9]{8}$/)
    expect(polls).toBeGreaterThanOrEqual(2)
    expect(claimsOf(personToken)).toMatchObject({ iss: PS, aud: RESOURCE })

    // And the deferred person token is a real one: it carries the whole chain.
    const resourceToken = await getResourceToken(personToken)
    const authToken = await getAuthToken(resourceToken)
    const answered = await callResource(agent.presenting(authToken))
    expect(answered.status).toBe(200)
  }, 60_000)

  it('the auth token endpoint defers the same way', async () => {
    // `requirement` is the auth-token switch; `person_requirement` the person
    // one. Both deferrals can be live at once, and each is polled at its own
    // Location.
    const personToken = await getPersonToken()
    const resourceToken = await getResourceToken(personToken)

    await mockin.configure({ requirement: 'interaction', auto_approve: false })

    let sawInteraction = false
    const { authToken } = await exchangeToken({
      signedFetch: agent.psFetch,
      authServerUrl: PS,
      resourceToken,
      onInteraction: (_url, code) => {
        sawInteraction = true
        void mockin.consent(code)
      },
    })

    expect(sawInteraction).toBe(true)
    expect(headerOf(authToken)).toMatchObject({ typ: TOKEN_TYP.auth })
    expect(claimsOf(authToken)).toMatchObject({ aud: RESOURCE, ps: PS })
  }, 60_000)
})

// ===========================================================================
// 3. Mission stripping, both directions
// ===========================================================================

describe('mission_s256', () => {
  const MISSION = 'q1nS8dQOgYpZ5m6cq0FzB3TnyeF3cO7t_v6i9Xw2r0k'

  it('survives person token -> resource token -> auth token unchanged', async () => {
    // The honest case. Proves the fleet's own minting path — the agent naming
    // the mission once at the person token endpoint, `@aauth/resource` copying
    // it forward — produces something the PS accepts.
    const chain = await walkTheChain({ missionS256: MISSION })

    expect(claimsOf(chain.personToken).mission_s256).toBe(MISSION)
    expect(claimsOf(chain.resourceToken).mission_s256).toBe(MISSION)
    expect(claimsOf(chain.authToken).mission_s256).toBe(MISSION)

    const answered = await callResource(agent.presenting(chain.authToken))
    expect(answered.status).toBe(200)
    expect(answered.body).toMatchObject({ mission_s256: MISSION })

    // NOTE: this asserts equality and nothing more. mockin does not implement
    // `mission_endpoint`, so it accepts any value as a mission hash: it never
    // resolves a mission, never checks the mission is active, and never
    // supplies an `expires_at`. §Resource Token Verification step 7, and every
    // `expires_at` clamp in the fleet, remain unverified end to end.
  }, 30_000)

  it('rejects a resource token that dropped the mission the person token carried', async () => {
    // Stripping is the case that matters: a resource that quietly omits
    // `mission_s256` would otherwise widen a mission-scoped grant into an
    // unscoped one.
    const personToken = await getPersonToken({ missionS256: MISSION })
    expect(claimsOf(personToken).mission_s256).toBe(MISSION)

    resource.mint = { stripMission: true }
    const resourceToken = await getResourceToken(personToken)
    expect(claimsOf(resourceToken).mission_s256).toBeUndefined()

    const refused = await redeemExpectingRefusal(resourceToken)
    expect(refused.status).toBe(400)
    expect(refused.error).toBe('invalid_resource_token')
    // The direction is in the message: the person token had it, the resource
    // token does not.
    expect(refused.detail)
      .toMatch(/mission_s256 mismatch: person token has .+, resource_token has \(none\)/)
  }, 30_000)

  it('rejects a resource token that invented a mission the person token did not carry', async () => {
    const personToken = await getPersonToken()
    expect(claimsOf(personToken).mission_s256).toBeUndefined()

    resource.mint = { inventMission: MISSION }
    const resourceToken = await getResourceToken(personToken)
    expect(claimsOf(resourceToken).mission_s256).toBe(MISSION)

    const refused = await redeemExpectingRefusal(resourceToken)
    expect(refused.status).toBe(400)
    expect(refused.detail)
      .toMatch(/mission_s256 mismatch: person token has \(none\), resource_token has /)
  }, 30_000)
})

// ===========================================================================
// 4. tenant copy-through
// ===========================================================================

describe('tenant', () => {
  const TENANT = 'acme-corp'

  it('the agent names the tenant in the person token request', async () => {
    // AAuth issue #88: nothing otherwise selects which tenant a person token
    // carries when a person holds a personal context plus several managed ones.
    // The `tenant` request parameter is the resolution, and it is the agent
    // that sends it — the PS cannot guess.
    const personToken = await getPersonToken({ tenant: TENANT })
    expect(claimsOf(personToken).tenant).toBe(TENANT)

    // And a different value comes back, so this is the parameter deciding it
    // and not a fixed server-side default.
    await mockin.reset()
    const other = await getPersonToken({ tenant: 'globex' })
    expect(claimsOf(other).tenant).toBe('globex')
  }, 30_000)

  it('survives person token -> resource token -> auth token', async () => {
    const chain = await walkTheChain({ tenant: TENANT })

    expect(claimsOf(chain.personToken).tenant).toBe(TENANT)
    expect(claimsOf(chain.resourceToken).tenant).toBe(TENANT)
    expect(claimsOf(chain.authToken).tenant).toBe(TENANT)

    const answered = await callResource(agent.presenting(chain.authToken))
    expect(answered.status).toBe(200)
    expect(answered.body).toMatchObject({ tenant: TENANT })
  }, 30_000)

  it('fails the exchange, not just the hint, when the resource omits it', async () => {
    // Three resource-side branches in the fleet omitted this. Step 6 rejects on
    // mismatch *or omission*, so for a tenant-bearing person it kills the
    // exchange outright.
    const personToken = await getPersonToken({ tenant: TENANT })
    expect(claimsOf(personToken).tenant).toBe(TENANT)

    resource.mint = { stripTenant: true }
    const resourceToken = await getResourceToken(personToken)
    expect(claimsOf(resourceToken).tenant).toBeUndefined()

    const refused = await redeemExpectingRefusal(resourceToken)
    expect(refused.status).toBe(400)
    expect(refused.error).toBe('invalid_resource_token')
    expect(refused.detail)
      .toMatch(/tenant mismatch: person token has acme-corp, resource_token has \(none\)/)
  }, 30_000)

  it('rejects a resource token that changed the tenant', async () => {
    const personToken = await getPersonToken({ tenant: TENANT })
    resource.mint = { overrideTenant: 'other-corp' }
    const resourceToken = await getResourceToken(personToken)
    expect(claimsOf(resourceToken).tenant).toBe('other-corp')

    const refused = await redeemExpectingRefusal(resourceToken)
    expect(refused.status).toBe(400)
    expect(refused.detail)
      .toMatch(/tenant mismatch: person token has acme-corp, resource_token has other-corp/)
  }, 30_000)
})

// ===========================================================================
// 5. `typ` discrimination — a person token is not authorization
// ===========================================================================

describe('typ discrimination', () => {
  it('rejects an aa-person+jwt where an auth token is required, as 401 not 403', async () => {
    // A person token and a PS-issued auth token share iss, dwk, aud, sub and
    // cnf. They differ only in `typ`. Without the check, a person token passes
    // signature, iss, aud and cnf verification and lands on the scope gate as
    // 403 insufficient_scope — a wrong-credential problem reported as a
    // permissions problem.
    const personToken = await getPersonToken()

    resource.accept = ['auth']
    resource.scopeGateReached = false

    const rejected = await callResource(agent.presenting(personToken))

    expect(rejected.status).toBe(401)
    expect(rejected.body).toMatchObject({ error: 'token_type_not_accepted' })
    expect(rejected.status).not.toBe(403)
    // The decisive assertion: it never reached the scope check.
    expect(resource.scopeGateReached).toBe(false)
  }, 30_000)

  it('the same person token is accepted where a person token is what is wanted', async () => {
    const personToken = await getPersonToken()
    resource.accept = ['person']
    const challenged = await callResource(agent.presenting(personToken))
    expect(challenged.status).toBe(401)
    expect(requirementOf(challenged.headers)?.requirement).toBe('auth-token')
  }, 30_000)

  it('a real auth token is refused by a call site that only takes person tokens', async () => {
    const chain = await walkTheChain()
    resource.accept = ['person']
    const rejected = await callResource(agent.presenting(chain.authToken))
    expect(rejected.status).toBe(401)
    expect(rejected.body).toMatchObject({ error: 'token_type_not_accepted' })
  }, 30_000)
})

// ===========================================================================
// 6. planAccessMode against a resource that actually declares each mode
// ===========================================================================

describe('planAccessMode', () => {
  const MODES: KnownAccessMode[] = [
    'agent-token', 'person-token', 'session-token', 'auth-token', 'per-call',
  ]
  /** Decided in the package contract, not a judgement call. */
  const UNSATISFIABLE_WITHOUT_PS = new Set(['person-token', 'auth-token', 'per-call'])

  async function declaredMode(): Promise<string | undefined> {
    const res = await router.fetch(`${RESOURCE}/.well-known/aauth-resource.json`)
    const metadata = await res.json() as { access_mode?: string }
    return metadata.access_mode
  }

  for (const mode of MODES) {
    it(`${mode}: satisfiable with a person server`, async () => {
      resource.accessMode = mode
      const plan = planAccessMode(await declaredMode(), { hasPersonServer: true })
      expect(plan).toEqual({ kind: 'satisfiable', mode })
    })

    it(`${mode}: ${UNSATISFIABLE_WITHOUT_PS.has(mode) ? 'unsatisfiable' : 'satisfiable'} without one`, async () => {
      resource.accessMode = mode
      const plan = planAccessMode(await declaredMode(), { hasPersonServer: false })
      if (UNSATISFIABLE_WITHOUT_PS.has(mode)) {
        expect(plan.kind).toBe('unsatisfiable')
        expect((plan as { mode: string }).mode).toBe(mode)
        expect((plan as { reason: string }).reason).toContain('person server')
      } else {
        expect(plan).toEqual({ kind: 'satisfiable', mode })
      }
    })
  }

  it('a resource declaring nothing is undeclared, never an error', async () => {
    resource.accessMode = undefined
    expect(await declaredMode()).toBeUndefined()
    expect(planAccessMode(await declaredMode(), { hasPersonServer: false }))
      .toEqual({ kind: 'undeclared' })
  })

  it('an unrecognized value is undeclared — call the resource and read the requirement', async () => {
    resource.accessMode = 'mode-invented-after-this-release'
    expect(planAccessMode(await declaredMode(), { hasPersonServer: true }))
      .toEqual({ kind: 'undeclared' })
  })

  it("the ps-less agent's own token is what makes hasPersonServer false", async () => {
    expect(claimsOf(agent.agentToken).ps).toBe(PS)
    expect(claimsOf(psLessAgent.agentToken).ps).toBeUndefined()

    resource.accessMode = 'auth-token'
    const declared = await declaredMode()
    const setup = { hasPersonServer: claimsOf(psLessAgent.agentToken).ps !== undefined }
    expect(planAccessMode(declared, setup).kind).toBe('unsatisfiable')
  })
})

// ===========================================================================
// 7. Ed25519 emitted, EdDSA rejected, on every token type at both ends
// ===========================================================================

describe('signature algorithms', () => {
  it('every token in the chain is emitted with the fully-specified Ed25519', async () => {
    const chain = await walkTheChain()
    for (const [name, jwt] of Object.entries({
      'agent token': agent.agentToken,
      'person token': chain.personToken,
      'resource token': chain.resourceToken,
      'auth token': chain.authToken,
    })) {
      expect(headerOf(jwt).alg, name).toBe('Ed25519')
      expect(headerOf(jwt).alg, name).not.toBe('EdDSA')
    }
  }, 30_000)

  it('every published key carries alg: Ed25519', async () => {
    const psJwks = await (await router.fetch(`${PS}/aauth/jwks.json`)).json() as { keys: Array<{ alg: string }> }
    const rsJwks = await (await router.fetch(`${RESOURCE}/jwks.json`)).json() as { keys: Array<{ alg: string }> }
    const agentJwks = await (await router.fetch(`${AGENT}/jwks.json`)).json() as { keys: Array<{ alg: string }> }
    for (const jwks of [psJwks, rsJwks, agentJwks]) {
      expect(jwks.keys.length).toBeGreaterThan(0)
      for (const key of jwks.keys) expect(key.alg).toBe('Ed25519')
    }
  })

  it('cnf.jwk carries alg: Ed25519 in the person and auth tokens', async () => {
    const chain = await walkTheChain()
    for (const jwt of [chain.personToken, chain.authToken]) {
      const cnf = claimsOf(jwt).cnf as { jwk: { alg: string; crv: string } }
      expect(cnf.jwk.alg).toBe('Ed25519')
      expect(cnf.jwk.crv).toBe('Ed25519')
    }
  }, 30_000)

  it('the PS rejects an agent token signed EdDSA', async () => {
    const eddsaAgent = await createAgent({ router, personServer: PS, alg: 'EdDSA' })
    try {
      mockin.trust(AGENT, eddsaAgent.jwks)
      await mockin.reset()
      let refused: PersonTokenError | undefined
      try {
        await getPersonToken({ agentUnder: eddsaAgent })
      } catch (err) {
        refused = err as PersonTokenError
      }
      expect(refused).toBeInstanceOf(PersonTokenError)
      expect(refused!.status).toBe(401)
      expect(refused!.error).toBe('invalid_jwt')
      expect(refused!.detail).toMatch(/EdDSA/)
      expect(refused!.detail).toMatch(/Ed25519 required/)
    } finally {
      await eddsaAgent.stop()
      mockin.trust(AGENT, agent.jwks)
      router.register(AGENT, agent.origin)
    }
  }, 30_000)

  it('the PS rejects a resource token signed EdDSA', async () => {
    const personToken = await getPersonToken()
    resource.mint = { alg: 'EdDSA' }
    const resourceToken = await getResourceToken(personToken)
    expect(headerOf(resourceToken).alg).toBe('EdDSA')

    const refused = await redeemExpectingRefusal(resourceToken)
    expect(refused.status).toBe(400)
    expect(refused.error).toBe('invalid_resource_token')
    expect(refused.detail).toMatch(/EdDSA/)
    expect(refused.detail).toMatch(/Ed25519 required/)
  }, 30_000)

  it('the resource rejects an EdDSA-signed token of every kind', async () => {
    // mockin never emits EdDSA, so the resource-side half needs forged tokens.
    // `verifyToken` refuses the polymorphic identifier before it fetches
    // anything, on all three typ values.
    const now = Math.floor(Date.now() / 1000)
    const common = {
      iss: PS,
      cnf: { jwk: agent.signingKey.publicJwk },
      iat: now,
      exp: now + 300,
    }
    const forged = {
      [TOKEN_TYP.person]: await forgeToken(
        agent.identityKey, { alg: 'EdDSA', typ: TOKEN_TYP.person },
        { ...common, dwk: DWK.person, aud: RESOURCE, sub: 'sub-1', jti: 'jti-1' },
      ),
      [TOKEN_TYP.auth]: await forgeToken(
        agent.identityKey, { alg: 'EdDSA', typ: TOKEN_TYP.auth },
        { ...common, dwk: DWK.person, aud: RESOURCE, sub: 'sub-1', ps: PS },
      ),
      [TOKEN_TYP.agent]: await forgeToken(
        agent.identityKey, { alg: 'EdDSA', typ: TOKEN_TYP.agent },
        { ...common, iss: AGENT, dwk: DWK.agent, sub: AGENT_ID },
      ),
    }

    for (const [typ, jwt] of Object.entries(forged)) {
      const rejected = await callResource(agent.presenting(jwt))
      expect(rejected.status, typ).toBe(401)
      expect(String((rejected.body as { error_description: string }).error_description), typ)
        .toMatch(/EdDSA/)
    }
  }, 30_000)
})

// ===========================================================================
// 8. content-digest and content-type on bodied PS requests
// ===========================================================================

describe('body signing toward the PS', () => {
  it('the agent covers content-digest and content-type by default', async () => {
    // §Covered Components: a bodied request to a PS or AS MUST additionally
    // sign `content-digest` and `content-type`. `createSignedFetch(...,
    // { signBody: true })` is what the -11 agent uses toward a PS.
    expect(PS_COMPONENTS_BODY).toContain('content-digest')
    expect(PS_COMPONENTS_BODY).toContain('content-type')

    let sent: Record<string, string> | undefined
    const observed = router.route(createSignedFetch(agent.keyMaterial, {
      signBody: true,
      onSigned: s => { sent = s.headers },
    }))

    const res = await observed(`${PS}/aauth/person`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ resource: RESOURCE }),
    })

    expect(res.status).toBe(200)
    expect(sent!['content-digest']).toMatch(/^sha-256=:.+:$/)
    expect(sent!['signature-input']).toContain('"content-digest"')
    expect(sent!['signature-input']).toContain('"content-type"')
  }, 30_000)

  it('the PS rejects a bodied request whose signature does not cover them', async () => {
    // Without `signBody`, @hellocoop/httpsig signs its DEFAULT_COMPONENTS_BODY,
    // which omits content-digest — and then emits no Content-Digest header at
    // all. This is the mistake the mandate exists to catch, and it is a real
    // rejection, not a warning.
    const unsigned = router.route(createSignedFetch(agent.keyMaterial))
    const res = await unsigned(`${PS}/aauth/person`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ resource: RESOURCE }),
    })

    expect(res.status).toBe(401)
    expect(await res.json()).toMatchObject({ error: 'signature_verification_failed' })
    expect(res.headers.get('signature-error')).toContain('content-digest')
    expect(res.headers.get('accept-signature')).toContain('content-digest')
  }, 30_000)

  it('and accepts the same request once require_body_signing is off', async () => {
    // Proves the previous rejection came from the body-signing rule and nothing
    // else: one switch, same request, different answer.
    await mockin.configure({ require_body_signing: false })

    const unsigned = router.route(createSignedFetch(agent.keyMaterial))
    const res = await unsigned(`${PS}/aauth/person`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ resource: RESOURCE }),
    })

    expect(res.status).toBe(200)
    const body = await res.json() as { person_token: string }
    expect(headerOf(body.person_token)).toMatchObject({ typ: TOKEN_TYP.person })
  }, 30_000)

  it('the auth token endpoint requires it too', async () => {
    const personToken = await getPersonToken()
    const resourceToken = await getResourceToken(personToken)

    const unsigned = router.route(createSignedFetch(agent.keyMaterial))
    const res = await unsigned(`${PS}/aauth/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ resource_token: resourceToken }),
    })

    expect(res.status).toBe(401)
    expect(res.headers.get('signature-error')).toContain('content-digest')
  }, 30_000)
})

// ===========================================================================
// 9. R3 — resource request records
//
// WHAT MOCKIN CANNOT PROVE HERE, stated once so no assertion below implies it:
//
//   * **mockin never routes an operation to `r3_per_call` on its own.**
//     `autoGrantR3` grants the whole document, every time; there is no
//     classifier, no risk heuristic, no consent screen. The only way an
//     `r3_per_call` claim exists is the `r3_grants` mock switch, which
//     replaces the grant wholesale with whatever object you hand it. So the
//     tests below use that switch to *stand in for the person's decision*, and
//     prove the resource and agent halves of the per-call round trip. Whether
//     a PS classifies correctly is untested and untestable here.
//   * **mockin does not link a proposal to a prior class grant.** It does not
//     remember the first R3 document, does not require the proposal's
//     operations to be a subset of what was granted, and does not connect the
//     two `POST /aauth/token` calls in any way. "You may only propose what you
//     were granted in principle" is therefore unverified end to end.
//   * **There is no proposal approval endpoint.** `POST /aauth/pending/:id`
//     accepts an `updated_resource_token` and never reads it.
//   * `r3_operations` is a **resource-facing** request member, not a PS one.
//     mockin has no such parameter; R3 reaches the PS only as the resource
//     token's `r3_uri` / `r3_s256`.
// ===========================================================================

describe('R3', () => {
  const CLASS_OPERATIONS = [{ operationId: 'listMessages' }, PER_CALL_OPERATION]

  /** The agent's R3 authorization request — the body `@aauth/fetch
   *  --operations` sends to a resource's authorize endpoint. */
  async function authorize(personToken: string, account?: string) {
    const res = await agent.presenting(personToken)(`${RESOURCE}/authorize`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        r3_operations: { vocabulary: R3_VOCABULARY, operations: CLASS_OPERATIONS },
        ...(account ? { account } : {}),
      }),
    })
    expect(res.status).toBe(200)
    return await res.json() as { resource_token: string; r3_uri: string; r3_s256: string }
  }

  async function invoke(
    authToken: string,
    operation: unknown,
    parameters: Record<string, unknown>,
  ) {
    const res = await agent.presenting(authToken)(`${RESOURCE}/invoke`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ operation, parameters }),
    })
    const text = await res.text()
    let body: unknown = text
    try { body = JSON.parse(text) } catch { /* keep the text */ }
    return { status: res.status, headers: res.headers, body }
  }

  it('r3_operations -> resource token with r3_uri/r3_s256 -> the PS fetches it -> r3_granted', async () => {
    const personToken = await getPersonToken()
    const authorized = await authorize(personToken)

    // The resource token references the document; it never carries it.
    const rt = claimsOf(authorized.resource_token)
    expect(rt.r3_uri).toBe(authorized.r3_uri)
    expect(rt.r3_s256).toBe(authorized.r3_s256)
    expect(rt.operations).toBeUndefined()
    expect(rt.vocabulary).toBeUndefined()

    // The PS has not seen the document yet.
    expect(resource.r3Served).toHaveLength(0)

    const authToken = await getAuthToken(authorized.resource_token)

    // It fetched it — over a signed request it had to be entitled to make.
    expect(resource.r3Served).toHaveLength(1)
    expect(await computeR3Hash(resource.r3Served[0])).toBe(authorized.r3_s256)

    const at = claimsOf(authToken)
    expect(at.r3_uri).toBe(authorized.r3_uri)
    expect(at.r3_s256).toBe(authorized.r3_s256)
    expect(at.r3_granted).toEqual({
      vocabulary: R3_VOCABULARY,
      operations: CLASS_OPERATIONS,
    })

    // A granted operation runs.
    const invoked = await invoke(authToken, CLASS_OPERATIONS[0], {})
    expect(invoked.status).toBe(200)
    expect(invoked.body).toMatchObject({ via: 'r3_granted' })
  }, 30_000)

  it('the account of the authorization request reaches the document and the token', async () => {
    const personToken = await getPersonToken()
    const authorized = await authorize(personToken, 'work@example.com')
    expect(claimsOf(authorized.resource_token).account).toBe('work@example.com')

    await getAuthToken(authorized.resource_token)
    const served = JSON.parse(resource.r3Served[0]) as { account?: string }
    expect(served.account).toBe('work@example.com')
  }, 30_000)

  it('rejects a resource token carrying r3_uri without r3_s256', async () => {
    // Both or neither. One without the other is a document nobody can pin.
    const personToken = await getPersonToken()
    const authorized = await authorize(personToken)
    // Minted by hand: `createResourceToken` refuses to emit one without the
    // other, so only a resource that bypassed the package can produce this.
    const { r3_s256: _dropped, ...claims } = claimsOf(authorized.resource_token)
    const half = await forgeToken(
      resource.signingKey, { typ: TOKEN_TYP.resource }, claims,
    )

    const refused = await redeemExpectingRefusal(half)
    expect(refused.error).toBe('invalid_resource_token')
    expect(refused.detail).toMatch(/both r3_uri and r3_s256 or neither/)
  }, 30_000)

  // -------------------------------------------------------------------------
  // Byte-stable serving
  // -------------------------------------------------------------------------

  it('serves identical bytes on every fetch, and they hash to the r3_s256 in the token', async () => {
    // The whole scheme rests on this. A resource that parses its stored
    // document and re-stringifies it on the way out changes key order or
    // whitespace, the hash stops matching, and every exchange fails with an
    // error that names neither cause.
    const personToken = await getPersonToken()
    const authorized = await authorize(personToken)

    // mockin does not cache R3 documents — it re-fetches on every exchange, so
    // two exchanges are two real fetches of the same URI.
    await getAuthToken(authorized.resource_token)
    const second = await authorize(personToken)
    expect(second.r3_uri).toBe(authorized.r3_uri)   // content-addressed
    expect(second.r3_s256).toBe(authorized.r3_s256)
    await getAuthToken(second.resource_token)

    expect(resource.r3Served).toHaveLength(2)
    expect(resource.r3Served[0]).toBe(resource.r3Served[1])
    for (const body of resource.r3Served) {
      expect(await computeR3Hash(body)).toBe(authorized.r3_s256)
    }
  }, 30_000)

  it('a document whose bytes changed under its URI is refused by the PS', async () => {
    // The negative of the above: if re-serialization ever did change the bytes,
    // this is the failure it produces. Simulated by mutating the store, because
    // `@aauth/resource` has no code path that re-serializes.
    const personToken = await getPersonToken()
    const authorized = await authorize(personToken)
    await resource.tamperR3(authorized.r3_uri, '{"vocabulary":"urn:aauth:vocabulary:openapi","operations":[{"operationId":"listMessages"}]}')

    const refused = await redeemExpectingRefusal(authorized.resource_token)
    expect(refused.error).toBe('invalid_resource_token')
    expect(refused.detail).toMatch(/r3_s256 mismatch/)
  }, 30_000)

  // -------------------------------------------------------------------------
  // Fetch authorization — §R3 Document Access Restriction
  // -------------------------------------------------------------------------

  it('refuses an agent: it authenticates, but not as a server', async () => {
    // An agent presents `Signature-Key: sig=jwt`. That proves which agent it
    // is, and an agent is never an entitled fetcher — the document describes
    // what the *person* is being asked to authorize, and the agent must not be
    // able to read it. There is no server identifier in a `sig=jwt`
    // presentation at all, so the check has nothing to compare and refuses.
    const personToken = await getPersonToken()
    const authorized = await authorize(personToken)

    const res = await agent.resourceFetch(authorized.r3_uri, { method: 'GET' })
    expect(res.status).toBe(401)
    expect(await res.json()).toEqual({ error: 'signature_required' })
    expect(resource.r3Served).toHaveLength(0)
  }, 30_000)

  it('refuses a server that authenticates correctly but is not the entitled one', async () => {
    // The signature verifies, the key resolves at
    // `{id}/.well-known/{dwk}`, and `id` is a real server identifier — it is
    // just not the `aud` of the resource token, nor the agent's PS. 403.
    const personToken = await getPersonToken()
    const authorized = await authorize(personToken)

    const intruder = serverSignedFetch(router, agent.identityKey, AGENT, 'aauth-agent.json')
    const res = await intruder(authorized.r3_uri, { method: 'GET' })
    expect(res.status).toBe(403)
    expect(await res.json()).toEqual({ error: 'forbidden' })
    expect(resource.r3Served).toHaveLength(0)
  }, 30_000)

  it('an unsigned fetch gets nothing', async () => {
    const personToken = await getPersonToken()
    const authorized = await authorize(personToken)
    const res = await router.fetch(authorized.r3_uri)
    expect(res.status).toBe(401)
    expect(resource.r3Served).toHaveLength(0)
  }, 30_000)

  // -------------------------------------------------------------------------
  // Per-call proposals
  // -------------------------------------------------------------------------

  /**
   * Walk the per-call round trip and return everything a test needs to assert.
   *
   * `r3_grants` stands in for the person's decision at both steps: first to put
   * `sendMessage` in `r3_per_call` rather than `r3_granted`, then to approve
   * the specific proposal. mockin has no consent screen for either.
   */
  async function perCallRoundTrip(parameters: Record<string, unknown>) {
    const personToken = await getPersonToken()
    const authorized = await authorize(personToken)

    await mockin.configure({
      r3_grants: {
        granted: { vocabulary: R3_VOCABULARY, operations: [CLASS_OPERATIONS[0]] },
        per_call: { vocabulary: R3_VOCABULARY, operations: [PER_CALL_OPERATION] },
      },
    })
    const classToken = await getAuthToken(authorized.resource_token)
    expect(claimsOf(classToken).r3_per_call)
      .toEqual({ vocabulary: R3_VOCABULARY, operations: [PER_CALL_OPERATION] })

    // Invoking the per-call operation produces a proposal, not a result.
    const challenged = await invoke(classToken, PER_CALL_OPERATION, parameters)
    expect(challenged.status).toBe(401)
    const proposalToken = resourceTokenFrom(challenged.headers)

    // The person approves this specific call.
    await mockin.configure({ r3_grants: null })
    const perCallToken = await getAuthToken(proposalToken)

    return { authorized, classToken, proposalToken, perCallToken }
  }

  it('per-call: proposal -> approval -> retry, and the resource enforces the parameters', async () => {
    const parameters = { to: 'alice@example.com', subject: 'Q3 numbers' }
    const { proposalToken, perCallToken } = await perCallRoundTrip(parameters)

    // The proposal is a full R3 document scoped to this one call.
    const proposal = resource.lastProposal!
    expect(proposal.document.operations).toEqual([PER_CALL_OPERATION])
    expect(proposal.document.parameters).toEqual(parameters)

    // The resource token references it. It does not carry the parameters.
    const rt = claimsOf(proposalToken)
    expect(rt.r3_uri).toBe(proposal.r3_uri)
    expect(rt.r3_s256).toBe(proposal.r3_s256)
    expect(JSON.stringify(rt)).not.toContain('alice@example.com')

    // Neither does the auth token: the PS saw the parameters in the document it
    // fetched, and put only the operation in the grant.
    const at = claimsOf(perCallToken)
    expect(at.r3_s256).toBe(proposal.r3_s256)
    expect(JSON.stringify(at)).not.toContain('alice@example.com')
    expect((at.r3_granted as { operations: unknown[] }).operations).toEqual([PER_CALL_OPERATION])

    // The retry with the approved parameters succeeds.
    const done = await invoke(perCallToken, PER_CALL_OPERATION, parameters)
    expect(done.status).toBe(200)
    expect(done.body).toMatchObject({ approved: parameters })
  }, 60_000)

  it('per-call: an approval for one recipient is not replayable against another', async () => {
    const { perCallToken } = await perCallRoundTrip({
      to: 'alice@example.com',
      subject: 'Q3 numbers',
    })

    const replayed = await invoke(perCallToken, PER_CALL_OPERATION, {
      to: 'attacker@example.com',
      subject: 'Q3 numbers',
    })
    expect(replayed.status).toBe(403)
    expect(replayed.body).toMatchObject({ error: 'proposal_parameter_mismatch' })
    expect(String((replayed.body as { error_description: string }).error_description))
      .toMatch(/Parameter "to" differs from the approved proposal/)
  }, 60_000)

  it('per-call: a parameter the proposal did not carry is rejected', async () => {
    const { perCallToken } = await perCallRoundTrip({ to: 'alice@example.com' })

    const extra = await invoke(perCallToken, PER_CALL_OPERATION, {
      to: 'alice@example.com',
      bcc: 'attacker@example.com',
    })
    expect(extra.status).toBe(403)
    expect(String((extra.body as { error_description: string }).error_description))
      .toMatch(/Parameter "bcc" was not in the approved proposal/)

    const missing = await invoke(perCallToken, PER_CALL_OPERATION, {})
    expect(missing.status).toBe(403)
    expect(String((missing.body as { error_description: string }).error_description))
      .toMatch(/Approved parameter "to" is missing from the call/)
  }, 60_000)

  it('per-call: the invoked operation must be the approved one', async () => {
    const { perCallToken } = await perCallRoundTrip({ to: 'alice@example.com' })
    const wrong = await invoke(perCallToken, CLASS_OPERATIONS[0], { to: 'alice@example.com' })
    expect(wrong.status).toBe(403)
    expect(wrong.body).toMatchObject({ error: 'proposal_operation_mismatch' })
  }, 60_000)

  // -------------------------------------------------------------------------
  // Digest parameters
  // -------------------------------------------------------------------------

  it('a digest parameter reaches the PS as a hash and an excerpt, never as the value', async () => {
    const secret = 'Dear Alice,\n\nthe merger closes on the 14th. Wire the deposit to account 4471-9930.\n\nBob'
    const digest = await digestParameter(secret, {
      media_type: 'text/plain',
      excerptLength: 24,
    })
    expect(digest.s256).toBe(await computeR3Hash(secret))
    expect(digest.excerpt).toBe('Dear Alice,\n\nthe merger …')
    expect(secret).not.toContain(digest.excerpt!)  // the excerpt is truncated

    const { perCallToken } = await perCallRoundTrip({ to: 'alice@example.com', body: digest })

    // Neither the document the PS fetched nor the token it issued carries the
    // value — only the hash, the excerpt and the media type.
    const servedText = resource.r3Served.join('\n')
    expect(servedText).toContain(digest.s256)
    expect(servedText).toContain('text/plain')
    expect(servedText).not.toContain('4471-9930')
    expect(JSON.stringify(claimsOf(perCallToken))).not.toContain('4471-9930')

    // At call time the agent presents the full bytes, and the resource verifies
    // them against the approved digest.
    const done = await invoke(perCallToken, PER_CALL_OPERATION, {
      to: 'alice@example.com',
      body: secret,
    })
    expect(done.status).toBe(200)
  }, 60_000)

  it('a digest parameter whose bytes changed is rejected', async () => {
    const secret = 'Wire the deposit to account 4471-9930.'
    const digest = await digestParameter(secret, { media_type: 'text/plain' })
    const { perCallToken } = await perCallRoundTrip({ to: 'alice@example.com', body: digest })

    const tampered = await invoke(perCallToken, PER_CALL_OPERATION, {
      to: 'alice@example.com',
      body: 'Wire the deposit to account 0000-0000.',
    })
    expect(tampered.status).toBe(403)
    expect(String((tampered.body as { error_description: string }).error_description))
      .toMatch(/Parameter "body" does not hash to the approved s256/)
  }, 60_000)
})

// ===========================================================================
// Things the PS refuses that no other test covers
// ===========================================================================

describe('deferred features the fleet must not have shipped', () => {
  it('upstream_token is rejected at both endpoints — call chaining is out of scope', async () => {
    // `@aauth/agent` deliberately does not send it. Asserted at the HTTP level
    // so the refusal is on record, and so a future implementation cannot land
    // silently on a PS that does not support it.
    for (const [endpoint, extra] of [
      ['person', { resource: RESOURCE }],
      ['token', { resource_token: 'x' }],
    ] as const) {
      const res = await agent.psFetch(`${PS}/aauth/${endpoint}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ ...extra, upstream_token: 'anything' }),
      })
      expect(res.status, endpoint).toBe(400)
      expect(await res.json(), endpoint).toMatchObject({ error: 'invalid_request' })
    }
  }, 30_000)

  it('the person token endpoint requires a resource', async () => {
    const res = await agent.psFetch(`${PS}/aauth/person`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({}),
    })
    expect(res.status).toBe(400)
    // §Error Response Format: RFC 9457 problem details — `application/problem+json`,
    // a REQUIRED `error` extension member, an OPTIONAL `detail`. Asserted raw
    // here because it is the one place the suite sees the media type; every
    // other refusal is read off `PersonTokenError` / `TokenExchangeError`,
    // which accept the pre-11 `error_description` spelling too (Wallet still
    // emits it).
    expect(res.headers.get('content-type')).toContain('application/problem+json')
    expect(await res.json()).toMatchObject({
      error: 'invalid_request',
      detail: 'resource is required',
    })
  }, 30_000)

  it('the PS publishes auth_token_endpoint and person_token_endpoint, not token_endpoint', async () => {
    const metadata = await (await router.fetch(`${PS}/.well-known/aauth-person.json`)).json() as Record<string, unknown>
    expect(metadata.auth_token_endpoint).toBe(`${PS}/aauth/token`)
    expect(metadata.person_token_endpoint).toBe(`${PS}/aauth/person`)
    // Renamed in -11. A PS still publishing the old name is pre-11.
    expect(metadata.token_endpoint).toBeUndefined()
    // Not published, so nothing in this suite can exercise missions beyond
    // equality — see the file header.
    expect(metadata.mission_endpoint).toBeUndefined()
    expect(metadata.revocation_endpoint).toBeUndefined()
    expect(metadata.mission_control_endpoint).toBeUndefined()
  })

  it('@aauth/agent refuses a PS whose metadata is still -10 shaped', async () => {
    // A PS that publishes no `person_token_endpoint` cannot mint the person
    // token a resource now demands, so nothing downstream can succeed. Fail at
    // the metadata document rather than half-way through a flow.
    const serving = (doc: Record<string, unknown>) => async () =>
      new Response(JSON.stringify(doc), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })

    await expect(fetchAuthServerMetadata({
      signedFetch: serving({ token_endpoint: `${PS}/aauth/token`, jwks_uri: `${PS}/aauth/jwks.json` }),
      authServerUrl: PS,
    })).rejects.toThrow(/auth_token_endpoint/)

    await expect(fetchAuthServerMetadata({
      signedFetch: serving({ auth_token_endpoint: `${PS}/aauth/token` }),
      authServerUrl: PS,
    })).rejects.toThrow(/person_token_endpoint/)

    // The real document passes both checks.
    clearMetadataCache()
    const metadata = await fetchAuthServerMetadata({
      signedFetch: agent.psFetch,
      authServerUrl: PS,
    })
    expect(metadata.auth_token_endpoint).toBe(`${PS}/aauth/token`)
    expect(metadata.person_token_endpoint).toBe(`${PS}/aauth/person`)
  }, 30_000)
})
