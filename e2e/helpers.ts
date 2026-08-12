/**
 * Cross-package e2e fixtures for AAuth -11.
 *
 * The point of this suite is that nothing here is a mock of the protocol. The
 * person server is **mockin** (WP-19), started as a real process — the only
 * implementation in existence issuing -11 person tokens. The agent side is
 * `@aauth/agent` + `@hellocoop/httpsig` making real signed HTTP requests. The
 * resource side is `@aauth/resource` inside a real `node:http` server that
 * verifies those signatures. So a test that passes here is a statement about
 * four packages agreeing on the wire, not about a stub.
 *
 * ## The one piece of scaffolding, and why it is unavoidable
 *
 * AAuth server identifiers are `https://host` with **no port** (Protocol
 * §Server Identifiers, enforced by `isServerIdentifier` in `@aauth/resource`
 * and by mockin's `validateResourceIdentifier`). Nothing on loopback can be
 * one. So every party gets a real identifier — `https://ps.mockin.test`,
 * `https://rs.mockin.test`, `https://agent.mockin.test` — which is what goes
 * into `iss`, `aud`, `ps` and every comparison, and a {@link LoopbackRouter}
 * rewrites *only the transport* to `http://127.0.0.1:port`. No claim, no
 * signature input, and no comparison is altered: the requests are signed over
 * the loopback `@authority` they are actually sent to, exactly as a real client
 * signs the authority it dials.
 */

import { createServer } from 'node:http'
import { existsSync } from 'node:fs'
import type { IncomingMessage, Server, ServerResponse } from 'node:http'
import { spawn } from 'node:child_process'
import type { ChildProcess } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { AddressInfo } from 'node:net'

import { generateKeyPair, exportJWK, SignJWT, calculateJwkThumbprint } from 'jose'
import type { JWK, KeyLike } from 'jose'
import { verify as httpSigVerify } from '@hellocoop/httpsig'

import { fetch as httpSigFetch } from '@hellocoop/httpsig'
import { createSignedFetch } from '@aauth/agent'
import type { FetchLike, GetKeyMaterial } from '@aauth/agent'
import {
  SIGNING_ALG, TOKEN_TYP, DWK,
  decodeJwtHeader, decodeJwtPayload, parseRequirementHeader,
} from '@aauth/protocol'
import type { AAuthChallenge } from '@aauth/protocol'
import {
  verifyToken,
  createResourceToken,
  buildAAuthHeader,
  AAuthTokenError,
  MemoryR3Store,
  publishR3Document,
  publishProposal,
  serveR3Document,
  verifyProposalParameters,
  getR3ByHash,
  parseR3Record,
  R3Error,
} from '@aauth/resource'
import type {
  PersonTokenReference,
  VerifiedPersonToken,
  VerifiedAuthToken,
  TokenKind,
  R3Document,
  R3OperationSet,
  R3ParameterValue,
} from '@aauth/resource'

export { decodeJwtHeader, decodeJwtPayload }

/**
 * The platform fetch, captured before {@link LoopbackRouter.install} replaces
 * the global. Everything in this file dials loopback through this one, so
 * installing the router can never recurse.
 */
const realFetch: typeof globalThis.fetch = globalThis.fetch.bind(globalThis)

const HERE = dirname(fileURLToPath(import.meta.url))
/** WP-19's worktree. mockin is not a workspace of this repo. */
export const MOCKIN_DIR = join(HERE, '..', '..', 'wp19')

// ---------------------------------------------------------------------------
// Identifiers
// ---------------------------------------------------------------------------

export const PS = 'https://ps.mockin.test'
export const RESOURCE = 'https://rs.mockin.test'
export const AGENT = 'https://agent.mockin.test'
export const AGENT_ID = 'aauth:e2e@agent.mockin.test'

// ---------------------------------------------------------------------------
// Loopback routing
// ---------------------------------------------------------------------------

/**
 * Maps AAuth server identifiers onto the loopback origins the test processes
 * actually listen on. Transport only — see the file header.
 */
export class LoopbackRouter {
  private readonly origins = new Map<string, string>()

  register(identifier: string, origin: string): void {
    this.origins.set(identifier, origin.replace(/\/$/, ''))
  }

  /** `https://rs.mockin.test/api` -> `http://127.0.0.1:54321/api`. */
  rewrite(url: string | URL): string {
    const s = typeof url === 'string' ? url : url.toString()
    for (const [identifier, origin] of this.origins) {
      if (s === identifier) return origin
      if (s.startsWith(`${identifier}/`)) return origin + s.slice(identifier.length)
    }
    return s
  }

  /** Plain fetch that resolves identifiers. For JWKS/metadata discovery. */
  get fetch(): (input: string, init?: RequestInit) => Promise<Response> {
    return (input, init) => realFetch(this.rewrite(input), init)
  }

  /**
   * Replace the global fetch with the resolving one.
   *
   * Needed because `@hellocoop/httpsig`'s `verify()` resolves a
   * `Signature-Key: sig=jwks_uri` by fetching `{id}/.well-known/{dwk}` on the
   * global fetch, with no injection point — and that is how the PS identifies
   * itself when it fetches an R3 document. Rewriting is idempotent, so a
   * request that already went through `route()` is unaffected.
   */
  install(): void {
    globalThis.fetch = ((input: RequestInfo | URL, init?: RequestInit) =>
      realFetch(
        typeof input === 'string' || input instanceof URL ? this.rewrite(input) : input,
        init,
      )) as typeof globalThis.fetch
  }

  uninstall(): void {
    globalThis.fetch = realFetch
  }

  /** Wrap a signed fetch so callers pass identifiers and the signature covers
   *  the loopback authority the request is really sent to. */
  route(signedFetch: FetchLike): FetchLike {
    return (url, init) => signedFetch(this.rewrite(url), init)
  }
}

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

export interface TestKey {
  privateKey: KeyLike
  /** Published form: fully-specified `alg: Ed25519` (RFC 9864), never `EdDSA`. */
  publicJwk: JWK
  privateJwk: JsonWebKey
  thumbprint: string
  kid: string
}

export async function ed25519Key(kid: string): Promise<TestKey> {
  const { privateKey, publicKey } = await generateKeyPair('Ed25519', { extractable: true })
  const publicJwk = { ...(await exportJWK(publicKey)), alg: SIGNING_ALG, kid, use: 'sig' }
  const privateJwk = (await exportJWK(privateKey)) as JsonWebKey
  return {
    privateKey,
    publicJwk,
    // `kid` is not in the lib.dom `JsonWebKey`, but @hellocoop/httpsig reads it
    // and RFC 7517 defines it.
    privateJwk: { ...privateJwk, alg: SIGNING_ALG, kid } as JsonWebKey,
    thumbprint: await calculateJwkThumbprint(publicJwk, 'sha256'),
    kid,
  }
}

// ---------------------------------------------------------------------------
// mockin — the person server
// ---------------------------------------------------------------------------

/** The mock switches this suite drives. See mockin's `src/aauth/mock.js`. */
export interface MockinConfig {
  /** Defer the **person** token independently of the auth token. */
  person_requirement?: 'interaction' | 'approval' | null
  /** Defer the **auth** token. */
  requirement?: 'interaction' | 'approval' | 'clarification' | null
  /** false makes an interaction real: poll -> 202 until `GET /aauth/consent`. */
  auto_approve?: boolean
  /** false relaxes the content-digest + content-type coverage requirement. */
  require_body_signing?: boolean
  /** Stamped on person tokens when the request body names no tenant. */
  tenant?: string | null
  /**
   * Replaces the R3 grant wholesale. mockin's own behaviour is to grant the
   * whole fetched document and never populate `r3_per_call`, so this switch is
   * the only source of an `r3_per_call` claim — it stands in for the person's
   * decision, which mockin does not model.
   */
  r3_grants?: { granted?: R3OperationSet | null; per_call?: R3OperationSet | null } | null
  token_lifetime?: number
  /** Preloaded entity discovery, so mockin never leaves the process. */
  trusted_servers?: Record<string, unknown>
}

export interface Mockin {
  /** `https://ps.mockin.test` — its `iss`, and the `aud` of every resource token. */
  readonly issuer: string
  readonly origin: string
  /** Patch the mock switches. Only the keys you pass are applied. */
  configure(patch: MockinConfig): Promise<void>
  /** `DELETE /mock` — clears the person-token `jti` store, pending requests,
   *  the entity cache **and `trusted_servers`**, then reinstalls the latter. */
  reset(): Promise<void>
  /** Drive an interaction to completion, as a browser would. */
  consent(code: string): Promise<Response>
  /** Register an entity so mockin resolves its metadata + JWKS in-process. */
  trust(identifier: string, jwks: { keys: JWK[] }, dwkDoc?: Record<string, unknown>): void
  stop(): Promise<void>
}

async function freePort(): Promise<number> {
  const probe = createServer()
  await new Promise<void>(resolve => probe.listen(0, '127.0.0.1', resolve))
  const port = (probe.address() as AddressInfo).port
  await new Promise<void>(resolve => probe.close(() => resolve()))
  return port
}

export async function startMockin(router: LoopbackRouter): Promise<Mockin> {
  const entry = join(MOCKIN_DIR, 'src', 'server.js')
  if (!existsSync(entry)) {
    throw new Error(
      `mockin not found at ${entry}. This suite drives the real -11 person `
      + 'server; check out WP-19 (branch aauth-11/wp19-mockin) beside this '
      + 'worktree and run `npm ci` in it.',
    )
  }
  const port = await freePort()
  const origin = `http://127.0.0.1:${port}`
  router.register(PS, origin)

  const child: ChildProcess = spawn(
    process.execPath,
    ['--no-warnings', join(MOCKIN_DIR, 'src', 'server.js')],
    {
      // ISSUER is what lands in `iss`, in every `Location`, and in the `aud`
      // a resource token must match exactly. It must be a server identifier.
      env: { ...process.env, PORT: String(port), IP: '127.0.0.1', ISSUER: PS },
      cwd: MOCKIN_DIR,
      stdio: ['ignore', 'pipe', 'pipe'],
    },
  )

  const stderr: string[] = []
  child.stderr?.on('data', (b: Buffer) => stderr.push(b.toString()))

  const deadline = Date.now() + 20_000
  for (;;) {
    if (child.exitCode !== null) {
      throw new Error(`mockin exited with ${child.exitCode}: ${stderr.join('')}`)
    }
    try {
      const res = await realFetch(`${origin}/.well-known/aauth-person.json`)
      if (res.ok) break
    } catch { /* not listening yet */ }
    if (Date.now() > deadline) throw new Error(`mockin did not start: ${stderr.join('')}`)
    await new Promise(r => setTimeout(r, 50))
  }

  const trusted: Record<string, unknown> = {}

  const put = async (patch: MockinConfig): Promise<void> => {
    const res = await realFetch(`${origin}/mock/aauth`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(patch),
    })
    if (!res.ok) throw new Error(`PUT /mock/aauth failed: ${res.status} ${await res.text()}`)
  }

  return {
    issuer: PS,
    origin,
    configure: patch => put(patch),
    async reset() {
      const res = await realFetch(`${origin}/mock`, { method: 'DELETE' })
      if (!res.ok) throw new Error(`DELETE /mock failed: ${res.status}`)
      // DELETE /mock resets trusted_servers along with everything else.
      await put({ trusted_servers: trusted })
    },
    consent(code) {
      return realFetch(`${origin}/aauth/consent?code=${encodeURIComponent(code)}`)
    },
    trust(identifier, jwks, dwkDoc) {
      trusted[identifier] = {
        metadata: { issuer: identifier, jwks_uri: `${identifier}/jwks.json`, ...dwkDoc },
        jwks,
      }
    },
    async stop() {
      child.kill('SIGKILL')
      await new Promise(r => child.once('exit', r))
    },
  }
}

// ---------------------------------------------------------------------------
// The agent
// ---------------------------------------------------------------------------

export interface AgentOptions {
  router: LoopbackRouter
  /** Omit to model an agent with no person server: the agent token carries no
   *  `ps` claim, which is what `planAccessMode` reads. */
  personServer?: string
  /** Header `alg`. Only a test proving `EdDSA` is rejected passes anything else. */
  alg?: string
  lifetimeSeconds?: number
  parentAgent?: string
}

export interface TestAgent {
  readonly identifier: string
  /** Loopback origin of this agent's own metadata + JWKS server. */
  readonly origin: string
  readonly sub: string
  /** The long-lived key published at the agent server's JWKS; signs the agent token. */
  readonly identityKey: TestKey
  /** The per-session key that signs HTTP requests and is bound by `cnf.jwk`. */
  readonly signingKey: TestKey
  readonly agentToken: string
  readonly jwks: { keys: JWK[] }
  readonly keyMaterial: GetKeyMaterial
  /**
   * Signed fetch for **PS and AS endpoints**. `signBody: true`, so a bodied
   * request additionally covers `content-digest` and `content-type`
   * (Protocol §Covered Components). This is the default an agent should use
   * toward a PS, and item 8 of the suite proves the requirement is real.
   */
  readonly psFetch: FetchLike
  /**
   * Signed fetch for **resources**. Deliberately no `signBody`: a resource
   * states its own extra components via `additional_signature_components`,
   * so the blanket PS mandate does not apply.
   */
  readonly resourceFetch: FetchLike
  /**
   * A resource-facing signed fetch presenting `token` in `Signature-Key`
   * instead of the agent token — how a person token and then an auth token
   * reach a resource. The HTTP signature stays on the same key, which is the
   * key `cnf.jwk` binds in every one of them.
   */
  presenting(token: string): FetchLike
  stop(): Promise<void>
}

export async function createAgent(options: AgentOptions): Promise<TestAgent> {
  const { router, personServer, alg = SIGNING_ALG, lifetimeSeconds = 3600 } = options

  const identityKey = await ed25519Key('agent-identity-1')
  const signingKey = await ed25519Key('agent-session-1')

  const now = Math.floor(Date.now() / 1000)
  const claims: Record<string, unknown> = {
    iss: AGENT,
    dwk: DWK.agent,
    sub: AGENT_ID,
    cnf: { jwk: signingKey.publicJwk },
    iat: now,
    exp: now + lifetimeSeconds,
  }
  if (personServer) claims.ps = personServer
  if (options.parentAgent) claims.parent_agent = options.parentAgent

  const agentToken = await new SignJWT(claims)
    .setProtectedHeader({ alg, typ: TOKEN_TYP.agent, kid: identityKey.kid })
    .sign(identityKey.privateKey)

  const keyMaterial: GetKeyMaterial = async () => ({
    signingKey: signingKey.privateJwk,
    signatureKey: { type: 'jwt', jwt: agentToken },
  })

  // The agent server. A resource verifying an agent token discovers the key
  // that signed it at `{iss}/.well-known/aauth-agent.json` -> `jwks_uri`, so
  // this has to be a real document over real HTTP for that path to be tested.
  const jwks = { keys: [identityKey.publicJwk] }
  const agentServer = createServer((req, res) => {
    const path = new URL(req.url ?? '/', AGENT).pathname
    const body = path === '/.well-known/aauth-agent.json'
      ? { issuer: AGENT, name: 'e2e agent', jwks_uri: `${AGENT}/jwks.json` }
      : path === '/jwks.json'
        ? jwks
        : undefined
    res.writeHead(body ? 200 : 404, { 'content-type': 'application/json' })
    res.end(JSON.stringify(body ?? { error: 'not_found' }))
  })
  await new Promise<void>(resolve => agentServer.listen(0, '127.0.0.1', resolve))
  const origin = `http://127.0.0.1:${(agentServer.address() as AddressInfo).port}`
  // Every agent shares the identifier `AGENT`, so the last one created owns the
  // route. A test that spins up a second agent restores the route afterwards.
  router.register(AGENT, origin)

  return {
    stop: () => new Promise<void>(resolve => { agentServer.close(() => resolve()) }),
    identifier: AGENT,
    origin,
    sub: AGENT_ID,
    identityKey,
    signingKey,
    agentToken,
    jwks,
    keyMaterial,
    psFetch: router.route(createSignedFetch(keyMaterial, { signBody: true })),
    resourceFetch: router.route(createSignedFetch(keyMaterial)),
    presenting(token: string) {
      return router.route(createSignedFetch(async () => ({
        signingKey: signingKey.privateJwk,
        signatureKey: { type: 'jwt', jwt: token },
      })))
    },
  }
}

// ---------------------------------------------------------------------------
// The resource
// ---------------------------------------------------------------------------

/**
 * How the resource under test should mint the resource token, so a test can
 * make it misbehave in exactly one way and watch mockin catch it.
 */
export interface MintBehaviour {
  /** Drop `mission_s256` the person token carried — mission stripping. */
  stripMission?: boolean
  /** Claim a `mission_s256` the person token did not carry. */
  inventMission?: string
  /** Drop `tenant` the person token carried. */
  stripTenant?: boolean
  /** Replace `tenant` with something else. */
  overrideTenant?: string
  /** Sign the resource token with the polymorphic `EdDSA`. */
  alg?: string
  /** Name a `person_token_jti` this PS never issued. */
  forgePersonTokenJti?: string
  scope?: string
  lifetimeSeconds?: number
}

export interface ResourceOptions {
  router: LoopbackRouter
  /** The PS this resource sends resource tokens to — the `aud` it mints. */
  personServer: string
  /** Published in `/.well-known/aauth-resource.json`. */
  accessMode?: string
  /** Which token kinds `/api` accepts. Defaults to `['auth']`. */
  accept?: readonly TokenKind[]
  mint?: MintBehaviour
}

export interface ResourceCall {
  status: number
  headers: Headers
  body: unknown
}

export interface TestResource {
  readonly identifier: string
  readonly origin: string
  readonly signingKey: TestKey
  readonly jwks: { keys: JWK[] }
  /**
   * Base for published R3 URIs.
   *
   * `http://localhost:port/r3`, not the `https://rs.mockin.test` identifier,
   * because the PS fetches this URL for real — it is a document location, not
   * a server identifier, and no spec rule makes it one. `publishR3Document`
   * allows exactly `https://` or `http://localhost` for this reason.
   */
  readonly r3BaseUri: string
  /** Every R3 body this resource has served, in order. Byte-for-byte. */
  readonly r3Served: string[]
  /** Mutable, so one server can be re-pointed between assertions. */
  mint: MintBehaviour
  accept: readonly TokenKind[]
  accessMode: string | undefined
  /** True once the request reached the scope gate — the check that must NOT be
   *  reached when the wrong credential type is presented (item 5). */
  scopeGateReached: boolean
  /** The last per-call proposal this resource published. */
  readonly lastProposal: { r3_uri: string; r3_s256: string; document: R3Document } | undefined
  /** Fresh R3 store, empty served-bytes log. */
  resetR3(): void
  /**
   * Replace the bytes stored under an `r3_uri` while leaving the recorded
   * `s256` alone — the state a resource would be in if something between the
   * store and the wire re-serialized the document. `@aauth/resource` has no
   * code path that does this, which is the point.
   */
  tamperR3(uri: string, body: string): Promise<void>
  stop(): Promise<void>
}

const RESOURCE_SCOPE = 'read'

/** The class R3 document's vocabulary. One of R3 -02's seven. */
export const R3_VOCABULARY = 'urn:aauth:vocabulary:openapi'
/** The operation this resource treats as `r3_per_call` — sending mail is the
 *  canonical "approved in principle, not for any particular call" case. */
export const PER_CALL_OPERATION = { operationId: 'sendMessage' }

/**
 * A resource, as `@aauth/resource` intends one to be written.
 *
 * `GET /api` runs the full ladder: verify the HTTP signature, verify whatever
 * token the `Signature-Key` carried, and answer with the requirement that
 * moves the agent forward.
 *
 *   no token / agent token -> 401 `requirement=person-token`
 *   person token           -> mint a resource token, 401 `requirement=auth-token`
 *   auth token             -> 200
 */
export async function startResource(options: ResourceOptions): Promise<TestResource> {
  const { router, personServer } = options
  const signingKey = await ed25519Key('resource-1')

  const state = {
    mint: options.mint ?? {},
    accept: options.accept ?? (['agent', 'person', 'auth'] as const),
    accessMode: options.accessMode,
    scopeGateReached: false,
    r3Served: [] as string[],
    /**
     * The `jti` of the person token this resource most recently verified.
     * AAuth issue #90: a per-call challenge fires on a request carrying an
     * auth token, which has no `person_token_jti`, yet the resource token it
     * must issue makes that claim REQUIRED — so a resource has to retain the
     * person tokens it verified.
     */
    retainedPersonTokenJti: undefined as string | undefined,
    lastProposal: undefined as
      | { r3_uri: string; r3_s256: string; document: R3Document }
      | undefined,
  }

  // The R3 store. `MemoryR3Store` is the package's own conforming
  // implementation; a real resource backs this with KV.
  let r3Store = new MemoryR3Store()
  let r3BaseUri = ''

  const sign = (payload: Record<string, unknown>, header: Record<string, unknown>) =>
    new SignJWT(payload)
      .setProtectedHeader({ ...header, alg: state.mint.alg ?? header.alg } as never)
      .sign(signingKey.privateKey)

  const json = (res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}) => {
    res.writeHead(status, { 'content-type': 'application/json', ...headers })
    res.end(JSON.stringify(body))
  }

  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    void (async () => {
      const chunks: Buffer[] = []
      for await (const c of req) chunks.push(c as Buffer)
      const rawBody = Buffer.concat(chunks)
      const url = new URL(req.url ?? '/', RESOURCE)

      if (url.pathname === '/.well-known/aauth-resource.json') {
        return json(res, 200, {
          issuer: RESOURCE,
          // `name`, never `client_name` — RFC 7591's spelling appears nowhere
          // in the AAuth specs.
          name: 'e2e resource',
          jwks_uri: `${RESOURCE}/jwks.json`,
          ...(state.accessMode !== undefined ? { access_mode: state.accessMode } : {}),
        })
      }
      if (url.pathname === '/jwks.json') {
        return json(res, 200, { keys: [signingKey.publicJwk] })
      }

      const verifySignature = () => httpSigVerify(
        {
          method: req.method ?? 'GET',
          authority: req.headers.host ?? '',
          path: url.pathname,
          query: url.search.replace(/^\?/, '') || undefined,
          headers: req.headers as Record<string, string | string[]>,
          body: rawBody.length ? rawBody : undefined,
        },
        // Protocol -10: accept only fully-specified identifiers. `EdDSA` is
        // not in this set, at the HTTP-signature layer as well as the JWT one.
        { supportedAlgorithms: ['Ed25519'] },
      )

      // ---------------------------------------------------------------------
      // GET /r3/<key> — serve a published R3 document.
      //
      // AAuth-R3 §R3 Document Access Restriction: only the AS that is `aud` of
      // a resource token carrying this `r3_uri`, or the PS of the agent it was
      // issued to, may fetch. The entitled party is established from the
      // verified signature — `sig=jwks_uri`'s `id`, which is a server
      // identifier the signature proves, never a header the caller sets.
      // An agent presenting `sig=jwt` has no such identifier and is refused.
      // ---------------------------------------------------------------------
      if (url.pathname.startsWith('/r3/')) {
        const verified = await verifySignature()
        const signer = verified.verified ? verified.jwks_uri?.id : undefined
        const response = await serveR3Document({
          store: r3Store,
          key: `${r3BaseUri}/${url.pathname.slice('/r3/'.length)}`,
          signer,
        })
        if (response.status === 200) state.r3Served.push(response.body)
        res.writeHead(response.status, response.headers)
        // Serve the stored bytes verbatim. Never JSON.parse and re-stringify:
        // the hash is over these exact bytes.
        return res.end(response.body)
      }

      if (url.pathname !== '/api' && url.pathname !== '/authorize' && url.pathname !== '/invoke') {
        return json(res, 404, { error: 'not_found' })
      }

      const result = await verifySignature()

      if (!result.verified) {
        return json(res, 401, { error: 'signature_verification_failed', error_description: result.error }, {
          'aauth-requirement': buildAAuthHeader('agent-token'),
        })
      }
      if (!result.jwt?.raw) {
        return json(res, 401, { error: 'agent_token_required' }, {
          'aauth-requirement': buildAAuthHeader('agent-token'),
        })
      }

      let verified
      try {
        verified = await verifyToken({
          jwt: result.jwt.raw,
          httpSignatureThumbprint: result.thumbprint,
          resource: RESOURCE,
          accept: state.accept,
          fetch: router.fetch,
        })
      } catch (err) {
        const e = err as AAuthTokenError
        // Every token-verification failure is a 401-class rejection. It never
        // degrades into the 403 scope answer below — that is the whole point of
        // `accept` being a required parameter.
        return json(res, 401, { error: e.code, error_description: e.message }, {
          'aauth-requirement': buildAAuthHeader('agent-token'),
        })
      }

      if (verified.type === 'agent') {
        return json(res, 401, { error: 'person_token_required' }, {
          'aauth-requirement': buildAAuthHeader('person-token'),
        })
      }

      // ---------------------------------------------------------------------
      // POST /authorize — the R3 authorization request.
      //
      // The agent names the operations it wants (`r3_operations`, the shape
      // `@aauth/fetch --operations` sends). The resource writes an R3 document
      // describing exactly those, publishes it, and answers with a resource
      // token referencing it by `r3_uri` / `r3_s256`. The document itself never
      // travels in the token.
      // ---------------------------------------------------------------------
      if (url.pathname === '/authorize') {
        if (verified.type !== 'person') {
          return json(res, 401, { error: 'person_token_required' }, {
            'aauth-requirement': buildAAuthHeader('person-token'),
          })
        }
        const person = verified as VerifiedPersonToken
        state.retainedPersonTokenJti = person.jti
        const body = rawBody.length
          ? JSON.parse(rawBody.toString('utf8')) as {
            r3_operations?: R3OperationSet
            account?: string
          }
          : {}
        if (!body.r3_operations) return json(res, 400, { error: 'invalid_request' })

        const document: R3Document = {
          vocabulary: body.r3_operations.vocabulary,
          operations: body.r3_operations.operations,
          ...(body.account !== undefined ? { account: body.account } : {}),
          display: { summary: 'Read and send messages on your behalf' },
        }
        const published = await publishR3Document({
          document,
          baseUri: r3BaseUri,
          store: r3Store,
          // The `aud` of the resource token about to be minted, plus the
          // agent's PS. Nobody else may read this document.
          authorized: [personServer, person.iss],
        })

        const resourceToken = await createResourceToken(
          {
            resource: RESOURCE,
            audience: personServer,
            personToken: {
              iss: person.iss,
              sub: person.sub,
              jti: person.jti,
              ...(person.mission_s256 ? { mission_s256: person.mission_s256 } : {}),
              ...(person.tenant ? { tenant: person.tenant } : {}),
            },
            agentJkt: result.thumbprint,
            scope: state.mint.scope ?? RESOURCE_SCOPE,
            ...(body.account !== undefined ? { account: body.account } : {}),
            r3: { uri: published.r3_uri, s256: published.r3_s256 },
            kid: signingKey.kid,
          },
          sign,
        )
        return json(res, 200, {
          resource_token: resourceToken,
          r3_uri: published.r3_uri,
          r3_s256: published.r3_s256,
        })
      }

      // ---------------------------------------------------------------------
      // POST /invoke — call one R3 operation with an auth token.
      //
      //   operation in `r3_granted`  -> run it
      //   operation in `r3_per_call` -> build a proposal from the *concrete*
      //                                 parameters of this call, publish it,
      //                                 and challenge with a resource token
      //                                 that references it
      //   retry carrying `r3_s256`   -> recover the approved proposal and
      //                                 verify the presented parameters
      // ---------------------------------------------------------------------
      if (url.pathname === '/invoke') {
        if (verified.type !== 'auth') {
          return json(res, 401, { error: 'auth_token_required' }, {
            'aauth-requirement': buildAAuthHeader('agent-token'),
          })
        }
        const auth = verified as VerifiedAuthToken
        const body = JSON.parse(rawBody.toString('utf8')) as {
          operation: unknown
          parameters: Record<string, R3ParameterValue>
        }
        const inSet = (set: R3OperationSet | undefined) =>
          !!set?.operations?.some(op => JSON.stringify(op) === JSON.stringify(body.operation))

        // A retry: the auth token names an approved *proposal*.
        //
        // `r3_s256` alone does not say which — a class-grant auth token
        // carries the class document's hash. What distinguishes a proposal is
        // its REQUIRED `parameters`, so resolve the reference and look.
        const referenced = auth.r3_s256 ? await getR3ByHash(r3Store, auth.r3_s256) : null
        const isProposal = !!referenced && parseR3Record(referenced).parameters !== undefined
        if (isProposal) {
          try {
            const { parameters } = await verifyProposalParameters({
              store: r3Store,
              r3_s256: referenced!.s256,
              presented: body.parameters,
              operation: body.operation,
            })
            return json(res, 200, { ok: true, invoked: body.operation, approved: parameters })
          } catch (err) {
            const e = err as R3Error
            return json(res, 403, { error: e.code, error_description: e.message })
          }
        }

        if (inSet(auth.r3_granted)) {
          return json(res, 200, { ok: true, invoked: body.operation, via: 'r3_granted' })
        }

        if (inSet(auth.r3_per_call)) {
          const published = await publishProposal({
            vocabulary: R3_VOCABULARY,
            operation: body.operation,
            parameters: body.parameters,
            display: { summary: 'Send one message', detail: 'This exact message, once.' },
            store: r3Store,
            baseUri: r3BaseUri,
            authorized: [personServer, auth.ps],
          })
          state.lastProposal = {
            r3_uri: published.r3_uri,
            r3_s256: published.r3_s256,
            document: JSON.parse(published.body) as R3Document,
          }
          const resourceToken = await createResourceToken(
            {
              resource: RESOURCE,
              audience: personServer,
              personToken: {
                iss: auth.ps,
                sub: auth.sub,
                // §Resource Token Structure makes `person_token_jti` REQUIRED,
                // but a per-call challenge fires on a request carrying an
                // *auth* token, which has no such claim — AAuth issue #90. The
                // resource retains the person token it verified and re-uses its
                // jti; this test resource keeps exactly one.
                jti: state.retainedPersonTokenJti ?? '',
                ...(auth.mission_s256 ? { mission_s256: auth.mission_s256 } : {}),
                ...(auth.tenant ? { tenant: auth.tenant } : {}),
              },
              agentJkt: result.thumbprint,
              scope: state.mint.scope ?? RESOURCE_SCOPE,
              r3: { uri: published.r3_uri, s256: published.r3_s256 },
              kid: signingKey.kid,
            },
            sign,
          )
          return json(res, 401, { error: 'per_call_approval_required' }, {
            'aauth-requirement': buildAAuthHeader('auth-token', { resourceToken }),
          })
        }

        return json(res, 403, { error: 'insufficient_scope', error_description: 'operation not granted' })
      }

      if (verified.type === 'person') {
        const person = verified as VerifiedPersonToken
        state.retainedPersonTokenJti = person.jti
        const ref: PersonTokenReference = {
          iss: person.iss,
          sub: person.sub,
          jti: state.mint.forgePersonTokenJti ?? person.jti,
        }
        // Honest path: copy `mission_s256` and `tenant` through unchanged.
        // §Resource Token Structure — a resource MUST NOT omit either.
        if (person.mission_s256 && !state.mint.stripMission) ref.mission_s256 = person.mission_s256
        if (state.mint.inventMission) ref.mission_s256 = state.mint.inventMission
        if (person.tenant && !state.mint.stripTenant) ref.tenant = person.tenant

        const resourceToken = await createResourceToken(
          {
            resource: RESOURCE,
            audience: personServer,
            personToken: ref,
            agentJkt: result.thumbprint,
            scope: state.mint.scope ?? RESOURCE_SCOPE,
            ...(state.mint.overrideTenant ? { tenant: state.mint.overrideTenant } : {}),
            ...(state.mint.lifetimeSeconds ? { lifetime: state.mint.lifetimeSeconds } : {}),
            kid: signingKey.kid,
          },
          sign,
        )
        return json(res, 401, { error: 'auth_token_required' }, {
          'aauth-requirement': buildAAuthHeader('auth-token', { resourceToken }),
        })
      }

      // Auth token. Only here does the resource look at scope.
      state.scopeGateReached = true
      const scopes = (verified.scope ?? '').split(' ').filter(Boolean)
      if (!scopes.includes(RESOURCE_SCOPE)) {
        return json(res, 403, { error: 'insufficient_scope', scope: RESOURCE_SCOPE })
      }
      return json(res, 200, {
        ok: true,
        ps: verified.ps,
        sub: verified.sub,
        scope: verified.scope,
        ...(verified.tenant ? { tenant: verified.tenant } : {}),
        ...(verified.mission_s256 ? { mission_s256: verified.mission_s256 } : {}),
      })
    })().catch((err: Error) => {
      if (!res.headersSent) json(res, 500, { error: 'server_error', error_description: err.message })
    })
  })

  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
  const port = (server.address() as AddressInfo).port
  const origin = `http://127.0.0.1:${port}`
  // The PS dials this for real, so it must be a URL that resolves outside this
  // process. `localhost` rather than `127.0.0.1` because `publishR3Document`
  // requires https or `http://localhost` — an R3 document MUST be served over
  // HTTPS, with that one loopback exception for local development.
  r3BaseUri = `http://localhost:${port}/r3`
  router.register(RESOURCE, origin)

  return {
    identifier: RESOURCE,
    origin,
    r3BaseUri,
    signingKey,
    jwks: { keys: [signingKey.publicJwk] },
    get r3Served() { return state.r3Served },
    get lastProposal() { return state.lastProposal },
    resetR3() {
      state.r3Served.length = 0
      state.lastProposal = undefined
      // Documents are content-addressed, so the same request produces the same
      // URI in every test. A fresh store is the only real isolation.
      r3Store = new MemoryR3Store()
    },
    async tamperR3(uri, body) {
      const record = await r3Store.get(uri)
      if (!record) throw new Error(`no R3 record at ${uri}`)
      await r3Store.put(uri, { ...record, body })
      await r3Store.put(record.s256, { ...record, body })
    },
    get mint() { return state.mint },
    set mint(v) { state.mint = v },
    get accept() { return state.accept },
    set accept(v) { state.accept = v },
    get accessMode() { return state.accessMode },
    set accessMode(v) { state.accessMode = v },
    get scopeGateReached() { return state.scopeGateReached },
    set scopeGateReached(v) { state.scopeGateReached = v },
    stop: () => new Promise<void>(resolve => { (server as Server).close(() => resolve()) }),
  }
}

// ---------------------------------------------------------------------------
// Reading the wire
// ---------------------------------------------------------------------------

export async function callResource(fetchFn: FetchLike, path = '/api'): Promise<ResourceCall> {
  const res = await fetchFn(`${RESOURCE}${path}`, { method: 'GET' })
  const text = await res.text()
  let body: unknown = text
  try { body = JSON.parse(text) } catch { /* keep the text */ }
  return { status: res.status, headers: res.headers, body }
}

/** The `resourceToken` out of a `401 requirement=auth-token` challenge. */
export function resourceTokenFrom(headers: Headers): string {
  const header = headers.get('aauth-requirement')
  if (!header) throw new Error('response carried no AAuth-Requirement')
  const challenge = parseRequirementHeader(header)
  if (challenge.requirement !== 'auth-token' || !challenge.resourceToken) {
    throw new Error(`not an auth-token challenge: ${header}`)
  }
  return challenge.resourceToken
}

/**
 * A signed fetch that identifies itself as a **server**, via
 * `Signature-Key: sig=jwks_uri;id="…";dwk="…";kid="…"`.
 *
 * This is how a PS identifies itself when it fetches an R3 document: not with
 * an agent token, but with a signature whose key resolves at
 * `{id}/.well-known/{dwk}`. `id` is therefore a server identifier the
 * signature proves, which is what §R3 Document Access Restriction compares.
 *
 * Used here to sign as a party that authenticates correctly and is still not
 * entitled to the document.
 */
export function serverSignedFetch(
  router: LoopbackRouter,
  key: TestKey,
  id: string,
  dwk: string,
): FetchLike {
  return (url, init) => httpSigFetch(router.rewrite(url), {
    ...init,
    signingKey: key.privateJwk,
    signatureKey: { type: 'jwks_uri', id, kid: key.kid, dwk },
    // Exactly what a PS signs on an R3 GET.
    components: ['@method', '@authority', '@path', 'signature-key'],
  })
}

/** The parsed `AAuth-Requirement` of a response, or undefined. */
export function requirementOf(headers: Headers): AAuthChallenge | undefined {
  const header = headers.get('aauth-requirement')
  return header ? parseRequirementHeader(header) : undefined
}

export function claimsOf(jwt: string): Record<string, unknown> {
  return decodeJwtPayload(jwt)
}

export function headerOf(jwt: string): Record<string, unknown> {
  return decodeJwtHeader(jwt)
}

/** Mint a token of any shape, signed by any key — for the negative tests that
 *  need a credential no conformant issuer would produce. */
export async function forgeToken(
  key: TestKey,
  header: { alg?: string; typ: string },
  claims: Record<string, unknown>,
): Promise<string> {
  return new SignJWT(claims)
    .setProtectedHeader({ alg: SIGNING_ALG, kid: key.kid, ...header } as never)
    .sign(key.privateKey)
}

export { SIGNING_ALG, TOKEN_TYP, DWK, RESOURCE_SCOPE }
