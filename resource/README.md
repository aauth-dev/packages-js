# @aauth/resource

The resource-side reference implementation of [AAuth](https://github.com/dickhardt/AAuth). Verify
what an agent presents, mint what a resource issues, publish and enforce R3.

Formerly `@aauth/mcp-server`. It contains no MCP and never did — it is the library a resource uses,
whatever protocol the resource speaks.

Runs on Cloudflare Workers. This package imports no `node:*` built-ins; it uses only `crypto`,
`crypto.subtle`, `fetch`, `TextEncoder` and `TextDecoder`.

Header construction and parsing live in [`@aauth/protocol`](https://www.npmjs.com/package/@aauth/protocol)
and are re-exported here, so a resource has one import.

## Install

```bash
npm install @aauth/resource
```

## Verifying what the agent presented

```ts
import { verifyToken, AAuthTokenError } from '@aauth/resource'

const verified = await verifyToken({
  jwt: sig.jwt.raw,                       // from @hellocoop/httpsig
  httpSignatureThumbprint: sig.thumbprint,
  resource: 'https://notes.example',      // this resource's own identifier
  accept: ['auth'],                       // what THIS endpoint requires
})
```

`accept` is required and there is no default. A person token and a PS-issued auth token carry the
same `iss`, `dwk`, `aud`, `sub` and `cnf`; only `typ` distinguishes them. An endpoint that requires
authorization passes `['auth']`. Passing `['auth', 'person']` there accepts an identity assertion as
a grant, and the mistake fails open — so the check is a parameter you must state, not one you can
forget.

`verifyToken` performs: `typ` recognition → the `accept` check → required-claim structure → `exp`
in the future and `iat` not in the future → key binding (`cnf.jwk` against the HTTP signing key) →
`kid` selection and signature verification against the JWKS discovered at `{iss}/.well-known/{dwk}`
→ `iss` a valid HTTPS server identifier → `aud` equal to `resource`. Nothing is acted on before the
signature verifies.

The polymorphic `EdDSA` identifier is rejected in both the JWT header and `cnf.jwk`, per RFC 9864.

### Results

| `type` | Shape |
| --- | --- |
| `'agent'` | `iss`, `sub`, `jti?`, `ps?`, `parent_agent?`, `cnf`, `iat`, `exp`, `claims` |
| `'person'` | `iss`, `aud`, `sub`, `jti`, `mission_s256?`, `tenant?`, `cnf`, `iat`, `exp`, `claims` |
| `'auth'` | `iss`, `aud`, `ps`, `sub`, `scope?`, `account?`, `mission_s256?`, `tenant?`, `r3_uri?`, `r3_s256?`, `r3_granted?`, `r3_per_call?`, `cnf`, `iat`, `exp`, `claims` |

There is no `agent` claim in AAuth -11 and none is surfaced. A resource learns which agent it is
talking to from the agent token, and binds authorization to the key via `agent_jkt` / `cnf`.

`sub` is unique within the issuer, not globally. Treat `(iss, sub)` as the identity, treat `sub` as
opaque, and never match a `sub` from one issuer against a record established under another, however
the values compare.

### Errors

`AAuthTokenError` carries a stable `code`. Branch on `code`, never on `message`.

| Code | Meaning |
| --- | --- |
| `unsupported_token_type` | `typ` is not an AAuth token type |
| `token_type_not_accepted` | Recognized, but not allowed at this call site — including a person token where an auth token is required |
| `invalid_agent_token` / `invalid_person_token` / `invalid_auth_token` | Structure, discovery or signature failed |
| `token_expired` | `exp` is in the past |
| `aud_mismatch` | `aud` is not this resource |
| `key_binding_failed` | `cnf.jwk` is not the key that signed the request |
| `metadata_fetch_failed` | `{iss}/.well-known/{dwk}` could not be read |
| `invalid_configuration` | `accept` or `resource` was not supplied correctly |

## Challenging

```ts
import { buildAAuthHeader } from '@aauth/resource'

buildAAuthHeader('agent-token')    // 401 — present your agent token
buildAAuthHeader('person-token')   // 401 — obtain a person token from your PS and retry
buildAAuthHeader('auth-token', { resourceToken })
buildAAuthHeader('interaction', { url, code })   // 202
buildAAuthHeader('approval')
buildAAuthHeader('clarification')
buildAAuthHeader('claims')
```

A resource MUST have verified a person token before it issues a resource token, and MUST challenge
with `requirement=person-token` when it has not.

`buildMissionHeader`, `parseMissionHeader` and the `AAuthMission` type are gone. The `AAuth-Mission`
header and its IANA registration were removed in -11. A mission reaches a resource only inside a
PS-issued token, as `mission_s256`.

## Minting a resource token

```ts
import { createResourceToken } from '@aauth/resource'

const resourceToken = await createResourceToken(
  {
    resource: 'https://notes.example',   // iss
    audience: psUrl,                     // aud: the PS (three-party) or the AS (four-party)
    personToken: verifiedPersonToken,    // ps, sub, person_token_jti, mission_s256, tenant come from here
    agentJkt: sig.thumbprint,
    scope: 'notes.read notes.write',
    kid: publicJwk.kid,
    r3: { uri: r3_uri, s256: r3_s256 },  // optional; both or neither
    missionExpiresAt,                    // optional clamp
  },
  async (payload, header) => signJwt(header, payload, privateKey),
)
```

The header handed to your signer is `{ alg: 'Ed25519', typ: 'aa-resource+jwt', kid? }`. Sign it as
given — `alg` is the fully-specified RFC 9864 identifier, and the polymorphic `EdDSA` MUST NOT be
used.

`mission_s256` is copied from the person token unchanged and is REQUIRED when the person token
carried one; a resource MUST NOT omit it. The PS resolves the person token by `person_token_jti` and
compares, so dropping it is detected as mission stripping.

`clampToMission(exp, missionExpiresAt)` is exported for anything else a resource derives from a
mission-scoped token: no token carrying `mission_s256` may outlive its mission.

## R3 documents

```ts
import { publishR3Document, serveR3Document } from '@aauth/resource'

const { r3_uri, r3_s256 } = await publishR3Document({
  document: {
    vocabulary: 'urn:aauth:vocabulary:mcp',
    operations: [{ tool: 'create_note' }],
    display: { summary: 'Create notes in your notebook' },
  },
  baseUri: 'https://notes.example/r3',
  store,
  authorized: [psUrl, agentToken.ps],   // see below
})
```

**Serialize once, serve those exact bytes.** `r3_s256` is the SHA-256 of the bytes as served, with
no canonicalization step. Any re-stringify — middleware that parses and re-encodes JSON, a framework
`json()` helper, CDN minification, key reordering — changes the bytes and breaks hash verification at
the PS and AS. `publishR3Document` serializes once and stores the result; `serveR3Document` returns
those bytes verbatim. Write the returned `body` to the wire as-is; do not pass it through a JSON
response helper.

R3 -02 removed the `version` field. Including one is rejected.

### The store you supply

```ts
interface R3Store {
  get(key: string): Promise<R3Record | null>
  put(key: string, record: R3Record, ttlSeconds?: number): Promise<void>
}

interface R3Record {
  uri: string          // the r3_uri this is served at
  s256: string         // BASE64URL(SHA-256(body)) — the r3_s256 claim
  body: string         // the exact bytes to serve
  authorized: string[] // server identifiers entitled to fetch it
  createdAt: number
  expiresAt?: number
}
```

Two methods, both keyed by opaque string. Back it with Workers KV
(`put(key, JSON.stringify(record), { expirationTtl })` / `get(key, 'json')`), Redis, or anything
else — `body` is a string and survives a JSON round trip unchanged. `MemoryR3Store` is a conforming
in-memory implementation for tests and single-process deployments.

Each record is written under two keys: its `s256` and its `uri`. The fetch path knows only the URI;
the per-call retry path knows only the hash from the auth token. Both resolve.

### Access restriction

Agents must never read an R3 document — agent opacity depends entirely on it. Exactly two parties
are entitled:

- the AS named in the `aud` of a resource token carrying that `r3_uri`; and
- the PS named by the `ps` claim of the agent token the agent presented.

Pass both to `publishR3Document` as `authorized`. In three-party access they are the same party.

```ts
const res = await serveR3Document({ store, key: url.pathname.split('/').pop()!, signer })
// 401 unsigned · 403 wrong signer · 404 unknown · 200 with the exact stored bytes
```

`signer` is the server identifier established from the *verified* HTTP Message Signature on the
fetch — not a header the caller controls. Comparison is exact string equality.

## Per-call proposals

An `r3_per_call` operation is authorized in principle but not for any specific call. When the agent
invokes one, build a proposal: a full R3 document scoped to that one invocation, carrying a REQUIRED
`parameters` object.

```ts
import { publishProposal, digestParameter, verifyProposalParameters } from '@aauth/resource'

// 1. Challenge
const proposal = await publishProposal({
  vocabulary: 'urn:aauth:vocabulary:mcp',
  operation: { tool: 'send_email' },
  parameters: {
    to: 'mom@example.com',
    subject: 'Dinner Sunday?',
    body: await digestParameter(emailBody, { media_type: 'text/plain' }),
  },
  display: { summary: 'Send an email as you', detail: '## Action\nSend an email\n\n## To\nmom@example.com' },
  store,
  baseUri: 'https://mail.example/r3',
  authorized: [asUrl, agentToken.ps],
})
// mint a resource token with r3: { uri: proposal.r3_uri, s256: proposal.r3_s256 }

// 2. …the AS evaluates the parameters, the PS renders `display`, the agent retries…

// 3. Enforced retry
await verifyProposalParameters({
  store,
  r3_s256: authToken.r3_s256!,
  presented: call.arguments,
  operation: { tool: 'send_email' },
})
```

`verifyProposalParameters` rejects on any difference: a parameter the proposal did not carry, an
approved parameter missing from the call, a structural value that does not deep-equal the approved
one, or a digest parameter whose bytes do not satisfy `BASE64URL(SHA-256(presented)) === s256`. An
approval to email one recipient cannot be replayed against another.

`digestParameter` keeps a large or sensitive value out of every token and away from the PS: only the
hash and a short excerpt appear in the proposal. The full bytes travel agent → resource at call
time, where they are verified against the digest.

The token carries only `r3_uri` / `r3_s256`, never the parameters.

## Interaction (202 deferred responses)

```ts
import { InteractionManager } from '@aauth/resource'

const manager = new InteractionManager({
  baseUrl: 'https://notes.example',
  interactionUrl: 'https://notes.example/interact',
})

const { headers, pending } = manager.createPending()
// headers: Location, Retry-After, Cache-Control, AAuth-Requirement
manager.resolve(pending.id, { granted: true })
```

This is the only part of the package with a transitive `node:crypto` dependency, via
`@aauth/interaction-code`. On Workers it needs `nodejs_compat`, which workerd supports.

## License

MIT
