# @aauth/call-log

One log record per HTTP call between AAuth roles, written at each end. The
AAuth call log (`monitor.aauth.dev`) joins the caller's and the callee's record
on `call_id` and shows one row: who called whom, the request, the response.

The record is `aauth.call`, specified in `aauth-dev/monitor`
`plan/CALL_RECORD.md`. No dependencies. Runs in Cloudflare Workers
(`nodejs_compat`) and Node.

## What it does

- **Tokens are logged as `{ type, payload }`** — the JWT's `typ` header and its
  claims — wherever they appear: in `signed` and in place of the JWT string in
  a body, at any depth. Never the JWT, so no log holds a presentable token.
- **Bodies are logged.** JSON bodies as values; anything else as its content
  type and size. A record over 30 KB has its larger body cut to text and
  `truncated: true`.
- **`call_id`** is base64url SHA-256 of the `Signature` header. Both ends hold
  it, so their records join with no new header on the wire.
- **`parent`** is the call being handled when an outbound call is made. It is
  carried in AsyncLocalStorage from the middleware to any logged fetch in its
  async continuation, so call sites pass nothing. Where the chain is broken on
  purpose — a queue consumer, an alarm — pass `parent` yourself.
- **Levels:** 30; 40 for a 4xx that is not a challenge, a peer's 5xx, or a
  fetch that threw; 50 only for a 5xx the logging party answered itself.

## The host

```ts
import { callLogMiddleware, loggedFetch, nameAgent, type CallLogHost } from '@aauth/call-log'

const host = (c: Context): CallLogHost => ({
  origin: c.env.ORIGIN,           // this party's server identifier
  role: 'resource',               // agent | resource | ps | as
  log: (record) => emit(c, record), // your event sink: adds service, timestamp, event_id
  defer: (p) => c.executionCtx.waitUntil(p),
})
```

`log` is called once per record, never awaited, wrapped in try/catch. Bodies
are read from clones inside `defer`, after the response has gone.

## The callee side

```ts
app.use('*', async (c, next) => callLogMiddleware(host(c))(c, next))
```

One record per request, skipping `OPTIONS`, `HEAD`, `/.well-known/*`,
`/health` and `/openapi.json` (`skip` overrides). The caller is named from
`Signature-Key` without verification, so a refused call still says who
called. A person token names no agent; when your verifier resolves one, say so:

```ts
nameAgent(verified.agent_id)
```

## The caller side

With `@aauth/agent`'s `createSignedFetch`, which reports the on-wire request
through `onSigned`:

```ts
const psFetch = loggedFetch(
  (onSigned) => createSignedFetch(keyMaterial, { signBody: true, onSigned }),
  host(c),
  { to_role: 'ps' },
)
```

`makeFetch` is called once per call, so concurrent calls never swap reports.
With `@hellocoop/httpsig`'s `fetch`:

```ts
const send = loggedHttpsigFetch(httpsigFetch, host(c), { to_role: 'as' })
const res = await send(url, { method: 'POST', body, signingKey, signatureKey })
```

For a fetch you cannot wrap, `failedFetch(host, { url, status | error })`
records a failure.

## Pieces

`callIdOf`, `tokenOf`, `tokenize`, `signerOf`, `paramsOf`, `errorOf`,
`levelOf`, `partOf`, `cap`, `buildRecord`, `targetOf` are exported for a host
that builds records its own way (Wallet's Fastify hooks do).
