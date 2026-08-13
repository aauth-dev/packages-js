# @aauth/agent

The agent-side AAuth protocol library. Signs HTTP requests, obtains person tokens, handles AAuth challenge-response flows, exchanges resource tokens for auth tokens at the person server, and polls 202 deferred responses.

Renamed from `@aauth/mcp-agent`: the package contains no MCP and never did. Its only runtime dependencies are [`@aauth/protocol`](../protocol) and `@hellocoop/httpsig`.

Part of [aauth-dev/packages-js](https://github.com/aauth-dev/packages-js). Protocol spec: [dickhardt/AAuth](https://github.com/dickhardt/AAuth).

## Install

```bash
npm install @aauth/agent
```

## Usage

### `createAAuthFetch(options): FetchLike`

Creates a protocol-aware fetch that handles the full AAuth flow: signs requests, obtains a person token when a resource challenges with `requirement=person-token`, parses 401 `AAuth-Requirement` challenges, exchanges resource tokens with the person server, caches auth tokens, handles `AAuth-Access` session tokens, and retries.

```ts
import { createAAuthFetch } from '@aauth/agent'

const fetch = createAAuthFetch({
  getKeyMaterial: async () => ({
    signingKey: privateKeyJwk,
    signatureKey: { type: 'jwt', jwt: agentToken }
  }),
  // Person server — the `ps` claim of the agent token.
  authServerUrl: 'https://ps.example',
  // Optional: declare protocol capabilities
  capabilities: ['interaction', 'clarification'],
  // Optional: the mission the agent is operating under, as the base64url
  // SHA-256 of the approved mission blob. Forwarded when a person token is
  // requested; it then flows person token → resource token → auth token.
  missionS256: 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
  // Optional callbacks
  onInteraction: (url, code) => {
    console.log(`Visit ${url}?code=${code}`)
  },
  onClarification: async (question) => {
    return prompt(question)
  },
  // Optional hints for the person server
  justification: 'Read project files',
  loginHint: 'user@example.com',
  tenant: 'acme.com',
  domainHint: 'acme.com',
})

const response = await fetch('https://resource.example/api')
```

There is no `AAuth-Mission` header in protocol -11 — it and its IANA registration were removed. A mission reaches a resource only inside a PS-issued token, as the `mission_s256` claim.

### `requestPersonToken(options): Promise<PersonTokenResult>`

Requests a person token from the PS's `person_token_endpoint`. A person token identifies the person the agent acts for to one resource. A resource MUST have verified one before it issues a resource token, and the agent MUST present one on every authorization endpoint request.

```ts
import { requestPersonToken } from '@aauth/agent'

const { personToken, expiresIn } = await requestPersonToken({
  signedFetch: psSignedFetch,          // createSignedFetch(..., { signBody: true })
  personServerUrl: 'https://ps.example',
  resource: 'https://resource.example',
  missionS256: '...',                  // optional
  subagentToken: '...',                // optional — parent requesting for a sub-agent
  onInteraction: (url, code) => { /* the PS may ask the person first */ },
})
```

The request is a signed POST presenting the agent token via `Signature-Key: sig=jwt;jwt="…"`, with body `{resource, mission_s256?, subagent_token?}`. A `202` with `requirement=interaction` is polled at its `Location` like any other deferred response. `upstream_token` (call chaining) is not implemented.

Present the token in place of the agent token:

```http
Signature-Key: sig=jwt;jwt="<person token>"
```

### `createPersonTokenCache(options): PersonTokenCache`

Caches person tokens per `(resource, mission_s256)` — a person token is scoped to one resource and, when it carries `mission_s256`, to one mission.

```ts
import { createPersonTokenCache } from '@aauth/agent'

const personTokens = createPersonTokenCache({
  signedFetch: psSignedFetch,
  personServerUrl: 'https://ps.example',
})

const token = await personTokens.get('https://resource.example', missionS256)

// One rotation of the agent's signing key invalidates every cached token at
// once — they all bind that key through `cnf`. Flush and re-request lazily.
personTokens.clear()
```

`set(resource, missionS256, token, expiresIn)` seeds a token obtained elsewhere, such as the `person_tokens` map a PS returns with a mission approval.

### `createSignedFetch(getKeyMaterial, options?): FetchLike`

Creates a fetch that signs requests with HTTP Message Signatures but does not handle AAuth challenges. Use this when you only need request signing.

```ts
import { createSignedFetch } from '@aauth/agent'

const signedFetch = createSignedFetch(async () => ({
  signingKey: privateKeyJwk,
  signatureKey: { type: 'hwk' }
}), {
  capabilities: ['interaction'],
})

// For PS and AS endpoints: a request carrying a body additionally signs
// `content-digest` and `content-type`.
const psSignedFetch = createSignedFetch(getKeyMaterial, { signBody: true })
```

Set `signBody` only for PS and AS endpoints. Resources declare what they need through `additional_signature_components` in their metadata, so a blanket body mandate toward a resource would be wrong.

### `exchangeToken(options): Promise<TokenExchangeResult>`

Exchanges a resource token for an auth token at the person server. Handles metadata discovery (`/.well-known/aauth-person.json`), 202 deferred responses, and interaction polling.

```ts
import { exchangeToken } from '@aauth/agent'

const { authToken, expiresIn } = await exchangeToken({
  signedFetch: psSignedFetch,
  authServerUrl: 'https://ps.example',
  resourceToken: '...',
  justification: 'Read project files',
})
```

The auth token request has no mission parameter — the mission reaches the PS inside the resource token, which copied it from the person token.

### `fetchAuthServerMetadata(options)` / `resolveAuthServerMetadata(options)`

Fetches and validates `/.well-known/aauth-person.json`. Both `auth_token_endpoint` (renamed from `token_endpoint` in -11) and `person_token_endpoint` (new in -11) are REQUIRED; a person server publishing neither cannot complete a flow, and the document is rejected. `resolveAuthServerMetadata` returns a caller-supplied cached copy when there is one.

### `pollDeferred(options): Promise<DeferredResult>`

Polls a 202 Location URL until a terminal response. Handles `Retry-After`, `Prefer: wait`, clarification chat, and interaction codes.

```ts
import { pollDeferred } from '@aauth/agent'

const { response, error } = await pollDeferred({
  signedFetch,
  locationUrl: 'https://ps.example/pending/abc123',
  interactionCode: 'ABCD1234',
  onInteraction: (url, code) => { /* show to user */ },
  maxPollDuration: 900, // seconds, default 900
})
```

## Protocol primitives

Header parsing (`parseRequirementHeader`, `buildCapabilitiesHeader`, …), `access_mode` planning, token `typ` and `dwk` constants, and JWT decoding live in [`@aauth/protocol`](../protocol). This package consumes them and defines none of them.

## Key Material Callback

All signing functions take a `GetKeyMaterial` callback. This decouples key management from the protocol — you provide keys however you want:

```ts
type GetKeyMaterial = () => Promise<{
  signingKey: JsonWebKey          // Ed25519 private key for HTTP signatures
  signatureKey:
    | { type: 'jwt', jwt: string }  // agent, person, or auth token
    | { type: 'hwk' }               // bare public key (pseudonym)
}>
```

For local development, use [`@aauth/local-keys`](../local-keys) to provide this callback from the OS keychain.

## License

MIT
