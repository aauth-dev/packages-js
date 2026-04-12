# @aauth/mcp-server

Server-side AAuth for MCP. Verifies signed requests, validates agent and auth tokens, builds AAuth challenge headers, creates resource tokens, and manages 202 interaction flows.

See the [AAuth repo](https://github.com/hellocoop/AAuth) for protocol overview.

## Install

```bash
npm install @aauth/mcp-server
```

## Usage

### `verifyToken(options): Promise<VerifiedToken>`

Verifies a JWT from a signed request. Supports both `aa-agent+jwt` and `aa-auth+jwt` token types. Fetches issuer metadata and JWKS automatically (cached).

```ts
import { verifyToken } from '@aauth/mcp-server'

const result = await verifyToken({
  jwt: tokenFromSignatureKeyHeader,
  httpSignatureThumbprint: thumbprintFromVerifiedSignature,
})

if (result.type === 'agent') {
  // VerifiedAgentToken: iss, sub, cnf, iat, exp
  console.log(`Agent: ${result.sub}`)
}

if (result.type === 'auth') {
  // VerifiedAuthToken: iss, aud, agent, cnf, sub?, scope?, iat, exp
  console.log(`Authorized agent: ${result.agent}, scope: ${result.scope}`)
}
```

Throws `AAuthTokenError` with a spec-defined error code on failure:

| Code | Meaning |
|------|---------|
| `invalid_agent_token` | Agent token verification failed |
| `invalid_auth_token` | Auth token verification failed |
| `key_binding_failed` | Request signing key doesn't match token `cnf.jwk` |

### `buildAAuthHeader(requirement, params?): string`

Builds an `AAuth-Requirement` response header.

```ts
import { buildAAuthHeader } from '@aauth/mcp-server'

// 401 — require auth token
const header = buildAAuthHeader('auth-token', { resourceToken: '...' })
response.setHeader('aauth-requirement', header)

// 202 — require interaction
buildAAuthHeader('interaction', { url: 'https://example.com/interact', code: 'ABCD1234' })

// Simple levels (no params)
buildAAuthHeader('approval')
buildAAuthHeader('clarification')
buildAAuthHeader('claims')
```

### `buildAAuthAccessHeader(token): string`

Builds an `AAuth-Access` response header for two-party mode. The token is opaque to the agent — the resource wraps its own authorization state.

```ts
import { buildAAuthAccessHeader } from '@aauth/mcp-server'

response.setHeader('aauth-access', buildAAuthAccessHeader(wrappedToken))
```

### `parseCapabilitiesHeader(headerValue): Capability[]`

Parses an `AAuth-Capabilities` request header.

```ts
import { parseCapabilitiesHeader } from '@aauth/mcp-server'

const caps = parseCapabilitiesHeader(request.headers.get('aauth-capabilities'))
// ['interaction', 'clarification', 'payment']
```

### `parseMissionHeader(headerValue): Mission`

Parses an `AAuth-Mission` request header into a `Mission` object that can be passed directly to `createResourceToken`.

```ts
import { parseMissionHeader } from '@aauth/mcp-server'

const mission = parseMissionHeader(request.headers.get('aauth-mission'))
// { approver: 'https://ps.example', s256: '...' }
```

### `createResourceToken(options, sign): Promise<string>`

Creates an `aa-resource+jwt` token for inclusion in 401 AAuth challenges.

```ts
import { createResourceToken } from '@aauth/mcp-server'

const resourceToken = await createResourceToken(
  {
    resource: 'https://api.example.com',
    authServer: 'https://ps.example',      // PS URL (three-party) or AS URL (four-party)
    agent: 'aauth:claude@user.github.io',
    agentJkt: thumbprint,                  // JWK Thumbprint of agent's signing key
    scope: 'files.read',
    mission: parseMissionHeader(request.headers.get('aauth-mission')),  // optional
    lifetime: 300,                         // seconds, default 300
  },
  async (payload, header) => {
    // Sign the JWT with your resource server's key
    return signedJwtString
  }
)
```

### `InteractionManager`

Manages pending requests for 202 deferred response flows.

```ts
import { InteractionManager } from '@aauth/mcp-server'

const manager = new InteractionManager({
  baseUrl: 'https://api.example.com',
  pendingPath: '/pending',  // default
  codeLength: 8,            // default
  ttl: 600,                 // seconds, default
})

// Create a pending request (returns headers for 202 response)
const { headers, pending } = manager.createPending()
// headers: { Location, Retry-After, Cache-Control, AAuth }
// pending: { id, code, promise, resolve, reject }

// Resolve when the interaction completes
manager.resolve(pending.id, { granted: true })

// Or reject
manager.reject(pending.id, 'denied')

// Cleanup expired entries
manager.cleanup()
```

### `clearMetadataCache()`

Clears the cached issuer metadata and JWKS used by `verifyToken`.

```ts
import { clearMetadataCache } from '@aauth/mcp-server'

clearMetadataCache()
```

## License

MIT
