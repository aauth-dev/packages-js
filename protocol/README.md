# @aauth/protocol

The AAuth wire format, on its own. Header build/parse, `access_mode` planning,
protocol constants, and unverified JWT decoding. No I/O, no crypto, no runtime
dependencies.

Tracks `draft-hardt-oauth-aauth-protocol-11`.

```
npm install @aauth/protocol
```

## AAuth-Requirement

```ts
import { parseRequirementHeader, buildRequirementHeader, UnsupportedRequirementError }
  from '@aauth/protocol'

// resource side
res.setHeader('AAuth-Requirement', buildRequirementHeader({
  requirement: 'auth-token',
  resourceToken,
}))

// agent side
try {
  const challenge = parseRequirementHeader(res.headers.get('AAuth-Requirement')!)
} catch (e) {
  if (e instanceof UnsupportedRequirementError) {
    // MUST NOT treat the response as satisfiable. Surface e.value to the caller.
  }
}
```

Recognized values: `agent-token`, `person-token`, `auth-token`, `approval`,
`interaction`, `clarification`, `claims`. Anything else throws
`UnsupportedRequirementError`, carrying the raw `value`. For a `202` the caller
MAY keep polling `Location` in case a later response carries a value it knows.

`requirement=auth-token` requires a `resource-token` parameter and
`requirement=interaction` requires both `url` and `code`; a header missing one
is malformed and throws a plain `Error`. Unknown parameters are ignored.

## AAuth-Capabilities

```ts
buildCapabilitiesHeader(['interaction', 'clarification'])  // "interaction, clarification"
parseCapabilitiesHeader('interaction, quantum-consent')    // ["interaction"]
```

Parsing filters unrecognized values and never throws — recipients MUST ignore
what they do not recognize. Building does not filter: an agent unions its own
capabilities with the ones its PS reports, which may be newer than this library.

An absent header is not an empty one. When the header is absent, recipients MUST
NOT assume any capabilities.

## access_mode

`access_mode` in `/.well-known/aauth-resource.json` is advisory — the runtime
`AAuth-Requirement` is authoritative. `planAccessMode` gives an agent one of
three answers and never throws.

```ts
const plan = planAccessMode(metadata.access_mode, { hasPersonServer: false })

switch (plan.kind) {
  case 'undeclared':     // absent or unrecognized — call the resource anyway
  case 'satisfiable':    // plan.mode is reachable with this setup
  case 'unsatisfiable':  // skip the resource, show plan.reason
}
```

Unrecognized values are `undeclared`, not errors: the value space is the AAuth
Access Mode Value Registry, and an agent that stops on an unknown value breaks
every time a value is registered.

`unsatisfiable` comes from an agent token with no `ps` claim. Three of the five
modes reach a person server, and without one none of them can complete:

| Mode | No person server | Why |
| --- | --- | --- |
| `agent-token` | satisfiable | Identity only; no PS in the flow. |
| `session-token` | satisfiable | Resource-managed; the resource issues its own credential. |
| `person-token` | **unsatisfiable** | The agent must sign with a person token, which only a PS issues. |
| `auth-token` | **unsatisfiable** | The resource token is exchanged for an auth token at the PS. |
| `per-call` | **unsatisfiable** | Terminates in an auth token — the grant is the `r3_per_call` claim. |

## Constants

`TOKEN_TYP` (the four `typ` values), `DWK` (the four well-known key documents),
`SIGNING_ALG` — `Ed25519`, fully specified per RFC 9864. The polymorphic
`EdDSA` MUST NOT be used.

## JWT decoding

`decodeJwtHeader` and `decodeJwtPayload` parse a token's segments and throw on
anything malformed. **No signature verification.** They prove nothing; never
make a trust decision on their output.

## Not here

`AAuth-Mission` was removed in -11, along with its IANA registration. A mission
reaches a resource only inside a PS-issued token, as the `mission_s256` claim.
There are no mission header helpers in this package and there will not be.

## License

MIT
