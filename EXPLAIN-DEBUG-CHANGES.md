# fetch: `--explain` vs `--debug` output modes

> Re-applied on top of the upstream "CLI UX rework" (#12, v1.0.0). An earlier
> draft was written against the pre-rework code, then reverted (stashed) and
> reworked against current `main`.

## Goal

Split `@aauth/fetch`'s wire-visibility output into two purpose-built modes so it
works better for **explaining** a call vs **debugging** it — and surface request
**and** response **bodies** (the reworked `-v` showed headers only).

## The two modes

| Flag | Purpose | Output (stderr; response body still goes to stdout) |
|------|---------|------|
| `--explain` | Teaching view — "what `-v` used to be" | Per-step pretty-JSON objects: `type` (request\|response\|info), `step` (pairs a request with its response), a `description`, method/url/status, the real RFC 9421 signed headers, **and bodies**. |
| `--debug` (= `-v` / `--verbose`) | Raw wire view | Every HTTP hop as a `{ request }` object (method, url, headers, body) then a `{ response }` object (status, headers, body) — response nested under a **property**, not tagged with a `type`; no descriptions, no info events. |

- `-v` / `--verbose` are **aliases of `--debug`** (per decision).
- Response/request bodies are plumbed through **every** hop.

## Implementation

### `mcp-agent` (plumb bodies on every hop)
The rework already captured the signed request (`onSigned`/`CapturedSent`, which
includes the body) and peeked *some* response bodies into events — but only
per-status (401 challenge, 202 token, metadata-ok). Made the peek **unconditional
when a listener is attached** and filled `request_body` at every `:done`
emission. `AAuthEvent` already had `request_body`; no type change needed.
- `aauth-fetch.ts`: `signed_request` and `retry_with_auth_token` — peek body
  always (gated on `onEvent`), add `request_body`.
- `token-exchange.ts`: `ps_token_request` and `ps_metadata_request` — peek
  always, add `request_body`.
- `deferred.ts`: `consent_poll` — import `peekResponseBody`, peek body, add
  `request_body`.

### `fetch/src/render.ts`
- Renamed `makeVerboseRenderer` → **`makeExplainRenderer`**; it now also emits
  `body` (parsed from the event's `request_body` / `response.body` strings) on
  the request and response objects.
- Added **`makeDebugRenderer`**: raw `{ request }` / `{ response }` per hop with
  bodies; skips `start` (buffers method/url) and `info` events; no
  step/description vocabulary.
- Added `bodyForDisplay` / `requestBody` / `responseBody` helpers (JSON-parse a
  body string for display, else leave raw).

### `fetch/src/args.ts`
- `FetchArgs`: removed `verbose`, added `explain` and `debug`.
- Parsing: `--explain` → `explain`; `--debug` / `--verbose` / `-v` → `debug`.

### `fetch/src/handlers.ts`
- `verboseRenderer(verbose)` → `eventRenderer(args)` — picks
  `makeExplainRenderer` (explain) or `makeDebugRenderer` (debug), else undefined.
- The handler-driven signed calls (`handleAuthorize`, `handlePreAuthed`,
  `handleAgentOnly`) emit their own events; added a `peekBodyText` + `doneResponse`
  helper so those events carry the response body, and set `request_body` from the
  captured sent request — so bodies appear in agent-only / pre-authed / authorize
  too, not just the full flow.
- `makeOnInteraction`: suppress the plain "Opening …" line when **either**
  renderer is active (was keyed on `verbose`).
- All four handler signatures: `verbose: boolean` → `explain: boolean; debug: boolean`.

### `fetch/src/help.ts`
- `OUTPUT` section documents `--explain` and `--debug, -v, --verbose`.

### Tests
- `render.test.ts`: import/describe → `makeExplainRenderer`; added body-plumbing
  tests and a `makeDebugRenderer` block.
- `args.test.ts`: defaults + `-v/--verbose/--debug → debug` + `--explain` tests.
- `handlers.test.ts`: `verbose:false` → `explain:false`; the old `-v` test split
  into an `--explain` test (asserts description + body) and a `--debug` test
  (asserts raw `{request}`/`{response}` + body, no description/type).
- `json-input.test.ts`: `verbose` → `explain`/`debug`.

## Verification
- `mcp-agent`: 64 tests pass; `tsc` build clean.
- `fetch`: 108 tests pass; `tsc --noEmit` clean; `npm run build` clean.
- Live against `https://whoami.aauth.dev?scope=openid+profile`:
  - `--debug` → raw `{request}`/`{response}` per hop with full signed headers
    and bodies (401 `auth_token_required`, PS metadata, …).
  - `--explain` → descriptive per-step objects (type/step/description) + headers
    + bodies, including the `challenge` info event.

## Lockfile fix (applied)
`npm install`/`npm ci` were broken on `main` under npm 11 with `Invalid Version`.
Cause: commit `c6fe394 "Bump all packages to 1.0.0"` regenerated
`package-lock.json` on macOS, which prunes cross-platform optional deps (npm bug
#4828), leaving four `@aauth/hardware-keys-*` nodes as bare `{ "optional": true }`
with no `version`. npm 11 is stricter than npm 10 and hard-errors on these. Not
caused by the npm 11 upgrade — the malformed lockfile was the trigger. The team
has hand-fixed this before (`62b79b0`, `e9ddb5f`, `aecdb52`).

Fix (same pattern as `62b79b0`, for 1.0.0): removed the four bare
`hardware-keys/node_modules/@aauth/hardware-keys-*` placeholders and added proper
top-level `node_modules/@aauth/hardware-keys-*` nodes with the published 1.0.0
`resolved`/`integrity`/`cpu`/`os` (+`libc: [glibc]` for linux). Verified: `npm ci`
+ build + 64 mcp-agent / 108 fetch tests all pass on npm 11.16.0. This also
reinstalled `@hellocoop/httpsig@1.6.0` properly from the lockfile (superseding the
earlier manual tarball swap).

Note: re-running `npm install` on macOS may re-prune these nodes (the same bug),
so don't regenerate the lockfile on macOS without re-restoring them.

- Workspace dists are consumed via symlink, so after editing `mcp-agent` or
  `local-keys` you must `npm run build` them before building/testing `fetch`.

## Follow-ups (not done)
- `--debug` response headers are still the AAuth-relevant subset
  (`summarizeResponseHeaders`), since that's what the event stream carries.
  Full response headers for the raw view would need the event payload to carry
  all headers and the renderer to filter — deferred.
- `www/src/lib/walkthrough.md` references `-v` for "each event's description
  field" — that's now `--explain` (descriptions), not `-v` (= `--debug`, raw).
  Consider updating the walkthrough.
