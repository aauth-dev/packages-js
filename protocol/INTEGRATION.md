# Integrating `@aauth/protocol`

Four steps. None of them are in this commit — every file they touch is shared
with the other AAuth -11 work packages, so WP-1 left them alone rather than
collide. Apply them in one integration pass.

The package is `protocol/`, version `1.0.0`, ESM. Its one runtime dependency is
`@hellocoop/httpsig ^2.1.0`, for the RFC 8941 structured field parser on that
package's `/structured-fields` subpath; every consumer of `@aauth/protocol`
installs it anyway. Its only devDependencies are `@types/node ^20.0.0` and
`typescript ^5.0.0`, both already in the tree at the same ranges as every
sibling package.

---

## 1. Workspaces entry — `packages-js/package.json`

Add `"protocol"` to the `workspaces` array. It has no dependencies on any
sibling, so position does not matter; first is fine, and matches the fact that
`@aauth/agent` and `@aauth/resource` depend on it rather than the reverse.

```json
  "workspaces": [
    "protocol",
    "interaction-code",
    "local-keys",
    "bootstrap",
    "hardware-keys",
    "mcp-agent",
    "mcp-server",
    "mcp-stdio",
    "mcp-openclaw",
    "fetch"
  ]
```

## 2. Lockfile node — `packages-js/package-lock.json`

Two entries, matching how every other workspace appears:

```json
    "node_modules/@aauth/protocol": {
      "resolved": "protocol",
      "link": true
    },
```

```json
    "protocol": {
      "name": "@aauth/protocol",
      "version": "1.0.0",
      "license": "MIT",
      "devDependencies": {
        "@types/node": "^20.0.0",
        "typescript": "^5.0.0"
      }
    },
```

No `dependencies` key — the absence is asserted by a test in
`protocol/src/index.test.ts`, so do not add one.

Verify with **`npm ci`**, not `npm install`. `npm install` is forbidden on macOS
in this repo: it prunes the cross-platform `@aauth/hardware-keys-*` optional
nodes. See `packages-js/CLAUDE.md`.

## 3. Vitest alias — `packages-js/vitest.config.ts`

**Required.** Without it, any sibling test that imports the package by name
fails to resolve. WP-3 (`@aauth/agent`) and WP-4 (`@aauth/resource`) both
consume `@aauth/protocol` and both need this line.

Add to the `resolve.alias` map, exactly:

```ts
      '@aauth/protocol': path.resolve(__dirname, 'protocol/src/index.ts'),
```

In place, the map reads:

```ts
  resolve: {
    alias: {
      '@aauth/protocol': path.resolve(__dirname, 'protocol/src/index.ts'),
      '@aauth/mcp-server': path.resolve(__dirname, 'mcp-server/src/index.ts'),
      '@aauth/mcp-agent': path.resolve(__dirname, 'mcp-agent/src/index.ts'),
      '@aauth/mcp-openclaw': path.resolve(__dirname, 'mcp-openclaw/src/index.ts'),
      '@aauth/local-keys': path.resolve(__dirname, 'local-keys/src/index.ts'),
      '@aauth/hardware-keys': path.resolve(__dirname, 'hardware-keys/index.js'),
    },
  },
```

The other WPs rename `mcp-server` and `mcp-agent` to `resource` and `agent`;
those key changes are theirs to report. This entry is additive and does not
conflict with them.

`protocol/src/*.test.ts` needs no alias — the tests import by relative path, so
they pass today from the worktree root with nothing else configured.

## 4. npm trusted-publisher bootstrap

`@aauth/protocol` is a brand-new package name, so **`release.yml` cannot publish
it until the first version exists on the registry.** Per
`packages-js/CLAUDE.md`, publish `1.0.0` by hand, then register the trusted
publisher:

```
npm trust github @aauth/protocol \
  --repository aauth-dev/packages-js \
  --file release.yml \
  --allow-publish
```

Do this before the wave's coordinated release, or the release run fails on this
package and leaves `@aauth/agent` and `@aauth/resource` pointing at a dependency
that does not exist.

---

## Downstream dependency range

Packages consuming this one should declare:

```json
    "@aauth/protocol": "^1.0.0"
```

WP-3 (`@aauth/agent` 3.0.0) and WP-4 (`@aauth/resource` 2.0.0) each need it.
Whether they declare it is their report to make; this note records the range so
all three agree.
