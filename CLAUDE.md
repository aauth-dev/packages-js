# AAuth Utilities and Packages

This repo contains utilities and packages for AAuth (Agent Auth) — an agent-aware auth protocol for modern distributed systems.

This repo will evolve as we learn things. Expect experimentation.

## AAuth Specification

The evolving AAuth specification lives in a separate repo:
- Local path: `../AAuth-spec`
- GitHub: https://github.com/dickhardt/AAuth

Key spec documents:
- `README.md` — full specification overview
- `aauth-explainer.md` — explainer document
- `AAuth_Spec_Complete.md` — complete specification
- `draft-hardt-aauth.md` — IETF-style draft

## Publishing Packages

Packages are published to npm via GitHub Actions with provenance signing. Do NOT publish manually from the command line (except for the one-time bootstrap of a brand-new package — see below).

### Bootstrapping a new package

A package can only be configured as a trusted publisher on npm after it exists in the registry. So the very first version of a new package must be published manually, after which all future versions go through GitHub Actions.

1. Make sure the new package's `package.json` has the correct `name`, `version` (e.g., `0.0.1`), `publishConfig.access` (`"public"` for scoped packages), and `repository` fields.
2. Log in to npm locally: `npm login`.
3. From the package directory, publish the initial version: `npm publish` (add `--access public` if the package is scoped and you haven't set `publishConfig.access`).
4. Configure GitHub as a trusted publisher (requires npm ≥ 11):
   ```
   npm trust github <package-name> \
     --repository aauth-dev/packages-js \
     --file release.yml \
     --allow-publish
   ```
   After this, the `release.yml` workflow can publish via OIDC without an npm token. Verify with `npm trust list <package-name>`.
5. From this point on, never publish manually — bump the version and cut a GitHub Release as described below.

### Publishing a new version

Packages are versioned **independently** (NOT lockstep — there is no
"all package.json must match" rule, and the release tag is just a marker, not a
version). `release.yml` publishes each package only when its own
`package.json` version differs from what's on npm; unchanged packages are
skipped. Inter-package deps use caret ranges (`^x.y.z`), so bumping one package
doesn't force its dependents to bump.

To ship a change:

1. Bump the `version` in the `package.json` of **only the package(s) you
   changed** — from that package's directory run:
   ```
   npm version patch --no-git-tag-version
   ```
   (`minor`/`major` as appropriate. The `--no-git-tag-version` flag is
   REQUIRED: plain `npm version` would commit and tag the whole monorepo with
   a `vX.Y.Z` tag that belongs to one package — release tags here are
   date/time markers, not versions.) If you used a new feature of a sibling
   workspace package, also tighten that dependency's range (e.g.
   `"@aauth/mcp-agent": "^1.1.0"`).
2. Update the matching `version` (and any changed dep range) in
   `package-lock.json` **by hand** — edit the workspace entry's `version` field.
   **Do NOT run `npm install` to regenerate the lockfile on macOS**: it prunes
   the cross-platform `@aauth/hardware-keys-*` optional nodes (npm bug), which
   reintroduces the `Invalid Version` / catch-22 breakage. Verify with `npm ci`.
3. Commit and push to `main`.
4. Cut a GitHub Release with a **date/time tag** (the tag is a marker, not a
   version): `gh release create "$(date -u +%Y-%m-%d-%H%M)" --title ... --notes ...`.
5. `release.yml` runs tests, then publishes each changed package with
   `--provenance` via OIDC. Already-published versions are skipped.

The workflow is at `.github/workflows/release.yml`.

### hardware-keys is decoupled — and why

The `@aauth/hardware-keys` native packages (`hardware-keys/npm/{darwin-arm64,
darwin-x64,linux-x64-gnu,win32-x64-msvc}`) are built + published by
`hardware-keys.yml` and are **only** rebuilt/republished when `hardware-keys`'s
own version changes — the `check-hardware-keys` job in `release.yml` gates this.
A JS-only release leaves them at their published version, so the lockfile's
`@aauth/hardware-keys-*` nodes stay valid and `npm ci` passes.

This decoupling exists to avoid a **publish/lockfile catch-22**: `npm ci`
verifies each native package's integrity against an *already-published* npm
tarball, but under lockstep a version bump would require the lockfile to
reference natives that only get published *by the release itself* → the release's
test job (`npm ci`) fails before the natives exist. So: never bump
`hardware-keys` just to keep numbers aligned. If you *do* change hardware-keys,
let its workflow publish the natives first, then bump/release the JS packages.

If the lockfile's `@aauth/hardware-keys-*` nodes ever lose their `version`/
`integrity` (e.g. a macOS `npm install` pruned them), restore the top-level
`node_modules/@aauth/hardware-keys-*` entries with the published version +
`resolved` + `integrity` (see prior "Restore platform nodes" commits).
