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

1. Bump the version in all `package.json` files (root + all 5 workspace packages must match)
2. Commit and push to `main`
3. Create a GitHub Release with tag `vX.Y.Z` matching the package version (e.g., `gh release create v0.2.1 --title "v0.2.1" --notes "..."`)
4. The `release.yml` workflow runs tests, verifies versions, builds, and publishes all packages with `--provenance`

The workflow is at `.github/workflows/release.yml`.
