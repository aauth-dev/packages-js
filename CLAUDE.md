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

Packages are published to npm via GitHub Actions with provenance signing. Do NOT publish manually from the command line.

To publish a new version:

1. Bump the version in all `package.json` files (root + all 5 workspace packages must match)
2. Commit and push to `main`
3. Create a GitHub Release with tag `vX.Y.Z` matching the package version (e.g., `gh release create v0.2.1 --title "v0.2.1" --notes "..."`)
4. The `release.yml` workflow runs tests, verifies versions, builds, and publishes all packages with `--provenance`

The workflow is at `.github/workflows/release.yml`.
