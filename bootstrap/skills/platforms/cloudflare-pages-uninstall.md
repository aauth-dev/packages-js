---
name: cloudflare-pages-uninstall
description: Remove the published AAuth JWKS and agent metadata from Cloudflare Pages
when: User is uninstalling an AAuth agent provider whose JWKS is published to Cloudflare Pages — the bootstrap uninstall skill loads this skill to take down the remote files before deleting local keys
agentUrlPattern: project.pages.dev or custom domain
---

# Skill: Remove AAuth keys from Cloudflare Pages

The bootstrap `uninstall` skill loads this skill BEFORE deleting local keys, so the published JWKS goes down before the local signing key does. End state: both `<agent-url>/.well-known/jwks.json` and `aauth-agent.json` return 404.

## Prerequisites

- `wrangler` CLI is authenticated (`npx wrangler whoami` succeeds), OR a git repo connected to the Cloudflare Pages project
- The agent URL (from `npx @aauth/bootstrap list`) — either `https://project-name.pages.dev` or a custom domain

## Path A — git-connected project (preferred when available)

### 1. Locate or clone the source repo

Find the local clone of the repo that Cloudflare Pages deploys from. The hosting metadata in `~/.aauth/config.json` may name it; otherwise ask the user.

### 2. Sync, verify, delete

```bash
cd <repo>
git fetch origin
git pull --ff-only
ls -la .well-known/ 2>/dev/null
git rm .well-known/jwks.json .well-known/aauth-agent.json
git commit -m "Remove AAuth JWKS and agent metadata (uninstall)"
git push origin <default-branch>
```

If both files are already absent, the remote is already clean — skip to step 4. If only one is present, surface to the user before proceeding.

### 3. Wait for Cloudflare Pages to redeploy

```bash
until ! curl -sI <agent-url>/.well-known/jwks.json | head -1 | grep -q "200"; do sleep 5; done
curl -I <agent-url>/.well-known/jwks.json | head -1
curl -I <agent-url>/.well-known/aauth-agent.json | head -1
```

A deploy typically lands in under a minute. If it takes much longer, surface to the user — there may be a build hook failure.

### 4. Report the world-state change, not the command

> "JWKS at <agent-url>/.well-known/jwks.json now returns 404 — resources can no longer verify signatures from this agent."

## Path B — direct wrangler upload (no source repo)

If the project is uploaded with `wrangler pages deploy` from a local directory:

### 1. Locate the staging directory

Find or recreate the directory that was used for the last `wrangler pages deploy`. If unknown, the cleanest move is to deploy an empty directory:

```bash
mkdir -p /tmp/aauth-uninstall && cd /tmp/aauth-uninstall
```

### 2. Deploy the empty/cleaned content

```bash
wrangler pages deploy . --project-name <project-name>
```

If the original staging directory contained other content the user wants to keep, ask first — deploying an empty directory will take it down too. In that case have the user point you at the right directory; delete only `.well-known/jwks.json` and `.well-known/aauth-agent.json` from it, then redeploy.

### 3. BLOCK until 404 (same as Path A step 3 + 4)

## Notes

- This skill is invoked by the bootstrap `uninstall` skill. Do not publish fresh AAuth files from it — that's the `cloudflare-pages` skill's job.
- Custom domains: the 404 must come back on the agent URL the user actually used (custom or `.pages.dev`), not just one of them.
- If you can't authenticate `wrangler` or find a connected repo, surface that as a blocker. Do not offer to have the user delete the files manually — without your verification step, "I'll do it" effectively means "leave them published."
