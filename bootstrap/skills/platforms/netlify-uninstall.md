---
name: netlify-uninstall
description: Remove the published AAuth JWKS and agent metadata from Netlify
when: User is uninstalling an AAuth agent provider whose JWKS is published to Netlify — the bootstrap uninstall skill loads this skill to take down the remote files before deleting local keys
agentUrlPattern: project.netlify.app or custom domain
---

# Skill: Remove AAuth keys from Netlify

The bootstrap `uninstall` skill loads this skill BEFORE deleting local keys, so the published JWKS goes down before the local signing key does. End state: both `<agent-url>/.well-known/jwks.json` and `aauth-agent.json` return 404.

## Prerequisites

- `netlify` CLI is authenticated (`npx netlify status` succeeds), OR a git repo connected to the Netlify site
- The agent URL (from `npx @aauth/bootstrap list`) — either `https://project.netlify.app` or a custom domain

## Path A — git-connected site (preferred when available)

### 1. Locate or clone the source repo

Find the local clone of the repo that Netlify deploys from. If unknown, ask the user.

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

### 3. Wait for Netlify to redeploy

Watch the build:

```bash
npx netlify watch
```

Then BLOCK until both URLs return 404:

```bash
until ! curl -sI <agent-url>/.well-known/jwks.json | head -1 | grep -q "200"; do sleep 5; done
curl -I <agent-url>/.well-known/jwks.json | head -1
curl -I <agent-url>/.well-known/aauth-agent.json | head -1
```

If a deploy fails, surface to the user — the published files won't have updated.

### 4. Report the world-state change, not the command

> "JWKS at <agent-url>/.well-known/jwks.json now returns 404 — resources can no longer verify signatures from this agent."

## Path B — direct CLI deploy (no source repo)

If the site is deployed with `netlify deploy --dir` from a local directory:

### 1. Locate the staging directory

Find the directory the user last deployed from. If unknown, ask — deploying an empty directory will take down any other content.

### 2. Delete only the AAuth files

```bash
cd <staging-dir>
rm .well-known/jwks.json .well-known/aauth-agent.json
```

### 3. Redeploy to production

```bash
npx netlify deploy --dir . --prod
```

### 4. BLOCK until 404 (same as Path A step 3 + 4)

## Notes

- This skill is invoked by the bootstrap `uninstall` skill. Do not publish fresh AAuth files from it — that's the `netlify` skill's job.
- Custom domains: the 404 must come back on the agent URL the user actually used (custom or `.netlify.app`), not just one of them.
- If you can't authenticate `netlify` or find a connected repo, surface that as a blocker. Do not offer to have the user delete the files manually — without your verification step, "I'll do it" effectively means "leave them published."
