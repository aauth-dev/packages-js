---
name: gitlab-pages-uninstall
description: Remove the published AAuth JWKS and agent metadata from GitLab Pages
when: User is uninstalling an AAuth agent provider whose JWKS is published to GitLab Pages — the bootstrap uninstall skill loads this skill to take down the remote files before deleting local keys
agentUrlPattern: username.gitlab.io
---

# Skill: Remove AAuth keys from GitLab Pages

The bootstrap `uninstall` skill loads this skill BEFORE deleting local keys, so the published JWKS goes down before the local signing key does. End state: both `https://username.gitlab.io/.well-known/jwks.json` and `aauth-agent.json` return 404.

## Prerequisites

- `glab` CLI is authenticated as the user who owns `username.gitlab.io`
- The agent URL (from `npx @aauth/bootstrap list`) is `https://username.gitlab.io`

## Steps

### 1. Locate or clone the GitLab Pages repo

Look for an existing `username.gitlab.io` clone first. If none:

```bash
glab repo clone username/username.gitlab.io
```

### 2. Sync with the remote

```bash
cd username.gitlab.io
git fetch origin
git pull --ff-only
```

Do NOT proceed if the pull fails — bring the working tree up to date first.

### 3. Check what's actually there

```bash
ls -la public/.well-known/ 2>/dev/null
```

GitLab Pages typically serves out of `public/`, so the files live at `public/.well-known/` (unlike GitHub Pages where they're at the repo root). If your project uses a different structure, ask the user.

- **Both files present** → continue to step 4.
- **Both absent** → the remote is already clean; report to the user and skip to step 7.
- **One present, one absent** → surface to the user before proceeding.

### 4. Delete the two AAuth files

```bash
git rm public/.well-known/jwks.json public/.well-known/aauth-agent.json
```

Delete ONLY these two files. The pipeline config (`.gitlab-ci.yml`) and any other content in `public/` are left alone.

### 5. Commit with the canonical uninstall message

```bash
git commit -m "Remove AAuth JWKS and agent metadata (uninstall)"
```

Same exact phrasing as the other platforms — this is what the `gitlab-pages` publish skill scans for when deciding whether to treat a future install as "first-time."

### 6. Push and BLOCK until the GitLab Pages pipeline redeploys

```bash
git push origin <default-branch>
```

GitLab Pages republishes via the pipeline configured in `.gitlab-ci.yml`. Watch for the pipeline:

```bash
glab ci view
```

Then BLOCK until both URLs return 404:

```bash
until ! curl -sI https://username.gitlab.io/.well-known/jwks.json | head -1 | grep -q "200"; do sleep 10; done
curl -I https://username.gitlab.io/.well-known/jwks.json | head -1
curl -I https://username.gitlab.io/.well-known/aauth-agent.json | head -1
```

Pipelines can take a few minutes. If a deploy fails (pipeline red), surface to the user — the published files won't have updated.

### 7. Report the world-state change, not the command

> "JWKS at https://username.gitlab.io/.well-known/jwks.json now returns 404 — resources can no longer verify signatures from this agent."

Then return to the bootstrap `uninstall` skill to continue with local teardown.

## Notes

- This skill is invoked by the bootstrap `uninstall` skill. Do not publish fresh AAuth files from it — that's the `gitlab-pages` skill's job.
- If the user can't authenticate `glab` here, surface that as a blocker. Do not offer to have the user delete the files manually — without your verification step, "I'll do it" effectively means "leave them published."
