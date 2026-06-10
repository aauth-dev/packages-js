---
name: github-pages-uninstall
description: Remove the published AAuth JWKS and agent metadata from GitHub Pages
when: User is uninstalling an AAuth agent provider whose JWKS is published to GitHub Pages — the bootstrap uninstall skill loads this skill to take down the remote files before deleting local keys
agentUrlPattern: username.github.io
---

# Skill: Remove AAuth keys from GitHub Pages

The bootstrap `uninstall` skill loads this skill BEFORE deleting local keys, so the published JWKS goes down before the local signing key does. End state: both `https://username.github.io/.well-known/jwks.json` and `aauth-agent.json` return 404.

## Prerequisites

- `gh` CLI is authenticated as the user who owns `username.github.io`
- The agent URL (from `npx @aauth/bootstrap list`) is `https://username.github.io`

## Steps

### 1. Locate or clone the GitHub Pages repo

Ask the user whether they have a local clone (paths vary — don't guess). Store the path as `REPO` for the rest of this skill. If they don't:

```
gh repo clone username/username.github.io /tmp/username.github.io
# REPO=/tmp/username.github.io
```

Run all git commands with `git -C "$REPO"` so you don't need to `cd`.

### 2. Sync with the remote

```
git -C "$REPO" fetch origin
git -C "$REPO" pull --ff-only
```

Do NOT proceed if the pull fails — investigate first. A non-fast-forward means someone else changed the repo; bring it up to date before deleting anything.

### 3. Check what's actually there

```
ls -la "$REPO/.well-known/" 2>/dev/null
```

- **Both files present** → continue to step 4.
- **Both absent** → the remote is already clean; report to the user and skip to step 7.
- **One present, one absent** → surface this to the user before proceeding. The published state is inconsistent with the local config.

### 4. Delete the two AAuth files

```
git -C "$REPO" rm .well-known/jwks.json .well-known/aauth-agent.json
```

Delete ONLY these two files. Do not touch other content in `.well-known/` or anywhere else in the repo — many users host real content here.

### 5. Commit with the canonical uninstall message

```
git -C "$REPO" commit -m "Remove AAuth JWKS and agent metadata (uninstall)"
```

This exact phrasing is what the `github-pages` publish skill scans for when it decides whether to treat a future install as "first-time" — i.e. to avoid silently resurrecting deleted keys from a stale local clone on another machine. Don't change the wording.

### 6. Push and BLOCK until both URLs return 404

```
git -C "$REPO" push
```

GitHub Pages can take up to a minute to update its cache. Poll until both URLs return 404 before reporting success — a successful `git push` is NOT proof the world has changed:

```bash
until ! curl -sI https://username.github.io/.well-known/jwks.json | head -1 | grep -q "200"; do sleep 5; done
curl -I https://username.github.io/.well-known/jwks.json | head -1
curl -I https://username.github.io/.well-known/aauth-agent.json | head -1
```

### 7. Report the world-state change, not the command

Tell the user concretely what changed in the world. Not the commit SHA — the URL that now 404s:

> "JWKS at https://username.github.io/.well-known/jwks.json now returns 404 — resources can no longer verify signatures from this agent."

Then return to the bootstrap `uninstall` skill to continue with local teardown.

## Notes

- This skill is invoked by the bootstrap `uninstall` skill. Do not publish fresh AAuth files from it — that's the `github-pages` skill's job.
- The GitHub Pages repo itself, `.nojekyll`, and any non-AAuth content are left alone.
- If the user can't authenticate `gh` here (no auth, wrong account), surface that as a blocker. Do not offer to have the user delete the files manually — without your verification step, "I'll do it" effectively means "leave them published."
