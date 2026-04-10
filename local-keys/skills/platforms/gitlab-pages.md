---
name: gitlab-pages
description: Publish AAuth agent metadata and public keys to GitLab Pages (username.gitlab.io)
when: User wants to publish their agent identity via GitLab Pages
requires: setup
agentUrlPattern: username.gitlab.io
pros: Free, git-integrated, private repos supported
cons: Requires .gitlab-ci.yml for deployment
detect_cli: glab --version
detect_auth: glab auth status
detect_existing: glab repo view {username}/{username}.gitlab.io
---

# Skill: Publish AAuth keys to GitLab Pages

## When to use

The user wants to publish their AAuth agent metadata and public keys via GitLab Pages. Keys should already be generated using the `keygen` skill.

## Prerequisites

- `@aauth/local-keys` is installed
- Keys have been generated (run `npx @aauth/local-keys show` to check)
- GitLab account
- `glab` CLI installed and authenticated (`glab auth login`), OR `git` configured for GitLab

## Agent URL

The agent URL will be `https://username.gitlab.io` (for the user/group Pages site) or `https://username.gitlab.io/project-name` (for a project Pages site).

For the simplest setup, use the user Pages site: create a repo named `username.gitlab.io`.

## Steps

### 1. Collect public keys to publish

Run:
```
npx @aauth/local-keys public-key
```

### 2. Locate or create the GitLab Pages repo

**User/group Pages site** (serves at `https://username.gitlab.io`):
- The repo must be named `username.gitlab.io`
- Check if it exists: `glab repo view username/username.gitlab.io` or look locally

**Project Pages site** (serves at `https://username.gitlab.io/project-name`):
- Any repo with GitLab Pages configured

If the repo doesn't exist:
```bash
mkdir username.gitlab.io && cd username.gitlab.io
git init
glab repo create username.gitlab.io --public
```

Or create it via the GitLab web UI.

### 3. Create the `.well-known/` directory and files

GitLab Pages serves files from a `public/` directory (the CI job output). Create:
```bash
mkdir -p public/.well-known
```

### 4. Create or update `public/.well-known/jwks.json`

- If the file exists, read it and parse the `keys` array.
- If it doesn't exist, start with `{ "keys": [] }`.
- Add all public JWKs from step 1 to the `keys` array.
- If a key with the same `kid` already exists, replace it. Otherwise append.
- Write the file with `JSON.stringify(jwks, null, 2)`.

### 5. Create or update `public/.well-known/aauth-agent.json`

```json
{
  "id": "https://username.gitlab.io",
  "name": "Username",
  "jwks_uri": "https://username.gitlab.io/.well-known/jwks.json"
}
```

Optionally add `logo_uri` (GitLab avatar: `https://gitlab.com/uploads/-/system/user/avatar/USER_ID/avatar.png`), `tos_uri`, `policy_uri`.

### 6. Create `.gitlab-ci.yml`

GitLab Pages requires a CI pipeline to deploy. Create `.gitlab-ci.yml` in the repo root:

```yaml
pages:
  stage: deploy
  script:
    - echo "Deploying to GitLab Pages"
  artifacts:
    paths:
      - public
  only:
    - main
```

This tells GitLab to publish everything in `public/` to Pages on every push to `main`.

### 7. Commit and push

```bash
git add .
git commit -m "Publish AAuth agent keys"
git push -u origin main
```

The CI pipeline will run and deploy the Pages site.

### 8. Verify publication

GitLab Pages can take a few minutes to deploy on the first push. Check the pipeline status in GitLab, then confirm:
- `https://username.gitlab.io/.well-known/jwks.json`
- `https://username.gitlab.io/.well-known/aauth-agent.json`

If Pages isn't enabled, go to the GitLab project → Settings → Pages → ensure it's enabled.

## Notes

- GitLab Pages serves files from the `public/` directory — not the repo root. All `.well-known/` files must be under `public/.well-known/`.
- The `.gitlab-ci.yml` file is required — without it, Pages won't deploy.
- Free tier supports Pages on both public and private repos.
- Custom domains are supported: project Settings → Pages → New Domain. HTTPS is automatic via Let's Encrypt.
- Old keys should remain in the JWKS for verification of previously issued tokens.
- GitLab Pages does not use Jekyll, so no `.nojekyll` file is needed.
