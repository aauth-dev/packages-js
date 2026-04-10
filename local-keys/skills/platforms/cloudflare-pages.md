---
name: cloudflare-pages
description: Publish AAuth agent metadata and public keys to Cloudflare Pages
when: User wants to publish their agent identity via Cloudflare Pages (custom domain or project.pages.dev)
requires: setup
agentUrlPattern: project.pages.dev or custom domain
pros: Free, fast global CDN, git-integrated, custom domains
cons: Requires Cloudflare account
detect_cli: npx wrangler --version
detect_auth: npx wrangler whoami
---

# Skill: Publish AAuth keys to Cloudflare Pages

## When to use

The user wants to publish their AAuth agent metadata and public keys via Cloudflare Pages. Keys should already be generated using the `keygen` skill.

## Prerequisites

- `@aauth/local-keys` is installed
- Keys have been generated (run `npx @aauth/local-keys show` to check)
- Cloudflare account
- `wrangler` CLI installed (`npm install -g wrangler`) and authenticated (`wrangler login`), OR a git repo connected to Cloudflare Pages

## Agent URL

The agent URL will be either:
- A custom domain configured in Cloudflare Pages (e.g. `https://agent.example.com`)
- The default `https://project-name.pages.dev`

Ask the user which they plan to use.

## Steps

### 1. Collect public keys to publish

Run:
```
npx @aauth/local-keys public-key
```

### 2. Create or locate the project

**Option A: Git-connected project** (recommended)

Create or locate a git repo that Cloudflare Pages will deploy from:
```bash
mkdir agent-site && cd agent-site
git init
```

**Option B: Direct upload**

If using `wrangler pages deploy` directly, create a local directory:
```bash
mkdir agent-site && cd agent-site
```

### 3. Create the `.well-known/` directory and files

```bash
mkdir -p .well-known
```

### 4. Create or update `.well-known/jwks.json`

- If the file exists, read it and parse the `keys` array.
- If it doesn't exist, start with `{ "keys": [] }`.
- Add all public JWKs from step 1 to the `keys` array.
- If a key with the same `kid` already exists, replace it. Otherwise append.
- Write the file with `JSON.stringify(jwks, null, 2)`.

### 5. Create or update `.well-known/aauth-agent.json`

```json
{
  "id": "https://project-name.pages.dev",
  "name": "Agent Name",
  "jwks_uri": "https://project-name.pages.dev/.well-known/jwks.json"
}
```

Replace the URLs with the custom domain if using one. Optionally add `logo_uri`, `tos_uri`, `policy_uri`.

### 6. Deploy

**Option A: Git-connected**

If the repo is connected to Cloudflare Pages:
```bash
git add .
git commit -m "Publish AAuth agent keys"
git push
```

Cloudflare Pages will auto-deploy. If not yet connected, go to the Cloudflare dashboard → Pages → Create a project → Connect to Git.

**Option B: Direct upload with wrangler**

```bash
wrangler pages deploy . --project-name <project-name>
```

If the project doesn't exist yet, wrangler will prompt to create it.

### 7. Configure custom domain (optional)

In the Cloudflare dashboard → Pages → your project → Custom domains → Add a custom domain.

The domain must be managed by Cloudflare (or you can add it to Cloudflare DNS). HTTPS is automatic.

### 8. Verify publication

Confirm the files are accessible:
- `https://project-name.pages.dev/.well-known/jwks.json`
- `https://project-name.pages.dev/.well-known/aauth-agent.json`

Or at the custom domain equivalent.

## Notes

- Cloudflare Pages serves `.well-known/` paths without any special configuration.
- The free tier supports unlimited static sites with unlimited bandwidth.
- For git-connected projects, every push to the main branch triggers a deploy.
- Custom domains get automatic HTTPS via Cloudflare's edge certificates.
- Old keys should remain in the JWKS for verification of previously issued tokens.
