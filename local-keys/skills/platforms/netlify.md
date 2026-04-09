---
name: netlify
description: Publish AAuth agent metadata and public keys to Netlify
when: User wants to publish their agent identity via Netlify (custom domain or project.netlify.app)
requires: setup
agentUrlPattern: project.netlify.app or custom domain
pros: Free tier, git-integrated, custom domains, simple deploy CLI
cons: Lower free tier bandwidth limits (100GB/month)
detect_cli: npx netlify --version
detect_auth: npx netlify status
---

# Skill: Publish AAuth keys to Netlify

## When to use

The user wants to publish their AAuth agent metadata and public keys via Netlify. Keys should already be generated using the `setup` skill.

## Prerequisites

- `@aauth/local-keys` is installed
- Keys have been generated (run `npx @aauth/local-keys show` to check)
- Netlify account

## Agent URL

The agent URL will be either:
- A custom domain configured in Netlify (e.g. `https://agent.example.com`)
- The default `https://site-name.netlify.app`

Ask the user which they plan to use.

## Steps

### 1. Collect public keys to publish

Run:
```
npx @aauth/local-keys public-key
```

### 2. Create or locate the project

**Option A: Git-connected site** (recommended)

Create or locate a git repo that Netlify will deploy from:
```bash
mkdir agent-site && cd agent-site
git init
```

**Option B: Manual deploy**

Create a local directory to deploy:
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
  "id": "https://site-name.netlify.app",
  "name": "Agent Name",
  "jwks_uri": "https://site-name.netlify.app/.well-known/jwks.json"
}
```

Replace the URLs with the custom domain if using one. Optionally add `logo_uri`, `tos_uri`, `policy_uri`.

### 6. Add a `_redirects` file (important)

Netlify needs a `_redirects` file to ensure `.well-known/` paths are served correctly. Create `_redirects` in the project root:

```
/.well-known/*  /.well-known/:splat  200
```

This ensures Netlify serves the `.well-known/` files without any rewriting.

### 7. Deploy

**Option A: Git-connected via CLI**

```bash
npx netlify init
```

Follow the prompts to connect to a Netlify site. Then:
```bash
git add .
git commit -m "Publish AAuth agent keys"
git push
```

**Option B: Manual deploy via CLI**

```bash
npx netlify deploy --prod --dir .
```

If not linked to a site yet, the CLI will prompt to create or link one.

**Option C: Drag and drop**

Go to [app.netlify.com](https://app.netlify.com), create a new site, and drag the project folder into the deploy area.

### 8. Configure custom domain (optional)

In the Netlify dashboard → Site settings → Domain management → Add a custom domain. HTTPS is automatic via Let's Encrypt.

### 9. Verify publication

Confirm the files are accessible:
- `https://site-name.netlify.app/.well-known/jwks.json`
- `https://site-name.netlify.app/.well-known/aauth-agent.json`

Or at the custom domain equivalent.

## Notes

- The `_redirects` file ensures `.well-known/` paths work correctly on Netlify.
- Free tier: 100GB bandwidth/month, 300 build minutes/month.
- For git-connected sites, every push to the production branch triggers a deploy.
- Custom domains get automatic HTTPS via Let's Encrypt.
- Old keys should remain in the JWKS for verification of previously issued tokens.
