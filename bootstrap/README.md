# @aauth/bootstrap

CLI for setting up AAuth agent keys, registering with a person server, and publishing keys to a hosting platform.

Part of [aauth-dev/packages-js](https://github.com/aauth-dev/packages-js). Protocol spec: [dickhardt/AAuth](https://github.com/dickhardt/AAuth).

## Quick Start

```bash
# Generate keys, bind the default person server (person.hello.coop), and walk through hosting setup
npx @aauth/bootstrap generate --agent <your-agent-url> --ps

# ...or point at a specific person server
npx @aauth/bootstrap generate --agent <your-agent-url> --ps https://person.example
```

`--ps` with no URL binds the default person server (`https://person.hello.coop`). Once an agent exists, you can re-run just `npx @aauth/bootstrap --ps` to (re)configure its person server.

The bootstrap flow detects available key backends (YubiKey PIV, macOS Secure Enclave, software), generates keys on the strongest available backend, configures a person server for your agent, and bundles agent skills that walk you through publishing keys on platforms like GitHub Pages, GitLab Pages, Cloudflare Pages, and Netlify.

Per [draft-hardt-aauth-bootstrap §Self-Hosted Enrollment](https://github.com/dickhardt/AAuth), publication of the JWKS is the enrollment — there is no separate enrollment step. Person binding to a user happens lazily on the agent's first authorized request, per [§Agent-Person Binding](https://github.com/dickhardt/AAuth) in the protocol spec.

## Commands

```
npx @aauth/bootstrap <command> [options]

Commands:
  discover                 List available key backends (JSON)
  generate [options]       Generate a key pair, output public JWK (JSON)
  sign-token [options]     Sign an agent token with ephemeral cnf (JSON)
  public-key [options]     Output public key(s) (JSON)
  add-agent <url> [opts]   Register an agent URL in config
  config                   Dump ~/.aauth/config.json
  show                     Human-readable status overview
  skill                    List available skills (JSON)
  skill <name>             Show full skill instructions
  help                     Show this help
```

### Generate options

```
--backend <name>         software (default), yubikey-piv, secure-enclave
--algorithm <alg>        EdDSA (default for software), ES256, RS256
--agent <url>            Associate key with an agent URL
```

### Sign-token options

```
--agent <url>            Agent URL (required)
--agent-id <id>          Agent identifier (default: from config)
--lifetime <seconds>     Token lifetime (default: 3600)
```

### Person server bootstrap

Can be combined with any command:

```
--person-server [url]    Bootstrap with person server (alias: --ps; default: https://person.hello.coop)
--local <name>           Local part of agent identifier (default: "local")
--login-hint <hint>      Hint about who to authorize
--domain-hint <domain>   Domain/org routing hint
--provider-hint <name>   Upstream identity provider hint
--tenant <id>            Tenant identifier
```

## For AI Agents

If you are an AI agent helping a user set up AAuth, **do not guess what is available**. Run the CLI to detect the user's environment first:

```bash
# 1. Detect available hardware and software backends
npx @aauth/bootstrap discover

# 2. Check current state (existing agents, keys, hosting)
npx @aauth/bootstrap show

# 3. Load the setup skill for step-by-step instructions
npx @aauth/bootstrap skill setup

# 4. List available hosting platform skills
npx @aauth/bootstrap skill
```

The `discover` output tells you what key backends are available on this machine. Use that — not assumptions — to guide key generation. Hardware backends (Secure Enclave, YubiKey) are always preferred over software (OS keychain).

The `skill` commands return structured instructions for the setup flow and each hosting platform. Load and follow these rather than improvising.

## Related Packages

- [`@aauth/local-keys`](../local-keys) — underlying library for key management and signing (use this from other packages)
- [`@aauth/fetch`](../fetch) — CLI for making AAuth-authenticated HTTP requests

## License

MIT
