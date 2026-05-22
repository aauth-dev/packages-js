# @aauth/bootstrap

CLI for setting up AAuth agent keys, registering with a person server, and publishing keys to a hosting platform.

Part of [aauth-dev/packages-js](https://github.com/aauth-dev/packages-js). Protocol spec: [dickhardt/AAuth](https://github.com/dickhardt/AAuth).

## Quick Start

```bash
# Register an agent provider: generate a key, bind it, and bind the default
# person server (person.hello.coop) — all in one command.
npx @aauth/bootstrap create <your-agent-provider-url>

# ...or pick a keystore and person server
npx @aauth/bootstrap create <your-agent-provider-url> --keystore secure-enclave --person-server https://person.example
```

`create` detects available keystores (YubiKey PIV, macOS Secure Enclave, software), generates a key in the chosen one (default: software/EdDSA), binds it to the agent provider, and binds a person server. Then load a skill to publish your keys on GitHub Pages, GitLab Pages, Cloudflare Pages, or Netlify.

Output is **pretty-printed JSON** on stdout (pipe it to `jq`); errors are `{ "error": "…" }` on stderr with a non-zero exit. Help and `skill` output are markdown.

Per [draft-hardt-aauth-bootstrap §Self-Hosted Enrollment](https://github.com/dickhardt/AAuth), publication of the JWKS is the enrollment — there is no separate enrollment step. Person binding to a user happens lazily on the agent's first authorized request, per [§Agent-Person Binding](https://github.com/dickhardt/AAuth) in the protocol spec.

## Commands

```
npx @aauth/bootstrap <command> [flags]

  list
    List agent providers, their keys, and available keystores
  create <agent-provider-url> [--keystore <name>] [--algorithm <alg>] [--person-server <url>]
    Register an agent provider (generates its first key, binds a person server)
  delete <agent-provider-url>
    Delete an agent provider and its keys (incl. from software & Secure Enclave keystores)
  token [--agent-provider <url>] [--agent-id <id>] [--local <name>] [--lifetime <s>]
    Generate an agent token
  skill [name]
    Print agent setup guides (markdown)
  help [command]
    Show help for a command
```

`--help` (`-h`) and `--version` work as well. Run `npx @aauth/bootstrap list` to see which keystores and algorithms this machine supports.

> **Note:** `delete` removes software and Secure Enclave keys for real. A YubiKey PIV key can't be wiped programmatically yet — `delete` removes the binding and reports the slot to clear manually (`ykman piv keys delete 9e`).

## For AI Agents

If you are an AI agent helping a user set up AAuth, **do not guess what is available**. Run the CLI to detect the user's environment first:

```bash
# 1. See available keystores + anything already configured
npx @aauth/bootstrap list

# 2. Load the setup skill for step-by-step instructions
npx @aauth/bootstrap skill setup

# 3. List available hosting platform skills
npx @aauth/bootstrap skill
```

The `keystores` array in `list` tells you what key keystores are available on this machine. Use that — not assumptions — to guide key generation. Hardware keystores (Secure Enclave, YubiKey) are always preferred over software (OS keychain).

The `skill` commands return markdown instructions for the setup flow and each hosting platform. Load and follow these rather than improvising.

## Related Packages

- [`@aauth/local-keys`](../local-keys) — underlying library for key management and signing (use this from other packages)
- [`@aauth/fetch`](../fetch) — CLI for making AAuth-authenticated HTTP requests

## License

MIT
