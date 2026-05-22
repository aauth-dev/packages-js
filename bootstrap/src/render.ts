import type { BackendInfo } from '@aauth/local-keys'
import type { SkillSummary } from './skills.js'

/** A keystore entry as surfaced by `list` (renamed from "backend"). */
export interface KeystoreInfo {
  keystore: string
  description: string
  algorithms: string[]
}

/**
 * Add ANSI syntax colors to a pretty-printed JSON string: keys blue, strings
 * green, numbers cyan, booleans/null yellow. Caller decides whether to apply it
 * (TTY only) — colors must never reach a pipe, or `jq` would choke on them.
 */
export function colorizeJson(json: string): string {
  const RESET = '\x1b[0m'
  return json.replace(
    /("(?:\\.|[^"\\])*")(\s*:)?|\b(true|false|null)\b|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/g,
    (match, str, colon, keyword, num) => {
      if (str !== undefined) {
        if (colon !== undefined) return `\x1b[34m${str}${RESET}${colon}` // key
        return `\x1b[32m${str}${RESET}` // string value
      }
      if (keyword !== undefined) return `\x1b[33m${keyword}${RESET}` // bool / null
      if (num !== undefined) return `\x1b[36m${num}${RESET}` // number
      return match
    },
  )
}

/** Map discovered backends to the `keystore` shape used in `list` output. */
export function shapeKeystores(backends: BackendInfo[]): KeystoreInfo[] {
  return backends.map((b) => ({
    keystore: b.backend,
    description: b.description,
    algorithms: b.algorithms,
  }))
}

/** Render the skill list as markdown (`#` title, `##` per skill) — agents parse this best. */
export function renderSkillListMarkdown(skills: SkillSummary[]): string {
  const lines = ['# AAuth bootstrap skills', '']
  for (const s of skills) {
    lines.push(`## ${s.name}`)
    if (s.description) lines.push(s.description)
    lines.push('')
  }
  lines.push('Run `npx @aauth/bootstrap skill <name>` to print a guide.')
  return lines.join('\n')
}

export function topLevelHelp(version: string): string {
  return `DESCRIPTION
  AAuth bootstrap v${version} — set up an agent provider identity for AAuth.
  Agents: run \`npx @aauth/bootstrap skill setup\` for end-to-end setup.

USAGE
  npx @aauth/bootstrap <command> [flags]

COMMANDS
  skill [name]
    Agent setup guides — start here:
      setup
        Set up an agent identity end-to-end

      github-pages
        Publish to GitHub Pages

      gitlab-pages
        Publish to GitLab Pages

      cloudflare-pages
        Publish to Cloudflare Pages

      netlify
        Publish to Netlify

  list
    List agent providers, keys, and keystores

  create <agent-provider-url> [--keystore <name>] [--algorithm <alg>] [--person-server <url>]
    Register an agent provider (generates its first key, binds a person server)

  delete <agent-provider-url>
    Delete an agent provider and its keys

  token [--agent-provider <url>] [--agent-id <id>] [--local <name>] [--lifetime <s>]
    Generate an agent token

  help [command]
    Show help for a command`
}

/** Per-command help text, keyed by command name. */
export const COMMAND_HELP: Record<string, string> = {
  list: `DESCRIPTION
  List configured agent providers, their keys (with public JWKs), and the
  keystores available on this machine.

USAGE
  npx @aauth/bootstrap list`,

  create: `DESCRIPTION
  Register a new agent provider. One command does the whole setup:
    - generates a signing key (in the chosen keystore)
    - binds that key to the agent provider
    - binds a person server (default: person.hello.coop, unless --person-server)
  Fails if the agent provider already exists (delete it first to re-create).

USAGE
  npx @aauth/bootstrap create <agent-provider-url> [flags]

FLAGS
  --keystore <name>
    Which keystore to use (default: software) — run \`list\` for available keystores

  --algorithm <alg>
    An algorithm the chosen keystore supports (see \`list\`); defaults to the keystore's default

  --person-server <url>
    Person server to bind (default: person.hello.coop)`,

  delete: `DESCRIPTION
  Delete an agent provider and its keys, including from hardware keystores.
  Fails if the agent provider doesn't exist.

USAGE
  npx @aauth/bootstrap delete <agent-provider-url>`,

  token: `DESCRIPTION
  Generate an agent token — the credential an agent presents to make authenticated calls.
  With one agent provider configured it needs no arguments — the agent provider and
  its agent-id come from config.

USAGE
  npx @aauth/bootstrap token [flags]

FLAGS
  --agent-provider <url>
    Pick the agent provider (default: the sole one in config)

  --agent-id <id>
    Override the agent id (default: the resolved provider's agent)

  --local <name>
    Override just the local-part → aauth:<name>@<host>

  --lifetime <seconds>
    Token lifetime (default: 3600)`,

  skill: `DESCRIPTION
  Print agent setup guides — how to generate keys and publish your agent identity.

USAGE
  npx @aauth/bootstrap skill [name]

  No name   List available skills (markdown)
  <name>    Print that skill's full instructions (markdown)`,

  help: `DESCRIPTION
  Show help for a command.

USAGE
  npx @aauth/bootstrap help [command]`,
}
