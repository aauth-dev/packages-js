import { FLAGS, FLAG_GROUPS, COMMANDS, flagInvocation } from './args.js'

/** USAGE block — one line per command (from the COMMANDS spec). */
function renderUsage(): string {
  return COMMANDS.map(c => `  ${c.usage}`).join('\n')
}

/** COMMANDS block — name + one-line summary (from the COMMANDS spec). */
function renderCommands(): string {
  return COMMANDS
    .filter(c => c.name !== '<resource>') // the default fetch is described in DESCRIPTION
    .map(c => `  ${c.name}\n    ${c.summary}`)
    .join('\n\n')
}

/** Flag sections, grouped and ordered per FLAG_GROUPS — generated from FLAGS. */
function renderFlagGroups(): string {
  const blocks: string[] = []
  for (const { group, heading } of FLAG_GROUPS) {
    const flags = FLAGS.filter(f => f.group === group)
    if (!flags.length) continue
    const lines = [heading]
    for (const f of flags) {
      lines.push(`  ${flagInvocation(f)}`)
      lines.push(`    ${f.summary}`)
      for (const d of f.details ?? []) lines.push(`    ${d}`)
    }
    blocks.push(lines.join('\n'))
  }
  return blocks.join('\n\n')
}

export function topLevelHelp(version: string): string {
  return `DESCRIPTION
  AAuth fetch v${version} — make a signed, authenticated request to <resource> and
  print its response. Runs the full AAuth flow adaptively: sign with the agent token
  and send; on a 401/202 challenge, exchange the resource token for an auth token
  (consent if needed) and retry; for a resource-managed (two-party) resource, carry
  the opaque AAuth-Access token instead. Result on stdout is the response body
  (pretty JSON when JSON, else raw); --emit adds the reusable credential
  alongside it.

USAGE
${renderUsage()}

COMMANDS
${renderCommands()}

${renderFlagGroups()}

EXAMPLES
  One-shot — run the full flow and print the response body:

  $ npx @aauth/fetch https://whoami.aauth.dev
  {
    "sub": "aauth:local@me.github.io",
    "ps": "https://person.hello.coop"
  }

  Reusing a token across calls, two-party (AAuth-Access) resources, R3 operations,
  and the full agent workflow are covered in the guide: npx @aauth/fetch skill

LEARN MORE
  Overview:          https://www.aauth.dev
  Agent index:       https://www.aauth.dev/llms.txt`
}
