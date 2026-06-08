import { readFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { FLAGS, FLAG_GROUPS, COMMANDS, flagInvocation } from './args.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const skillsDir = join(__dirname, '..', 'skills')

// ── Generated markdown tables (from the FLAGS/COMMANDS spec in args.ts) ──────────
// The skill guide (skills/fetch.md) carries <!-- AUTOGEN:* --> markers; renderSkill
// swaps them for these, so the guide's flag/command/env tables can't drift.

function commandsTable(): string {
  return [
    '| Command | Description |',
    '|---------|-------------|',
    ...COMMANDS.map(c => `| \`${c.name}\` | ${c.summary} |`),
  ].join('\n')
}

function flagsTable(): string {
  const rows: string[] = []
  for (const { group } of FLAG_GROUPS) {
    for (const f of FLAGS.filter(x => x.group === group)) {
      rows.push(`| \`${flagInvocation(f)}\` | ${group} | ${f.summary} |`)
    }
  }
  return ['| Flag | Group | Description |', '|------|-------|-------------|', ...rows].join('\n')
}

function envTable(): string {
  const rows = FLAGS.filter(f => f.env).map(f => `| \`${f.env}\` | \`--${f.long}\` |`)
  return ['| Variable | Equivalent flag |', '|----------|-----------------|', ...rows].join('\n')
}

const AUTOGEN: Record<string, () => string> = {
  'AUTOGEN:COMMANDS': commandsTable,
  'AUTOGEN:FLAGS': flagsTable,
  'AUTOGEN:ENV': envTable,
}

/** Replace each `<!-- AUTOGEN:X -->` marker with its generated table. */
function fillAutogen(md: string): string {
  return md.replace(/<!--\s*(AUTOGEN:[A-Z]+)\s*-->/g, (whole, key: string) => {
    const gen = AUTOGEN[key]
    return gen ? gen() : whole
  })
}

/** The AAuth protocol spec — a URL the agent fetches itself (nothing bundled). */
export const PROTOCOL_SPEC_URL =
  'https://raw.githubusercontent.com/dickhardt/AAuth/refs/heads/main/draft-hardt-oauth-aauth-protocol.md'

function stripFrontMatter(content: string): string {
  if (!content.startsWith('---\n')) return content.trim()
  const end = content.indexOf('\n---\n', 4)
  return end === -1 ? content.trim() : content.slice(end + 5).trim()
}

/**
 * The single fetch skill: the usage guide, plus a pointer to the AAuth protocol
 * spec (a URL to fetch yourself — nothing bundled). There is no skill selection;
 * `skill` prints this.
 */
export function renderSkill(): string {
  let guide = '# @aauth/fetch'
  try {
    guide = fillAutogen(stripFrontMatter(readFileSync(join(skillsDir, 'fetch.md'), 'utf-8')))
  } catch {
    // fall back to the heading if the bundled guide is missing
  }
  return `${guide}

## Learn more

- Overview: https://www.aauth.dev
- AAuth protocol spec — fetch this URL to read the full spec: ${PROTOCOL_SPEC_URL}
`
}
