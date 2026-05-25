import { readFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const skillsDir = join(__dirname, '..', 'skills')

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
    guide = stripFrontMatter(readFileSync(join(skillsDir, 'fetch.md'), 'utf-8'))
  } catch {
    // fall back to the heading if the bundled guide is missing
  }
  return `${guide}\n\n## AAuth protocol spec\n\nFetch this URL to read the full spec:\n${PROTOCOL_SPEC_URL}\n`
}
