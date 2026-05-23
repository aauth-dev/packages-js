import { readFileSync, readdirSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const skillsDir = join(__dirname, '..', 'skills')

export interface SkillSummary {
  name: string
  description: string
}

export interface Skill extends SkillSummary {
  body: string
}

function parseFrontMatter(content: string): { meta: Record<string, string>; body: string } {
  if (!content.startsWith('---\n')) return { meta: {}, body: content.trim() }
  const end = content.indexOf('\n---\n', 4)
  if (end === -1) return { meta: {}, body: content.trim() }
  const meta: Record<string, string> = {}
  for (const line of content.slice(4, end).split('\n')) {
    const colon = line.indexOf(':')
    if (colon === -1) continue
    meta[line.slice(0, colon).trim()] = line.slice(colon + 1).trim()
  }
  return { meta, body: content.slice(end + 5).trim() }
}

export function listSkills(): SkillSummary[] {
  let files: string[]
  try {
    files = readdirSync(skillsDir).filter(f => f.endsWith('.md'))
  } catch {
    return []
  }
  const skills: SkillSummary[] = []
  for (const f of files) {
    const { meta } = parseFrontMatter(readFileSync(join(skillsDir, f), 'utf-8'))
    if (!meta.name) continue
    skills.push({ name: meta.name, description: meta.description || '' })
  }
  return skills
}

export function getSkill(name: string): Skill | null {
  try {
    const content = readFileSync(join(skillsDir, `${name}.md`), 'utf-8')
    const { meta, body } = parseFrontMatter(content)
    return { name: meta.name || name, description: meta.description || '', body }
  } catch {
    return null
  }
}

/** Render the skill list as markdown (`#` title, `##` per skill) — agents parse this best. */
export function renderSkillListMarkdown(skills: SkillSummary[]): string {
  const lines = ['# AAuth fetch skills', '']
  for (const s of skills) {
    lines.push(`## ${s.name}`)
    if (s.description) lines.push(s.description)
    lines.push('')
  }
  lines.push('Run `npx @aauth/fetch skill <name>` to print a guide.')
  return lines.join('\n')
}
