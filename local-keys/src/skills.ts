import { readFileSync, readdirSync, existsSync } from 'node:fs'
import { join, basename, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const skillsDir = join(__dirname, '..', 'skills')
const platformsDir = join(skillsDir, 'platforms')

export interface SkillSummary {
  name: string
  description: string
  when: string
  requires?: string
}

export interface Skill extends SkillSummary {
  body: string
}

export interface PlatformSummary {
  name: string
  description: string
  agentUrlPattern: string
  pros: string
  cons: string
  detect_cli: string
  detect_auth: string
  detect_existing?: string
}

function parseFrontMatter(content: string): { meta: Record<string, string>; body: string } {
  if (!content.startsWith('---\n')) return { meta: {}, body: content }
  const end = content.indexOf('\n---\n', 4)
  if (end === -1) return { meta: {}, body: content }

  const meta: Record<string, string> = {}
  for (const line of content.slice(4, end).split('\n')) {
    const colon = line.indexOf(':')
    if (colon === -1) continue
    meta[line.slice(0, colon).trim()] = line.slice(colon + 1).trim()
  }

  return { meta, body: content.slice(end + 5).trim() }
}

function readSkillFiles(dir: string): Array<{ file: string; content: string }> {
  try {
    return readdirSync(dir)
      .filter((f) => f.endsWith('.md'))
      .map((f) => ({
        file: f,
        content: readFileSync(join(dir, f), 'utf-8'),
      }))
  } catch {
    return []
  }
}

/**
 * List all skills (top-level + platforms).
 */
export function listSkills(): SkillSummary[] {
  const skills: SkillSummary[] = []

  for (const { content } of readSkillFiles(skillsDir)) {
    const { meta } = parseFrontMatter(content)
    if (!meta.name) continue
    skills.push({
      name: meta.name,
      description: meta.description || '',
      when: meta.when || '',
      requires: meta.requires,
    })
  }

  for (const { content } of readSkillFiles(platformsDir)) {
    const { meta } = parseFrontMatter(content)
    if (!meta.name) continue
    skills.push({
      name: meta.name,
      description: meta.description || '',
      when: meta.when || '',
      requires: meta.requires,
    })
  }

  return skills
}

/**
 * Get a skill by name (searches top-level and platforms).
 */
export function getSkill(name: string): Skill | null {
  // Try top-level first
  for (const dir of [skillsDir, platformsDir]) {
    const filePath = join(dir, `${name}.md`)
    try {
      const content = readFileSync(filePath, 'utf-8')
      const { meta, body } = parseFrontMatter(content)
      return {
        name: meta.name || name,
        description: meta.description || '',
        when: meta.when || '',
        requires: meta.requires,
        body,
      }
    } catch {
      continue
    }
  }
  return null
}

/**
 * List available hosting platforms with their discovery metadata.
 * An agent uses this to check which platforms the user has available.
 */
export function listPlatforms(): PlatformSummary[] {
  const platforms: PlatformSummary[] = []

  for (const { content } of readSkillFiles(platformsDir)) {
    const { meta } = parseFrontMatter(content)
    if (!meta.name || !meta.detect_cli) continue
    platforms.push({
      name: meta.name,
      description: meta.description || '',
      agentUrlPattern: meta.agentUrlPattern || '',
      pros: meta.pros || '',
      cons: meta.cons || '',
      detect_cli: meta.detect_cli,
      detect_auth: meta.detect_auth || '',
      detect_existing: meta.detect_existing,
    })
  }

  return platforms
}
