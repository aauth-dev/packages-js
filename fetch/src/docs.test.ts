import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { FLAGS, flagInvocation } from './args.js'
import { renderSkill } from './skill.js'
import { topLevelHelp } from './help.js'

// These guard against the documentation drift the FLAGS-as-single-source rework
// was meant to kill: if a flag is added/renamed/removed in args.ts, the docs that
// derive from it must stay in sync (or be regenerated).

const pkgDir = join(dirname(fileURLToPath(import.meta.url)), '..')
const readPkg = (rel: string) => readFileSync(join(pkgDir, rel), 'utf-8')

describe('flag docs stay in sync with the FLAGS spec', () => {
  const help = topLevelHelp('0.0.0')
  const skill = renderSkill()
  const readme = readPkg('README.md')
  const skillMd = readPkg('skills/fetch.md')

  it('the skill guide carries the AUTOGEN markers (so the CLI fills them)', () => {
    for (const marker of ['AUTOGEN:COMMANDS', 'AUTOGEN:FLAGS', 'AUTOGEN:ENV']) {
      expect(skillMd).toContain(marker)
    }
  })

  it('rendered skill replaces every marker (no leftover AUTOGEN comments)', () => {
    expect(skill).not.toContain('AUTOGEN:')
  })

  it.each(FLAGS.map(f => [f.long, f] as const))('--%s appears in --help and the skill', (_long, f) => {
    expect(help).toContain(flagInvocation(f))
    expect(skill).toContain(flagInvocation(f))
  })

  it.each(FLAGS.map(f => f.long))('--%s appears in the README', (long) => {
    expect(readme).toContain(`--${long}`)
  })

  it.each(FLAGS.filter(f => f.env).map(f => [f.env!, f.long] as const))(
    'env var %s is documented in the skill', (env) => {
      expect(renderSkill()).toContain(env)
    },
  )

  it('no doc still describes -v as the descriptive/teaching renderer', () => {
    // The old drift: -v == type/step/description. -v is now an alias of --debug (raw).
    for (const doc of [help, skill, readme]) {
      expect(doc).not.toMatch(/-v[^\n]*type\/step\/description/)
    }
  })
})
