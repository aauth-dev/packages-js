#!/usr/bin/env node

import { createRequire } from 'node:module'
import { realpathSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { parseArgs } from './args.js'
import { readJsonInput, mergeJsonInput } from './json-input.js'
import { listSkills, getSkill, renderSkillListMarkdown } from './skill.js'
import { topLevelHelp, COMMAND_HELP } from './help.js'
import {
  resolvePersonServer,
  buildGetKeyMaterial,
  buildRequestInit,
  handleAuthorize,
  handlePreAuthed,
  handleAgentOnly,
  handleFullFlow,
} from './handlers.js'

const pkg = createRequire(import.meta.url)('../package.json') as { version: string }

function fail(message: string): void {
  console.error(JSON.stringify({ error: message }))
  process.exitCode = 1
}

function cmdSkill(name?: string): void {
  if (!name) {
    console.log(renderSkillListMarkdown(listSkills()))
    return
  }
  const skill = getSkill(name)
  if (!skill) return fail(`Unknown skill: "${name}". Run \`skill\` to list available skills.`)
  console.log(skill.body)
}

export async function run(): Promise<void> {
  let args = parseArgs(process.argv)

  if (args.version) {
    console.log(pkg.version)
    return
  }

  // `skill [name]` — help for it, or print the skill(s).
  if (args.command === 'skill') {
    if (args.help) { console.log(COMMAND_HELP.skill); return }
    cmdSkill(args.skillName)
    return
  }

  // `--json`: merge a request spec from stdin.
  if (args.jsonInput) {
    const json = await readJsonInput()
    args = mergeJsonInput(args, json)
  }

  // authorize command
  if (args.command === 'authorize') {
    if (args.help || !args.url) {
      console.log(COMMAND_HELP.authorize)
      if (!args.help && !args.url) process.exitCode = 1
      return
    }
    const personServer = resolvePersonServer(args.agentProvider, args.personServer)
    const getKeyMaterial = buildGetKeyMaterial(args)
    await handleAuthorize({ ...args, url: args.url }, getKeyMaterial, personServer)
    return
  }

  // Bare invocation or --help → top-level help.
  if (!args.url || args.help) {
    console.log(topLevelHelp(pkg.version))
    return
  }

  // Default fetch (or its modifier modes).
  const personServer = resolvePersonServer(args.agentProvider, args.personServer)
  const getKeyMaterial = buildGetKeyMaterial(args)
  const init = buildRequestInit(args)
  const url = args.url

  if (args.authToken && args.signingKey) {
    await handlePreAuthed({ ...args, url, authToken: args.authToken, signingKey: args.signingKey }, init)
  } else if (args.agentOnly) {
    await handleAgentOnly({ ...args, url }, init, getKeyMaterial)
  } else {
    await handleFullFlow({ ...args, url }, init, getKeyMaterial, personServer)
  }
}

/** True when this module is the process entrypoint (not imported by a test). */
function isEntrypoint(): boolean {
  try {
    return realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))
  } catch {
    return false
  }
}

if (isEntrypoint()) {
  run().catch((err: Error) => {
    fail(err.message)
  })
}
