#!/usr/bin/env node

import { createRequire } from 'node:module'
import { realpathSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import type { AuthServerMetadata } from '@aauth/mcp-agent'
import { parseArgs } from './args.js'
import { readJsonInput, mergeJsonInput } from './json-input.js'
import { renderSkill } from './skill.js'
import { topLevelHelp } from './help.js'
import {
  resolvePersonServer,
  resolvePersonServerMetadata,
  savePersonServerMetadata,
  runWithMetadataSelfHeal,
  buildGetKeyMaterial,
  buildRequestInit,
  handleAuthorize,
  handlePreAuthed,
  handleAgentOnly,
  handleFullFlow,
  initExplainLog,
} from './handlers.js'

const pkg = createRequire(import.meta.url)('../package.json') as { version: string }

function fail(message: string): void {
  console.error(JSON.stringify({ error: message }))
  process.exitCode = 1
}

function cmdSkill(): void {
  // One skill: the fetch guide + the protocol spec URL. No name/selection.
  console.log(renderSkill())
}

export async function run(): Promise<void> {
  let args = parseArgs(process.argv)

  if (args.version) {
    console.log(pkg.version)
    return
  }

  // `--help`/`-h` and the `help` command both show top-level help. Per-command
  // detail lives in the skill guide (`npx @aauth/fetch skill`), not here.
  if (args.help || args.command === 'help') {
    console.log(topLevelHelp(pkg.version))
    return
  }

  // `skill` — print the single guide (+ protocol & site URLs).
  if (args.command === 'skill') {
    cmdSkill()
    return
  }

  // `--json`: merge a request spec from stdin.
  if (args.jsonInput) {
    const json = await readJsonInput()
    args = mergeJsonInput(args, json)
  }

  // `--explain`: also tee event/consent output to
  // `~/.aauth/fetch/logs/<ISO>.log` so renderers can read events from a stable
  // path instead of capturing stderr. Best-effort; failure leaves stderr-only.
  const logPath = initExplainLog(args.explain === true)
  if (logPath) process.stderr.write(`Logging --explain events to ${logPath}\n`)

  // authorize command
  if (args.command === 'authorize') {
    if (!args.url) {
      fail('authorize requires a <resource> URL — see `npx @aauth/fetch skill`')
      return
    }
    const personServer = resolvePersonServer(args.agentProvider, args.personServer)
    const cachedMetadata = resolvePersonServerMetadata(personServer)
    const onMetadata = (m: AuthServerMetadata) => savePersonServerMetadata(personServer, m)
    const getKeyMaterial = buildGetKeyMaterial(args)
    const url = args.url
    await runWithMetadataSelfHeal(personServer, cachedMetadata, (metadata) =>
      handleAuthorize({ ...args, url }, getKeyMaterial, personServer, metadata, onMetadata),
    )
    return
  }

  // Bare invocation → top-level help.
  if (!args.url) {
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
    const cachedMetadata = resolvePersonServerMetadata(personServer)
    const onMetadata = (m: AuthServerMetadata) => savePersonServerMetadata(personServer, m)
    await runWithMetadataSelfHeal(personServer, cachedMetadata, (metadata) =>
      handleFullFlow({ ...args, url }, init, getKeyMaterial, personServer, metadata, onMetadata),
    )
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
