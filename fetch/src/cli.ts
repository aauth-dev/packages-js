#!/usr/bin/env node

import { parseArgs } from './args.js'
import { readJsonInput, mergeJsonInput } from './json-input.js'
import { printSkill } from './skill.js'
import { printGettingStarted } from './getting-started.js'
import {
  resolvePersonServer,
  buildGetKeyMaterial,
  buildRequestInit,
  handleAuthorize,
  handlePreAuthed,
  handleAgentOnly,
  handleFullFlow,
} from './handlers.js'

async function run() {
  let args = parseArgs(process.argv)

  // --skill: output LLM-readable guide and exit
  if (args.skill) {
    printSkill()
    return
  }

  // --json: merge stdin JSON with CLI args
  if (args.jsonInput) {
    const json = await readJsonInput()
    args = mergeJsonInput(args, json)
  }

  if (!args.url) {
    printGettingStarted()
    return
  }

  // Resolve person server URL from config if not provided
  const personServer = resolvePersonServer(args.agentUrl, args.personServer)

  // Build key material function
  const getKeyMaterial = buildGetKeyMaterial(args)

  // Build request init
  const init = buildRequestInit(args)

  const url = args.url!

  if (args.authorize) {
    await handleAuthorize({ ...args, url }, getKeyMaterial, personServer)
  } else if (args.authToken && args.signingKey) {
    await handlePreAuthed({ ...args, url, authToken: args.authToken, signingKey: args.signingKey }, init)
  } else if (args.agentOnly) {
    await handleAgentOnly({ ...args, url }, init, getKeyMaterial)
  } else {
    await handleFullFlow({ ...args, url }, init, getKeyMaterial, personServer)
  }
}

run().catch((err: Error) => {
  console.error(JSON.stringify({ error: err.message }))
  process.exitCode = 1
})
