#!/usr/bin/env node

import { createRequire } from 'node:module'
import {
  generateKey,
  generateKid,
  toPublicJwk,
  discoverBackends,
  getBackend,
  getAgentConfig,
  addKeyToAgent,
  deleteAgentProvider,
  listAgentProviders,
  readKeychain,
  writeKeychain,
  deleteKeychain,
  signAgentToken,
  validateUrl,
  ensureAgentUrls,
  KeyDeletionUnsupportedError,
} from '@aauth/local-keys'
import type { KeyAlgorithm, KeyBackend, LocalKeyMeta } from '@aauth/local-keys'
import { bootstrapWithPS } from './bootstrap-ps.js'
import { listSkills, getSkill } from './skills.js'
import { parseArgs } from './args.js'
import {
  topLevelHelp,
  COMMAND_HELP,
  shapeKeystores,
  renderSkillListMarkdown,
} from './render.js'

/** A JWK is opaque here — we only pass it through to JSON output. */
type Jwk = unknown

const pkg = createRequire(import.meta.url)('../package.json') as { version: string }

const DEFAULT_PERSON_SERVER = 'https://person.hello.coop'

// === output helpers (stdout = result, stderr = errors) ===

function printResult(value: unknown): void {
  console.log(JSON.stringify(value, null, 2))
}

function fail(message: string): void {
  console.error(JSON.stringify({ error: message }))
  process.exitCode = 1
}

// === shared helpers ===

/** Resolve the agent provider URL: explicit flag, else the sole configured one. */
function resolveProvider(explicit?: string): { url?: string; error?: string } {
  if (explicit) return { url: explicit }
  const providers = listAgentProviders()
  if (providers.length === 1) return { url: providers[0] }
  if (providers.length === 0) {
    return { error: 'No agent provider configured. Run `create <agent-provider-url>` first.' }
  }
  return { error: 'Multiple agent providers configured. Pass --agent-provider <url>.' }
}

/** Best-effort public JWK for a configured key (software from keychain, hardware from the device). */
async function resolvePublicJwk(agentUrl: string, kid: string, meta: LocalKeyMeta): Promise<Jwk | null> {
  if (meta.backend === 'software') {
    const data = readKeychain(agentUrl)
    const jwk = data?.keys[kid]
    return jwk ? toPublicJwk(jwk) : null
  }
  try {
    return await getBackend(meta.backend).getPublicKey(meta.keyId)
  } catch {
    return null
  }
}

// === commands ===

async function cmdList(): Promise<void> {
  const keystores = shapeKeystores(discoverBackends())

  const agentProviders = []
  for (const url of listAgentProviders()) {
    const cfg = getAgentConfig(url)
    if (!cfg) continue
    const keys = []
    for (const [kid, meta] of Object.entries(cfg.keys)) {
      keys.push({ kid, keystore: meta.backend, publicJwk: await resolvePublicJwk(url, kid, meta) })
    }
    agentProviders.push({
      url,
      agentId: cfg.agentId ?? null,
      personServer: cfg.personServerUrl ?? null,
      keys,
    })
  }

  printResult({ keystores, agentProviders })
}

async function cmdCreate(positional: string[], flags: Record<string, string | boolean>): Promise<void> {
  const url = positional[1]
  if (!url) return fail('Usage: create <agent-provider-url>')

  const urlError = validateUrl(url)
  if (urlError) return fail(`${url} — ${urlError}`)

  const existing = getAgentConfig(url)
  if (existing && Object.keys(existing.keys).length > 0) {
    return fail(`Agent provider already exists: ${url} (delete it first to re-create)`)
  }

  const keystore = (typeof flags.keystore === 'string' ? flags.keystore : 'software') as KeyBackend
  const algorithm = (typeof flags.algorithm === 'string'
    ? flags.algorithm
    : keystore === 'software' ? 'EdDSA' : 'ES256') as KeyAlgorithm
  const personServer = typeof flags['person-server'] === 'string'
    ? flags['person-server']
    : DEFAULT_PERSON_SERVER
  const local = typeof flags.local === 'string' ? flags.local : undefined

  const driver = getBackend(keystore)
  const deviceLabel = driver.getDeviceLabel()
  const created = new Date().toISOString().slice(0, 10)

  ensureAgentUrls(url)

  let kid: string
  let publicJwk: Jwk

  if (keystore === 'software') {
    const { privateJwk, publicJwk: pub } = await generateKey(algorithm === 'ES256' ? 'ES256' : 'EdDSA')
    kid = pub.kid as string
    publicJwk = { ...pub, aauth: { device: deviceLabel, created } } as Jwk
    writeKeychain(url, { current: kid, keys: { [kid]: privateJwk } })
    addKeyToAgent(url, kid, { backend: 'software', algorithm, keyId: kid, deviceLabel })
  } else {
    const ref = await driver.generateKey(algorithm)
    kid = generateKid()
    publicJwk = { ...ref.publicJwk, kid, aauth: { device: deviceLabel, created } } as Jwk
    addKeyToAgent(url, kid, { backend: keystore, algorithm, keyId: ref.keyId, deviceLabel })
  }

  // Bind a person server (fetches + validates its metadata, persists agentId + ps).
  const psError = validateUrl(personServer)
  if (psError) return fail(`person-server: ${personServer} — ${psError}`)
  await bootstrapWithPS({ agentUrl: url, personServerUrl: personServer, local })

  const cfg = getAgentConfig(url)
  printResult({
    agentProvider: url,
    agentId: cfg?.agentId ?? null,
    personServer: cfg?.personServerUrl ?? null,
    keys: [{ kid, keystore, publicJwk }],
  })
}

async function cmdDelete(positional: string[]): Promise<void> {
  const url = positional[1]
  if (!url) return fail('Usage: delete <agent-provider-url>')

  const cfg = getAgentConfig(url)
  if (!cfg) return fail(`Agent provider not found: ${url}`)

  let keysDeleted = 0
  const hardwareKeysRetained: Array<{ kid: string; keystore: string; keyId: string; hint: string }> = []

  // Software keys are grouped under the agent URL in the OS keychain — wipe in one shot.
  if (readKeychain(url)) deleteKeychain(url)

  for (const [kid, meta] of Object.entries(cfg.keys)) {
    if (meta.backend === 'software') {
      keysDeleted++
      continue
    }
    const driver = getBackend(meta.backend)
    try {
      await driver.deleteKey?.(meta.keyId)
      keysDeleted++
    } catch (e) {
      if (e instanceof KeyDeletionUnsupportedError) {
        hardwareKeysRetained.push({ kid, keystore: meta.backend, keyId: meta.keyId, hint: e.hint })
      } else {
        throw e
      }
    }
  }

  deleteAgentProvider(url)

  const result: Record<string, unknown> = { deleted: url, keysDeleted }
  if (hardwareKeysRetained.length > 0) result.hardwareKeysRetained = hardwareKeysRetained
  printResult(result)
}

async function cmdToken(flags: Record<string, string | boolean>): Promise<void> {
  const { url, error } = resolveProvider(typeof flags['agent-provider'] === 'string' ? flags['agent-provider'] : undefined)
  if (error || !url) return fail(error ?? 'No agent provider configured.')

  // Resolve agentId: explicit > --local + domain > config.
  let agentId = typeof flags['agent-id'] === 'string' ? flags['agent-id'] : undefined
  if (!agentId) {
    if (typeof flags.local === 'string') {
      agentId = `aauth:${flags.local}@${new URL(url).hostname}`
    } else {
      agentId = getAgentConfig(url)?.agentId
    }
  }
  if (!agentId) {
    return fail(`No agent identifier for ${url}. Pass --agent-id, or run \`create\` to configure one.`)
  }

  const lifetime = typeof flags.lifetime === 'string' ? parseInt(flags.lifetime, 10) : 3600
  const result = await signAgentToken({ agentUrl: url, sub: agentId, lifetime })
  printResult(result)
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

function cmdHelp(command?: string): void {
  if (command && COMMAND_HELP[command]) {
    console.log(COMMAND_HELP[command])
    return
  }
  console.log(topLevelHelp(pkg.version))
}

// === entrypoint ===

async function run(): Promise<void> {
  const { command, positional, flags, help, version } = parseArgs(process.argv.slice(2))

  if (version) {
    console.log(pkg.version)
    return
  }

  // Bare invocation or no recognized command → top-level help.
  if (!command || command === 'help') {
    cmdHelp(positional[1])
    return
  }

  // `<command> --help` / `-h` → that command's help.
  if (help) {
    cmdHelp(command)
    return
  }

  switch (command) {
    case 'list': await cmdList(); break
    case 'create': await cmdCreate(positional, flags); break
    case 'delete': await cmdDelete(positional); break
    case 'token': await cmdToken(flags); break
    case 'skill': cmdSkill(positional[1]); break
    default:
      fail(`Unknown command: ${command}. Run \`npx @aauth/bootstrap help\`.`)
  }
}

run().catch((err: Error) => {
  fail(err.message)
})
