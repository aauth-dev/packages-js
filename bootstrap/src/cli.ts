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
  listAgentProviders,
  readKeychain,
  writeKeychain,
  signAgentToken,
  validateUrl,
  ensureAgentUrls,
} from '@aauth/local-keys'
import type { LocalKeyMeta } from '@aauth/local-keys'
import { deleteAgent, uninstall, listBackups } from './teardown.js'
import { bootstrapWithPS } from './bootstrap-ps.js'
import { listSkills, getSkill } from './skills.js'
import { parseArgs } from './args.js'
import {
  topLevelHelp,
  COMMAND_HELP,
  shapeKeystores,
  renderSkillListMarkdown,
  withProtocolSpec,
  colorizeJson,
} from './render.js'
import {
  resolveProvider,
  resolveKeystoreAlgorithm,
  resolveAgentId,
  resolveLifetime,
} from './resolve.js'

/** A JWK is opaque here — we only pass it through to JSON output. */
type Jwk = unknown

const pkg = createRequire(import.meta.url)('../package.json') as { version: string }

const DEFAULT_PERSON_SERVER = 'https://person.hello.coop'

// === output helpers (stdout = result, stderr = errors) ===

function printResult(value: unknown): void {
  const json = JSON.stringify(value, null, 2)
  // Color only at a TTY; piped/redirected or NO_COLOR stays plain so ANSI codes
  // never reach `jq` or an agent reading the JSON.
  const useColor = process.stdout.isTTY === true && !process.env.NO_COLOR
  console.log(useColor ? colorizeJson(json) : json)
}

function fail(message: string): void {
  console.error(JSON.stringify({ error: message }))
  process.exitCode = 1
}

// === shared helpers ===

/** Read a flag's value as a string, or undefined if absent/boolean. */
function flagStr(flags: Record<string, string | boolean>, key: string): string | undefined {
  return typeof flags[key] === 'string' ? flags[key] as string : undefined
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

/**
 * Re-attach the `aauth` metadata (device + created) that `create` publishes, so
 * `list` shows the same public-key shape. `created` comes from the kid's date
 * prefix (`YYYY-MM-DD_hex`); `device` from the stored key metadata.
 */
function withAauthMeta(pub: Jwk | null, meta: LocalKeyMeta, kid: string): Jwk | null {
  if (!pub || typeof pub !== 'object') return pub
  const created = kid.includes('_') ? kid.split('_')[0] : undefined
  return { ...(pub as Record<string, unknown>), aauth: { device: meta.deviceLabel, created } }
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
      const publicJwk = withAauthMeta(await resolvePublicJwk(url, kid, meta), meta, kid)
      keys.push({ kid, keystore: meta.backend, publicJwk })
    }
    agentProviders.push({
      url,
      agentId: cfg.agentId ?? null,
      personServer: cfg.personServerUrl ?? null,
      hosting: cfg.hosting ?? null,
      jwksUri: cfg.jwksUri ?? null,
      keys,
    })
  }

  // Surface uninstall backups so setup can offer to reuse a prior identity's
  // settings (agent URL, person server, hosting) — fresh keys, same config.
  printResult({ keystores, agentProviders, backups: listBackups() })
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

  const { keystore, algorithm } = resolveKeystoreAlgorithm(flagStr(flags, 'keystore'), flagStr(flags, 'algorithm'))
  const personServer = flagStr(flags, 'person-server') ?? DEFAULT_PERSON_SERVER
  const local = flagStr(flags, 'local')

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

  const result = await deleteAgent(url)
  if (!result) return fail(`Agent provider not found: ${url}`)
  printResult(result)
}

async function cmdUninstall(flags: Record<string, string | boolean>): Promise<void> {
  printResult(await uninstall({ force: flags.force === true }))
}

async function cmdToken(flags: Record<string, string | boolean>): Promise<void> {
  const { url, error } = resolveProvider(flagStr(flags, 'agent-provider'), listAgentProviders())
  if (error || !url) return fail(error ?? 'No agent provider configured.')

  const agentId = resolveAgentId({
    explicit: flagStr(flags, 'agent-id'),
    local: flagStr(flags, 'local'),
    host: new URL(url).hostname,
    configAgentId: getAgentConfig(url)?.agentId,
  })
  if (!agentId) {
    return fail(`No agent identifier for ${url}. Pass --agent-id, or run \`create\` to configure one.`)
  }

  const lifetime = resolveLifetime(flagStr(flags, 'lifetime'))
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
  console.log(withProtocolSpec(skill.body))
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
    case 'uninstall': await cmdUninstall(flags); break
    case 'token': await cmdToken(flags); break
    case 'skill': cmdSkill(positional[1]); break
    default:
      fail(`Unknown command: ${command}. Run \`npx @aauth/bootstrap help\`.`)
  }
}

run().catch((err: Error) => {
  fail(err.message)
})
