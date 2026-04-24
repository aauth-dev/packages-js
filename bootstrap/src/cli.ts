#!/usr/bin/env node

import {
  generateKey,
  generateKid,
  toPublicJwk,
  readKeychain,
  writeKeychain,
  listAgentUrls,
  discoverBackends,
  getBackend,
  readConfig,
  addKeyToAgent,
  setPersonServer,
  setHosting,
  setAgentConfig,
  getAgentConfig,
  listConfiguredAgents,
  signAgentToken,
  resolveKey,
  validateUrl,
  ensureAgentUrls,
} from '@aauth/local-keys'
import type { KeyAlgorithm, KeyBackend, AAuthPublicJwk } from '@aauth/local-keys'
import { listSkills, getSkill } from './skills.js'
import { bootstrapWithPS } from './bootstrap-ps.js'
import open from 'open'

function parseArgs(args: string[]) {
  const flags: Record<string, string> = {}
  const positional: string[] = []
  // Alias map: short flag → canonical flag
  const aliases: Record<string, string> = { ps: 'person-server' }
  for (let i = 0; i < args.length; i++) {
    if (args[i].startsWith('--') && i + 1 < args.length && !args[i + 1].startsWith('--')) {
      const key = aliases[args[i].slice(2)] ?? args[i].slice(2)
      flags[key] = args[i + 1]
      i++
    } else if (args[i].startsWith('--')) {
      const key = aliases[args[i].slice(2)] ?? args[i].slice(2)
      flags[key] = 'true'
    } else {
      positional.push(args[i])
    }
  }
  return { flags, positional }
}

// === Commands ===

function cmdDiscover() {
  console.log(JSON.stringify(discoverBackends(), null, 2))
}

async function cmdGenerate(flags: Record<string, string>) {
  const backend = (flags.backend || 'software') as KeyBackend
  const algorithm = (flags.algorithm || (backend === 'software' ? 'EdDSA' : 'ES256')) as KeyAlgorithm
  const agentUrl = flags.agent
  const kid = generateKid()

  const driver = getBackend(backend)
  const deviceLabel = driver.getDeviceLabel()

  let publicJwk: AAuthPublicJwk

  if (backend === 'software') {
    const { privateJwk, publicJwk: pubJwk } = await generateKey()
    const actualKid = pubJwk.kid || kid
    publicJwk = {
      ...toPublicJwk(pubJwk),
      kid: actualKid,
      aauth: { device: deviceLabel, created: new Date().toISOString().slice(0, 10) },
    }

    if (agentUrl) {
      ensureAgentUrls(agentUrl)
      const existing = readKeychain(agentUrl)
      const data = existing ?? { current: actualKid, keys: {} }
      data.current = actualKid
      data.keys[actualKid] = privateJwk
      writeKeychain(agentUrl, data)

      addKeyToAgent(agentUrl, actualKid, {
        backend: 'software',
        algorithm: 'EdDSA',
        keyId: actualKid,
        deviceLabel,
      })
    }
  } else {
    const keyRef = await driver.generateKey(algorithm)
    publicJwk = {
      ...keyRef.publicJwk,
      kid,
      aauth: { device: deviceLabel, created: new Date().toISOString().slice(0, 10) },
    }

    if (agentUrl) {
      ensureAgentUrls(agentUrl)
      addKeyToAgent(agentUrl, kid, {
        backend,
        algorithm,
        keyId: keyRef.keyId,
        deviceLabel,
      })
    }
  }

  console.log(JSON.stringify({ kid: publicJwk.kid, publicJwk }, null, 2))
}

async function cmdSignToken(flags: Record<string, string>) {
  const agentUrl = flags.agent
  const lifetime = parseInt(flags.lifetime || '3600', 10)

  if (!agentUrl) {
    console.error(JSON.stringify({ error: '--agent <url> required' }))
    process.exitCode = 1
    return
  }

  // Resolve agent identifier from --agent-id flag or config
  const agentId = flags['agent-id'] ?? getAgentConfig(agentUrl)?.agentId
  if (!agentId) {
    console.error(JSON.stringify({ error: 'No agent identifier. Run bootstrap with --ps first, or pass --agent-id.' }))
    process.exitCode = 1
    return
  }

  const result = await signAgentToken({ agentUrl, sub: agentId, lifetime })
  console.log(JSON.stringify(result, null, 2))
}

async function cmdPublicKey(flags: Record<string, string>) {
  const agentUrl = flags.agent
  if (!agentUrl) {
    const backends = discoverBackends()
    const allKeys: Array<{ backend: string; keyId: string; publicJwk: unknown }> = []
    for (const info of backends) {
      const driver = getBackend(info.backend)
      try {
        const keys = await driver.listKeys()
        for (const k of keys) {
          if (k.publicJwk && k.publicJwk.kty) {
            allKeys.push({ backend: k.backend, keyId: k.keyId, publicJwk: k.publicJwk })
          }
        }
      } catch { /* skip */ }
    }
    console.log(JSON.stringify(allKeys, null, 2))
    return
  }

  try {
    const resolved = await resolveKey(agentUrl)
    const driver = getBackend(resolved.backend)
    const pubJwk = await driver.getPublicKey(resolved.keyId)
    console.log(JSON.stringify(pubJwk, null, 2))
  } catch (e) {
    console.error(JSON.stringify({ error: (e as Error).message }))
    process.exitCode = 1
  }
}

function cmdAddAgent(flags: Record<string, string>, positional: string[]) {
  const agentUrl = positional[1]
  if (!agentUrl) {
    console.error(JSON.stringify({ error: 'agent URL required' }))
    process.exitCode = 1
    return
  }

  const urlError = validateUrl(agentUrl)
  if (urlError) {
    console.error(JSON.stringify({ error: `${agentUrl} — ${urlError}` }))
    process.exitCode = 1
    return
  }

  ensureAgentUrls(agentUrl)

  if (flags['jwks-uri']) {
    const existing = getAgentConfig(agentUrl)
    setAgentConfig(agentUrl, { ...existing!, jwksUri: flags['jwks-uri'] })
  }

  if (flags.hosting) {
    setHosting(agentUrl, {
      platform: flags.hosting,
      repo: flags.repo,
    })
  }

  if (flags.kid && flags.backend && flags['key-id']) {
    addKeyToAgent(agentUrl, flags.kid, {
      backend: flags.backend as KeyBackend,
      algorithm: (flags.algorithm || 'ES256') as KeyAlgorithm,
      keyId: flags['key-id'],
      deviceLabel: flags.device || 'unknown',
    })
  }

  const config = getAgentConfig(agentUrl)
  console.log(JSON.stringify({ agentUrl, config }, null, 2))
}

function cmdConfig() {
  console.log(JSON.stringify(readConfig(), null, 2))
}

function cmdShow() {
  const backends = discoverBackends()
  console.log('Available backends:')
  for (const b of backends) {
    console.log(`  ${b.backend} — ${b.description} [${b.algorithms.join(', ')}]`)
  }

  const agents = listConfiguredAgents()
  if (agents.length > 0) {
    console.log('\nConfigured agents:')
    for (const url of agents) {
      const ac = getAgentConfig(url)
      if (!ac) continue
      console.log(`  ${url}`)
      if (ac.personServerUrl) console.log(`    person-server: ${ac.personServerUrl}`)
      for (const [kid, meta] of Object.entries(ac.keys)) {
        console.log(`    ${kid} [${meta.algorithm}] ${meta.backend} (${meta.deviceLabel})`)
      }
    }
  }

  const urls = listAgentUrls()
  if (urls.length > 0) {
    console.log('\nSoftware keys in keychain:')
    for (const url of urls) {
      const data = readKeychain(url)
      if (!data) continue
      for (const [kid, jwk] of Object.entries(data.keys)) {
        const marker = kid === data.current ? ' (current)' : ''
        const alg = jwk.crv === 'P-256' ? 'ES256' : 'EdDSA'
        console.log(`  ${url} ${kid}${marker} [${alg}]`)
      }
    }
  }
}

function cmdSkill(name?: string) {
  if (!name) {
    console.log(JSON.stringify(listSkills(), null, 2))
    return
  }

  const skill = getSkill(name)
  if (!skill) {
    console.error(JSON.stringify({ error: `Unknown skill: "${name}"` }))
    process.exitCode = 1
    return
  }

  console.log(skill.body)
}

function cmdHelp() {
  console.log(`Usage: npx @aauth/bootstrap <command> [options]

Commands:
  discover                 List available key backends (JSON)
  generate [options]       Generate a key pair, output public JWK (JSON)
  sign-token [options]     Sign an agent token with ephemeral cnf (JSON)
  public-key [options]     Output public key(s) (JSON)
  add-agent <url> [opts]   Register an agent URL in config
  config                   Dump ~/.aauth/config.json
  show                     Human-readable status overview
  skill                    List available skills (JSON)
  skill <name>             Show full skill instructions
  help                     Show this help

Generate options:
  --backend <name>         software (default), yubikey-piv, secure-enclave
  --algorithm <alg>        EdDSA (default for software), ES256, RS256
  --agent <url>            Associate key with an agent URL

Sign-token options:
  --agent <url>            Agent URL (required)
  --agent-id <id>          Agent identifier (default: from config)
  --lifetime <seconds>     Token lifetime (default: 3600)

Add-agent options:
  --kid <kid>              Key ID to associate
  --backend <name>         Key backend
  --key-id <id>            Backend-specific key ID (slot, label, etc.)
  --algorithm <alg>        Key algorithm

Person server bootstrap (can be combined with any command):
  --person-server <url>    Bootstrap with person server (alias: --ps)
  --local <name>           Local part of agent identifier (default: "local")
  --login-hint <hint>      Hint about who to authorize
  --domain-hint <domain>   Domain/org routing hint
  --provider-hint <name>   Upstream identity provider hint
  --tenant <id>            Tenant identifier

Examples:
  npx @aauth/bootstrap discover
  npx @aauth/bootstrap generate --backend yubikey-piv
  npx @aauth/bootstrap generate --backend secure-enclave --agent https://me.github.io
  npx @aauth/bootstrap sign-token --agent https://me.github.io
  npx @aauth/bootstrap add-agent https://me.github.io
  npx @aauth/bootstrap --ps https://hello.coop
  npx @aauth/bootstrap generate --agent https://me.github.io --ps https://hello.coop
  npx @aauth/bootstrap public-key --agent https://me.github.io`)
}

async function runBootstrapPS(flags: Record<string, string>) {
  const personServerUrl = flags['person-server']
  if (!personServerUrl) return

  const urlError = validateUrl(personServerUrl)
  if (urlError) {
    console.error(JSON.stringify({ error: `person-server: ${personServerUrl} — ${urlError}` }))
    process.exitCode = 1
    return
  }

  // Resolve agent URL from --agent flag or sole configured agent
  let agentUrl = flags.agent
  if (!agentUrl) {
    const configured = listConfiguredAgents()
    if (configured.length === 1) {
      agentUrl = configured[0]
    } else if (configured.length === 0) {
      console.error(JSON.stringify({ error: 'No agent configured. Use --agent <url> or run add-agent first.' }))
      process.exitCode = 1
      return
    } else {
      console.error(JSON.stringify({ error: 'Multiple agents configured. Use --agent <url> to specify.' }))
      process.exitCode = 1
      return
    }
  }

  console.error(`Bootstrapping ${agentUrl} with person server ${personServerUrl}...`)

  await bootstrapWithPS({
    agentUrl,
    personServerUrl,
    local: flags.local,
    loginHint: flags['login-hint'],
    domainHint: flags['domain-hint'],
    providerHint: flags['provider-hint'],
    tenant: flags.tenant,
    onInteraction: (interactionEndpoint, code) => {
      const url = `${interactionEndpoint}?code=${code}`
      console.error(`Opening browser for consent: ${url}`)
      open(url)
    },
  })

  console.error('Bootstrap complete. Person server registered.')
}

async function run() {
  const { flags, positional } = parseArgs(process.argv.slice(2))
  const command = positional[0]

  if (!command) {
    // No command: if --person-server is present, bootstrap; otherwise show status
    if (flags['person-server']) {
      await runBootstrapPS(flags)
      return
    }
    cmdShow()
    return
  }

  switch (command) {
    case 'discover': cmdDiscover(); break
    case 'generate': await cmdGenerate(flags); break
    case 'sign-token': await cmdSignToken(flags); break
    case 'public-key': await cmdPublicKey(flags); break
    case 'add-agent': cmdAddAgent(flags, positional); break
    case 'config': cmdConfig(); break
    case 'show': cmdShow(); break
    case 'skill': cmdSkill(positional[1]); break
    case 'help': cmdHelp(); break
    default:
      console.error(`Unknown command: ${command}`)
      cmdHelp()
      process.exitCode = 1
  }

  // After any command, run PS bootstrap if --person-server is present
  if (flags['person-server'] && process.exitCode !== 1) {
    await runBootstrapPS(flags)
  }
}

run().catch((err) => {
  console.error(JSON.stringify({ error: err.message }))
  process.exitCode = 1
})
