import { readFileSync, writeFileSync, mkdirSync } from 'node:fs'
import { join } from 'node:path'
import { homedir } from 'node:os'
import type { AAuthConfig, AgentConfig, AgentHosting, LocalKeyMeta } from './types.js'

const CONFIG_DIR = join(homedir(), '.aauth')
const CONFIG_FILE = join(CONFIG_DIR, 'config.json')

export function getConfigDir(): string {
  return CONFIG_DIR
}

export function readConfig(): AAuthConfig {
  try {
    const raw = readFileSync(CONFIG_FILE, 'utf-8')
    const parsed = JSON.parse(raw) as AAuthConfig
    // Ensure agents map exists
    if (!parsed.agents) parsed.agents = {}
    return parsed
  } catch {
    return { agents: {} }
  }
}

export function writeConfig(config: AAuthConfig): void {
  mkdirSync(CONFIG_DIR, { recursive: true })
  writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2) + '\n')
}

export function getAgentConfig(agentUrl: string): AgentConfig | null {
  const config = readConfig()
  return config.agents[agentUrl] ?? null
}

export function setAgentConfig(agentUrl: string, agentConfig: AgentConfig): void {
  const config = readConfig()
  config.agents[agentUrl] = agentConfig
  writeConfig(config)
}

export function addKeyToAgent(agentUrl: string, kid: string, meta: LocalKeyMeta): void {
  const config = readConfig()
  if (!config.agents[agentUrl]) {
    config.agents[agentUrl] = { keys: {} }
  }
  config.agents[agentUrl].keys[kid] = meta
  writeConfig(config)
}

export function setPersonServer(agentUrl: string, personServerUrl: string): void {
  const config = readConfig()
  if (!config.agents[agentUrl]) {
    config.agents[agentUrl] = { keys: {} }
  }
  config.agents[agentUrl].personServerUrl = personServerUrl
  writeConfig(config)
}

export function setHosting(agentUrl: string, hosting: AgentHosting): void {
  const config = readConfig()
  if (!config.agents[agentUrl]) {
    config.agents[agentUrl] = { keys: {} }
  }
  config.agents[agentUrl].hosting = hosting
  writeConfig(config)
}

export function listConfiguredAgents(): string[] {
  const config = readConfig()
  return Object.keys(config.agents)
}
