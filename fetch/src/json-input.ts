import type { FetchArgs } from './args.js'

export interface JsonRequest {
  url: string
  method?: string
  headers?: Record<string, string>
  body?: unknown
  // Spec-defined fields use the spec's snake_case names; our own artifacts
  // (signingKey, agentProvider, personServer, agentOnly, local) stay camelCase.
  auth_token?: string
  signingKey?: JsonWebKey
  agentProvider?: string
  local?: string
  operations?: string
  scope?: string
  personServer?: string
  agentOnly?: boolean
  login_hint?: string
  domain_hint?: string
  tenant?: string
  justification?: string
  capabilities?: string[]
}

export async function readJsonInput(): Promise<JsonRequest> {
  const chunks: Buffer[] = []
  for await (const chunk of process.stdin) {
    chunks.push(chunk as Buffer)
  }
  const raw = Buffer.concat(chunks).toString('utf-8').trim()
  if (!raw) {
    throw new Error('No JSON input on stdin')
  }
  return JSON.parse(raw) as JsonRequest
}

export function mergeJsonInput(args: FetchArgs, json: JsonRequest): FetchArgs {
  return {
    ...args,
    url: json.url ?? args.url,
    method: json.method ?? args.method,
    headers: json.headers
      ? Object.entries(json.headers).map(([k, v]) => `${k}: ${v}`)
      : args.headers,
    data: json.body !== undefined ? JSON.stringify(json.body) : args.data,
    authToken: json.auth_token ?? args.authToken,
    signingKey: json.signingKey ? JSON.stringify(json.signingKey) : args.signingKey,
    agentProvider: json.agentProvider ?? args.agentProvider,
    local: json.local ?? args.local,
    operations: json.operations ?? args.operations,
    scope: json.scope ?? args.scope,
    personServer: json.personServer ?? args.personServer,
    agentOnly: json.agentOnly ?? args.agentOnly,
    loginHint: json.login_hint ?? args.loginHint,
    domainHint: json.domain_hint ?? args.domainHint,
    tenant: json.tenant ?? args.tenant,
    justification: json.justification ?? args.justification,
    capabilities: json.capabilities ?? args.capabilities,
  }
}
