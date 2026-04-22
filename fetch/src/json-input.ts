import type { FetchArgs } from './args.js'

export interface JsonRequest {
  url: string
  method?: string
  headers?: Record<string, string>
  body?: unknown
  authToken?: string
  signingKey?: JsonWebKey
  agentUrl?: string
  local?: string
  operations?: string
  scope?: string
  personServer?: string
  authorize?: boolean
  agentOnly?: boolean
  loginHint?: string
  domainHint?: string
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
    authToken: json.authToken ?? args.authToken,
    signingKey: json.signingKey ? JSON.stringify(json.signingKey) : args.signingKey,
    agentUrl: json.agentUrl ?? args.agentUrl,
    local: json.local ?? args.local,
    operations: json.operations ?? args.operations,
    scope: json.scope ?? args.scope,
    personServer: json.personServer ?? args.personServer,
    authorize: json.authorize ?? args.authorize,
    agentOnly: json.agentOnly ?? args.agentOnly,
    loginHint: json.loginHint ?? args.loginHint,
    domainHint: json.domainHint ?? args.domainHint,
    tenant: json.tenant ?? args.tenant,
    justification: json.justification ?? args.justification,
    capabilities: json.capabilities ?? args.capabilities,
  }
}
