import type { FetchArgs } from './args.js'
import { FLAGS } from './args.js'

export interface JsonRequest {
  url: string
  method?: string
  headers?: Record<string, string>
  body?: unknown
  // Spec-defined fields use the spec's snake_case names; our own artifacts
  // (signingKey, agentProvider, personServer, agentOnly, local) stay camelCase.
  auth_token?: string
  aauth_access_token?: string
  signingKey?: JsonWebKey
  agentProvider?: string
  local?: string
  operations?: string
  scope?: string
  personServer?: string
  agentOnly?: boolean
  emit?: boolean
  login_hint?: string
  domain_hint?: string
  tenant?: string
  justification?: string
  prompt?: string
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

/**
 * Merge a JSON-stdin request spec onto parsed CLI args. CLI flags win only where
 * JSON omits the field. Field-name mapping and value transforms are driven by the
 * `json`/`jsonKind` entries in FLAGS (see args.ts) — the one place flags are
 * declared — so this never drifts from the parser. `url` is the lone special case
 * (a positional, not a flag).
 */
export function mergeJsonInput(args: FetchArgs, json: JsonRequest): FetchArgs {
  const merged = { ...args } as FetchArgs
  const ref = merged as unknown as Record<string, unknown>
  const src = json as unknown as Record<string, unknown>

  merged.url = json.url ?? args.url

  for (const f of FLAGS) {
    if (!f.json) continue
    const raw = src[f.json]
    switch (f.jsonKind) {
      case 'body': // request body → JSON-encoded `data`
        if (raw !== undefined) ref[f.field] = JSON.stringify(raw)
        break
      case 'headers': // { k: v } → ["k: v", …]
        if (raw && typeof raw === 'object') {
          ref[f.field] = Object.entries(raw as Record<string, string>).map(([k, v]) => `${k}: ${v}`)
        }
        break
      case 'json': // JWK / object → stringified
        if (raw) ref[f.field] = JSON.stringify(raw)
        break
      default: // 'string' | 'boolean' | 'array' — assign as-is
        if (raw !== undefined) ref[f.field] = raw
    }
  }

  return merged
}
