import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js'
import { createSignedFetch, getPersonToken } from '@aauth/agent'
import type { FetchLike, GetKeyMaterial, KeyMaterial } from '@aauth/agent'
import { decodeJwtPayload, parseRequirementHeader, planAccessMode } from '@aauth/protocol'
import type { Transport } from '@modelcontextprotocol/sdk/shared/transport.js'

interface ManagedServer {
  name: string
  url: string
  client: Client
  transport: Transport
  tools: Map<string, string> // prefixed name → original name
}

/**
 * Person server metadata, `/.well-known/aauth-person.json`.
 *
 * `auth_token_endpoint` is the -11 name for what was `token_endpoint`;
 * `person_token_endpoint` is new and REQUIRED — it is where the agent obtains
 * the person token a resource must have verified before it will issue a
 * resource token.
 */
export interface PersonServerMetadata {
  auth_token_endpoint: string
  person_token_endpoint: string
  jwks_uri?: string
  [key: string]: unknown
}

/** A configured server this agent's setup cannot use, and why. */
export interface SkippedServer {
  name: string
  url: string
  /** The `access_mode` the resource declared. */
  mode: string
  reason: string
}

export interface ServerManagerOptions {
  servers: Record<string, string> // name → url
  getKeyMaterial: GetKeyMaterial
  /** Person server URL. Defaults to the `ps` claim of the agent token. */
  personServerUrl?: string
  /** Cached PS metadata; when provided the person token request skips the
   *  /.well-known fetch. */
  personServerMetadata?: PersonServerMetadata
  /** Called with freshly-fetched PS metadata so the caller can persist it. */
  onPersonServerMetadata?: (metadata: PersonServerMetadata) => void
  /** Mission the agent is operating under; stamped into the person token. */
  missionS256?: string
  onInteraction?: (url: string, code: string) => void
}

interface CachedPersonToken {
  token: string
  expiresAt: number
}

/** Refresh a person token this far before it expires. */
const PERSON_TOKEN_SKEW_MS = 60_000

export class ServerManager {
  private servers = new Map<string, ManagedServer>()
  /** server name → person token for that server's resource. */
  private personTokens = new Map<string, CachedPersonToken>()
  private skipped = new Map<string, SkippedServer>()
  private personServerMetadata?: PersonServerMetadata
  /** Signs with the agent token — used to talk to the person server. */
  private agentSignedFetch: FetchLike

  constructor(private options: ServerManagerOptions) {
    this.agentSignedFetch = createSignedFetch(options.getKeyMaterial)
    this.personServerMetadata = options.personServerMetadata
  }

  async connectAll(): Promise<void> {
    const entries = Object.entries(this.options.servers)
    await Promise.all(entries.map(([name, url]) => this.connect(name, url)))
  }

  private async connect(name: string, url: string): Promise<void> {
    // The resource identifier is the origin — the `resource` the person token
    // is requested for and the token's `aud`.
    const resource = new URL(url).origin

    const plan = planAccessMode(await this.fetchAccessMode(resource), {
      hasPersonServer: (await this.personServer()) !== undefined,
    })
    if (plan.kind === 'unsatisfiable') {
      this.skipped.set(name, { name, url, mode: plan.mode, reason: plan.reason })
      return
    }

    // `person-token` and `auth-token` both put a person token on the wire from
    // the first call: a resource MUST have verified one before it issues a
    // resource token. Every other mode starts on the agent token and upgrades
    // if the resource challenges with requirement=person-token.
    if (plan.kind === 'satisfiable' && (plan.mode === 'person-token' || plan.mode === 'auth-token')) {
      await this.ensurePersonToken(name, resource)
    }

    const transport = new StreamableHTTPClientTransport(new URL(url), {
      fetch: this.createResourceFetch(name, resource),
    })

    const client = new Client({ name: `aauth-${name}`, version: '0.0.1' })
    await client.connect(transport)

    const { tools } = await client.listTools()
    const toolMap = new Map<string, string>()
    for (const tool of tools) {
      toolMap.set(`${name}_${tool.name}`, tool.name)
    }

    this.servers.set(name, { name, url, client, transport, tools: toolMap })
  }

  /**
   * A signed fetch for one resource that satisfies a person-token challenge.
   *
   * The key material getter picks up the person token as soon as there is one,
   * so a retry after `requirement=person-token` presents it via Signature-Key
   * in place of the agent token.
   */
  private createResourceFetch(name: string, resource: string): FetchLike {
    const signedFetch = createSignedFetch(() => this.keyMaterialFor(name))
    return async (url: string | URL, init?: RequestInit): Promise<Response> => {
      const response = await signedFetch(url, init)
      if (response.status !== 401) return response

      const header = response.headers.get('aauth-requirement')
      if (!header) return response

      // A requirement value this agent does not recognize throws
      // UnsupportedRequirementError out of parseRequirementHeader — the
      // response is not satisfiable and the error reaches the caller.
      const challenge = parseRequirementHeader(header)
      if (challenge.requirement !== 'person-token') return response

      // Only retry when the request body can be sent again.
      if (init?.body != null && typeof init.body !== 'string') return response

      this.personTokens.delete(name)
      await this.ensurePersonToken(name, resource)
      return signedFetch(url, init)
    }
  }

  /** The agent token, or the person token for `name` once there is one. */
  private async keyMaterialFor(name: string): Promise<KeyMaterial> {
    const keyMaterial = await this.options.getKeyMaterial()
    const cached = this.personTokens.get(name)
    if (!cached || cached.expiresAt <= Date.now() + PERSON_TOKEN_SKEW_MS) {
      return keyMaterial
    }
    return {
      signingKey: keyMaterial.signingKey,
      signatureKey: { type: 'jwt', jwt: cached.token },
    }
  }

  private async ensurePersonToken(name: string, resource: string): Promise<string> {
    const cached = this.personTokens.get(name)
    if (cached && cached.expiresAt > Date.now() + PERSON_TOKEN_SKEW_MS) {
      return cached.token
    }

    const personServerUrl = await this.personServer()
    if (!personServerUrl) {
      throw new Error(
        `${resource} requires a person token and this agent has no person server `
        + '(no "ps" claim in its agent token)',
      )
    }

    const result = await getPersonToken({
      signedFetch: this.agentSignedFetch,
      personServerUrl,
      personServerMetadata: this.personServerMetadata,
      onMetadata: (metadata: PersonServerMetadata) => {
        this.personServerMetadata = metadata
        this.options.onPersonServerMetadata?.(metadata)
      },
      resource,
      missionS256: this.options.missionS256,
      onInteraction: this.options.onInteraction,
    })

    this.personTokens.set(name, {
      token: result.personToken,
      expiresAt: Date.now() + result.expiresIn * 1000,
    })
    return result.personToken
  }

  /** Configured person server, else the agent token's `ps` claim. */
  private async personServer(): Promise<string | undefined> {
    if (this.options.personServerUrl) return this.options.personServerUrl
    const { signatureKey } = await this.options.getKeyMaterial()
    if (signatureKey.type === 'hwk') return undefined
    const ps = decodeJwtPayload(signatureKey.jwt).ps
    return typeof ps === 'string' ? ps : undefined
  }

  /**
   * The resource's declared `access_mode`, or undefined when it publishes no
   * metadata — planAccessMode treats that as undeclared, never an error.
   */
  private async fetchAccessMode(resource: string): Promise<string | undefined> {
    try {
      const response = await fetch(`${resource}/.well-known/aauth-resource.json`)
      if (!response.ok) return undefined
      const metadata = await response.json() as Record<string, unknown>
      return typeof metadata.access_mode === 'string' ? metadata.access_mode : undefined
    } catch {
      return undefined
    }
  }

  getTools(): Array<{ prefixedName: string; serverName: string; originalName: string; description?: string }> {
    const result: Array<{ prefixedName: string; serverName: string; originalName: string; description?: string }> = []
    for (const [, server] of this.servers) {
      for (const [prefixedName, originalName] of server.tools) {
        result.push({
          prefixedName,
          serverName: server.name,
          originalName,
        })
      }
    }
    return result
  }

  /** Servers not connected because this agent cannot satisfy their access mode. */
  getSkippedServers(): SkippedServer[] {
    return Array.from(this.skipped.values())
  }

  async callTool(
    prefixedName: string,
    args: Record<string, unknown>,
  ): Promise<unknown> {
    for (const [, server] of this.servers) {
      const originalName = server.tools.get(prefixedName)
      if (originalName) {
        return server.client.callTool({ name: originalName, arguments: args })
      }
    }
    throw new Error(`Unknown tool: ${prefixedName}`)
  }

  async shutdown(): Promise<void> {
    const closers = Array.from(this.servers.values()).map((s) =>
      s.transport.close().catch(() => {}),
    )
    await Promise.all(closers)
    this.servers.clear()
    this.personTokens.clear()
    this.skipped.clear()
  }
}
