import { R3Error } from './errors.js'
import { deepEqual, sha256Base64url, timingSafeEqualString, toBytes, type Bytes } from './util.js'
import {
  publishR3Document,
  parseR3Record,
  type R3Document,
  type R3Display,
  type R3ParameterDigest,
  type R3ParameterValue,
  type R3Record,
  type R3Store,
  type PublishedR3,
} from './r3.js'

/**
 * Per-call proposals (AAuth-R3 §Per-Call Proposals).
 *
 * An `r3_per_call` operation is authorized in principle but not for any
 * specific call. When the agent invokes one, the resource builds a proposal —
 * a full R3 document scoped to that one invocation, carrying a REQUIRED
 * `parameters` object — persists it, and challenges with a resource token
 * referencing it by `r3_uri`/`r3_s256`. The token carries the reference, never
 * the parameters.
 *
 * On the retry the resource recovers the proposal by `r3_s256` and MUST verify
 * the agent's actual parameters against it. Any difference is a rejection: an
 * approval to email one recipient cannot be replayed against another.
 *
 * ## Dispatch: `r3_s256` alone does not mean "per-call retry"
 *
 * A class-grant auth token carries the **class** document's `r3_s256`, and a
 * per-call retry carries the **proposal's**. Both are present, both are
 * strings, and nothing in the token distinguishes them. Branching on
 * `if (auth.r3_s256)` therefore sends every ordinary granted call into
 * {@link verifyProposalParameters}, which fails with `invalid_proposal` —
 * an error that points at the document rather than at the dispatch logic that
 * is actually wrong.
 *
 * What separates them is the proposal's REQUIRED `parameters`. So resolve the
 * reference and look, with {@link isProposal}:
 *
 * ```ts
 * const record = auth.r3_s256 ? await getR3ByHash(store, auth.r3_s256) : null
 *
 * if (isProposal(record)) {
 *   // A per-call retry. The parameters of this call must match the approval.
 *   await verifyProposalParameters({ store, r3_s256: record.s256, presented, operation })
 * } else if (inSet(auth.r3_granted, operation)) {
 *   // Authorized as a class. Run it.
 * } else if (inSet(auth.r3_per_call, operation)) {
 *   // Authorized in principle. Build a proposal for this call and challenge.
 * }
 * ```
 */

// --- Digest parameters ---

/**
 * Represent a large or sensitive parameter by a digest instead of the inline
 * value. Only the hash and the excerpt reach the PS; the full bytes travel
 * agent → resource at call time.
 */
export async function digestParameter(
  value: Bytes,
  options: { excerpt?: string; media_type?: string; excerptLength?: number } = {},
): Promise<R3ParameterDigest> {
  const digest: R3ParameterDigest = { s256: await sha256Base64url(value) }
  const excerpt = options.excerpt ?? (typeof value === 'string'
    ? truncate(value, options.excerptLength ?? 120)
    : undefined)
  if (excerpt !== undefined) digest.excerpt = excerpt
  if (options.media_type !== undefined) digest.media_type = options.media_type
  return digest
}

function truncate(value: string, max: number): string {
  return value.length <= max ? value : `${value.slice(0, max)}…`
}

/**
 * Is this a per-call proposal rather than a class R3 document?
 *
 * The one correct answer to the dispatch question above. A proposal is exactly
 * an R3 document carrying `parameters`; a class document never does. Accepts a
 * stored {@link R3Record} (parsed here), a parsed {@link R3Document}, or
 * `null`/`undefined` for "no document referenced", so a call site can pass a
 * store lookup straight in.
 *
 * `record.body` is parsed, not re-serialized — the stored bytes are never
 * touched, and nothing here can disturb the hash.
 */
export function isProposal(
  value: R3Record | R3Document | null | undefined,
): value is R3Record | R3Document {
  if (!value || typeof value !== 'object') return false
  const document = isR3Record(value) ? safeParse(value) : (value as R3Document)
  if (!document) return false
  const parameters = document.parameters
  return !!parameters && typeof parameters === 'object' && !Array.isArray(parameters)
}

function isR3Record(value: R3Record | R3Document): value is R3Record {
  return typeof (value as R3Record).body === 'string'
    && typeof (value as R3Record).s256 === 'string'
}

function safeParse(record: R3Record): R3Document | undefined {
  try {
    return parseR3Record(record)
  } catch {
    // Unparseable stored bytes are not a proposal. Whatever else is wrong with
    // them is verifyProposalParameters' problem, not the dispatcher's.
    return undefined
  }
}

export function isParameterDigest(value: unknown): value is R3ParameterDigest {
  return (
    !!value &&
    typeof value === 'object' &&
    !Array.isArray(value) &&
    typeof (value as R3ParameterDigest).s256 === 'string'
  )
}

// --- Building a proposal ---

export interface ProposalOptions {
  /** Vocabulary URI — the same one the class R3 document uses. */
  vocabulary: string
  /** The single `r3_per_call` operation being invoked, in that vocabulary. */
  operation: unknown
  /** REQUIRED. The concrete parameters of this call. A value MAY be a
   *  `{ s256, excerpt?, media_type? }` digest in place of the inline value. */
  parameters: Record<string, R3ParameterValue>
  account?: string
  display?: R3Display
}

/**
 * Build a per-call proposal document. Same structure and content addressing as
 * a class R3 document, plus the REQUIRED `parameters`.
 */
export function buildProposal(options: ProposalOptions): R3Document {
  const { vocabulary, operation, parameters, account, display } = options
  if (!parameters || typeof parameters !== 'object' || Array.isArray(parameters)) {
    throw new R3Error('invalid_proposal', 'A per-call proposal requires a `parameters` object')
  }
  const document: R3Document = {
    vocabulary,
    operations: [operation],
    ...(account !== undefined ? { account } : {}),
    ...(display !== undefined ? { display } : {}),
    parameters,
  }
  return document
}

export interface PublishProposalOptions extends ProposalOptions {
  store: R3Store
  baseUri?: string
  uri?: string
  /** The `aud` of the resource token you are about to mint, and the agent's
   *  PS. See `publishR3Document`. */
  authorized: Array<string | undefined>
  /** Default 3600 — a proposal must outlive the approval round trip, which is
   *  bounded by the auth token's 1 hour. */
  ttlSeconds?: number
}

/** Build, serialize once, and persist a proposal. Returns the `r3_uri` /
 *  `r3_s256` for the resource token. */
export async function publishProposal(options: PublishProposalOptions): Promise<PublishedR3> {
  const { store, baseUri, uri, authorized, ttlSeconds = 3600, ...rest } = options
  return publishR3Document({
    document: buildProposal(rest),
    store,
    ...(baseUri !== undefined ? { baseUri } : {}),
    ...(uri !== undefined ? { uri } : {}),
    authorized,
    ttlSeconds,
  })
}

// --- Enforced retry ---

export interface VerifyProposalOptions {
  store: R3Store
  /** `r3_s256` from the per-call auth token the agent presented. */
  r3_s256: string
  /** The parameters the agent actually supplied on this call. A value for a
   *  digest parameter may be a string, `Uint8Array`, or `ArrayBuffer`. */
  presented: Record<string, unknown>
  /** When given, the proposal's single operation must deep-equal this. */
  operation?: unknown
}

export interface VerifiedProposal {
  document: R3Document
  /** The approved parameters, as stored. */
  parameters: Record<string, R3ParameterValue>
}

/**
 * Recover the approved proposal by `r3_s256` and verify the agent's actual
 * parameters against it.
 *
 * - Every approved parameter MUST be present, and no parameter beyond them.
 * - A digest parameter MUST satisfy `BASE64URL(SHA-256(presented)) === s256`.
 * - Every other parameter MUST deep-equal the approved value.
 *
 * Throws `R3Error` on any difference.
 */
export async function verifyProposalParameters(
  options: VerifyProposalOptions,
): Promise<VerifiedProposal> {
  const { store, r3_s256, presented } = options

  if (typeof r3_s256 !== 'string' || !r3_s256) {
    throw new R3Error('proposal_not_referenced', 'The auth token carries no r3_s256')
  }
  const record = await store.get(r3_s256)
  if (!record) {
    throw new R3Error('proposal_not_found', `No approved proposal for r3_s256 ${r3_s256}`)
  }
  if (!timingSafeEqualString(record.s256, r3_s256)) {
    throw new R3Error('proposal_hash_mismatch', 'Stored proposal hash does not match r3_s256')
  }

  const document = parseR3Record(record)
  const approved = document.parameters
  if (!approved || typeof approved !== 'object') {
    throw new R3Error(
      'invalid_proposal',
      'The stored R3 document is not a per-call proposal — it has no `parameters`',
    )
  }

  if (options.operation !== undefined) {
    const ops = document.operations ?? []
    if (ops.length !== 1 || !deepEqual(ops[0], options.operation)) {
      throw new R3Error(
        'proposal_operation_mismatch',
        'The invoked operation is not the one that was approved',
      )
    }
  }

  if (!presented || typeof presented !== 'object' || Array.isArray(presented)) {
    throw new R3Error('proposal_parameter_mismatch', 'Presented parameters must be an object')
  }

  const approvedKeys = Object.keys(approved)
  const presentedKeys = Object.keys(presented)

  for (const key of presentedKeys) {
    if (!Object.prototype.hasOwnProperty.call(approved, key)) {
      throw new R3Error(
        'proposal_parameter_mismatch',
        `Parameter "${key}" was not in the approved proposal`,
      )
    }
  }

  for (const key of approvedKeys) {
    if (!Object.prototype.hasOwnProperty.call(presented, key)) {
      throw new R3Error(
        'proposal_parameter_mismatch',
        `Approved parameter "${key}" is missing from the call`,
      )
    }
    const approvedValue = approved[key]
    const presentedValue = presented[key]

    if (isParameterDigest(approvedValue)) {
      if (
        typeof presentedValue !== 'string' &&
        !(presentedValue instanceof Uint8Array) &&
        !(presentedValue instanceof ArrayBuffer)
      ) {
        throw new R3Error(
          'proposal_parameter_mismatch',
          `Parameter "${key}" was approved as a digest; the call must present its bytes`,
        )
      }
      const actual = await sha256Base64url(toBytes(presentedValue as Bytes))
      if (!timingSafeEqualString(actual, approvedValue.s256)) {
        throw new R3Error(
          'proposal_parameter_mismatch',
          `Parameter "${key}" does not hash to the approved s256`,
        )
      }
      continue
    }

    if (!deepEqual(approvedValue, presentedValue)) {
      throw new R3Error(
        'proposal_parameter_mismatch',
        `Parameter "${key}" differs from the approved proposal`,
      )
    }
  }

  return { document, parameters: approved }
}
