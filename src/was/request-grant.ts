/**
 * The requesting half of capability delegation (`was request-grant`), the
 * inverse of `was grant`. Instead of signing a capability for someone else,
 * this asks a user's wallet to sign one for us: it builds a zcap-only
 * Verifiable Presentation Request (VPR), opens an ephemeral exchange on the
 * WAS server to carry it, and waits for the wallet to post back a response
 * presentation holding the delegated capabilities.
 *
 * Nothing here is signed. The exchange routes are unauthenticated by design --
 * the exchange URL is itself the secret, and it travels point-to-point to the
 * user (today as a printed interaction URL). Both the exchange transport and
 * the zcap-only VPR composition come from `@interop/wallet-core/request`; what
 * is owned here is the CLI's own request shape (the public-collection
 * descriptor and the action normalization) and the response parsing.
 */
import {
  composeCapabilityRequest,
  createEphemeralExchange,
  pollEphemeralExchange,
  EPHEMERAL_EXCHANGE_TTL_MS
} from '@interop/wallet-core/request'
import type {
  ICapabilityQueryDetail,
  IVPRDetails
} from '@interop/data-integrity-core/vpr'
import type { IZcap } from '@interop/data-integrity-core/zcap'

/**
 * The wallet-defined descriptor for a world-readable collection under the
 * user's own Space. Naming a descriptor rather than a URL is what lets the
 * request be written before the Space exists: the wallet resolves it to one of
 * its own collections at consent time.
 */
export const PUBLIC_COLLECTION_TYPE = 'https://w3id.org/byoe#public-collection'

/** The collection the request names when `--collection` is not given. */
export const DEFAULT_COLLECTION = 'web'

/** The actions the request asks for when `--action` is not given. */
export const DEFAULT_ACTIONS = ['GET', 'HEAD', 'PUT', 'POST']

/**
 * The actions a capability request may name. A superset of the verbs
 * `was grant` signs (it adds `HEAD`), because the wallet -- not this CLI -- is
 * the authority on what it is willing to delegate.
 */
const REQUESTABLE_ACTIONS = ['GET', 'HEAD', 'PUT', 'POST', 'DELETE'] as const

/**
 * How long to wait for the user to approve before giving up: the server's
 * exchange TTL, since past it the exchange is gone and no approval can arrive.
 */
export const DEFAULT_TIMEOUT_MS = EPHEMERAL_EXCHANGE_TTL_MS

/**
 * The largest wait the poll's deadline accepts (a `setTimeout` delay, which is
 * truncated to a signed 32-bit value and would otherwise fire at once).
 * Anything past this is rejected as bad input rather than left to fail deep
 * inside the poll.
 */
export const MAX_TIMEOUT_MS = 2_147_483_647

/**
 * Raised when the exchange itself ran but produced no grant: the user declined,
 * let it expire, or approved a request the wallet could not satisfy. These are
 * operation failures rather than bad input, and the command reports them as
 * such. Internal to this package; nothing dispatches on the name across a
 * package boundary.
 */
export class GrantRequestError extends Error {}

/**
 * The subset of `fetch` the exchange helpers use.
 */
type FetchLike = (input: string, init?: RequestInit) => Promise<Response>

let exchangeFetch: FetchLike | undefined

/**
 * Replaces the `fetch` the exchange helpers transport over (a test-only seam,
 * mirroring `setWasClientFactory`). Call with no argument to restore the
 * global `fetch`.
 *
 * @param [fetchImpl] {FetchLike}
 * @returns {void}
 */
export function setExchangeFetch(fetchImpl?: FetchLike): void {
  exchangeFetch = fetchImpl
}

/**
 * Normalizes requested action verbs to their canonical uppercase form,
 * rejecting anything that is not an HTTP verb a WAS server matches against.
 *
 * @param actions {string[]}
 * @returns {string[]}
 */
function normalizeRequestedActions(actions: string[]): string[] {
  return actions.map(action => {
    const verb = action.toUpperCase()
    if (!(REQUESTABLE_ACTIONS as readonly string[]).includes(verb)) {
      throw new Error(
        `Unknown action "${action}" (supported: ` +
          `${REQUESTABLE_ACTIONS.join(', ')}).`
      )
    }
    return verb
  })
}

/**
 * Builds the zcap-only VPR this command sends: one capability query naming the
 * agent as the capability `controller` and a public-collection descriptor as
 * the target, composed by wallet-core. There is deliberately no
 * `DIDAuthentication` query and no `domain` -- the agent is asking for
 * authority, not proving who it is to a verifier, and a CLI has no attested
 * origin for a wallet to check a domain against (one sent anyway is enforced,
 * and fails).
 *
 * @param options {object}
 * @param options.controller {string}   The agent's did:key (the grantee).
 * @param [options.collection] {string}   The collection name to request.
 * @param [options.actions] {string[]}   The actions to request.
 * @param [options.reason] {string}   Human-readable text shown at consent.
 * @returns {IVPRDetails}
 */
export function buildCapabilityRequest({
  controller,
  collection = DEFAULT_COLLECTION,
  actions = DEFAULT_ACTIONS,
  reason
}: {
  controller: string
  collection?: string
  actions?: string[]
  reason?: string
}): IVPRDetails {
  const capabilityQuery: ICapabilityQueryDetail = {
    ...(reason !== undefined && { reason }),
    allowedAction: normalizeRequestedActions(actions),
    controller,
    invocationTarget: {
      type: PUBLIC_COLLECTION_TYPE,
      name: collection
    }
  }
  return composeCapabilityRequest({ capabilityQueries: [capabilityQuery] })
}

/**
 * Opens an ephemeral exchange on the WAS server carrying the request, and
 * returns both the URL to poll and the interaction URL to hand the user.
 *
 * @param options {object}
 * @param options.server {string}   The WAS server base URL.
 * @param options.request {IVPRDetails}   The VPR to store on the exchange.
 * @returns {Promise<{exchangeUrl: string, interactionUrl: string}>}
 */
export async function openGrantExchange({
  server,
  request
}: {
  server: string
  request: IVPRDetails
}): Promise<{ exchangeUrl: string; interactionUrl: string }> {
  return createEphemeralExchange({
    serverUrl: server,
    request,
    ...(exchangeFetch && { fetch: exchangeFetch })
  })
}

/**
 * Pulls the delegated capabilities out of a completed exchange response. The
 * wallet posts `{ verifiablePresentation }`, and the zcaps ride inside that
 * presentation as its `zcap` member.
 *
 * @param response {unknown}   The exchange's `response` member.
 * @returns {IZcap[]}
 */
export function extractCapabilities(response: unknown): IZcap[] {
  const presentation = (
    response as { verifiablePresentation?: { zcap?: IZcap | IZcap[] } }
  )?.verifiablePresentation
  if (!presentation) {
    throw new GrantRequestError(
      'The wallet response contained no verifiablePresentation.'
    )
  }
  const { zcap } = presentation
  const zcaps = zcap === undefined ? [] : Array.isArray(zcap) ? zcap : [zcap]
  for (const capability of zcaps) {
    if (typeof capability.id !== 'string' || capability.id === '') {
      throw new GrantRequestError(
        'The wallet returned a capability with no id, which cannot be filed ' +
          'in the zcap store or named by a later --capability.'
      )
    }
  }
  if (zcaps.length === 0) {
    throw new GrantRequestError(
      'The wallet returned a presentation with no capabilities: the request ' +
        'was declined, or the collection could not be granted (a public ' +
        'collection is only ever created public, never converted from an ' +
        'existing private one).'
    )
  }
  return zcaps
}

/**
 * Waits for the user's wallet to complete the exchange, and returns the
 * capabilities it delegated. Gives up at `timeoutMs`, and distinguishes an
 * exchange the server has already dropped from one still waiting on the user.
 *
 * @param options {object}
 * @param options.exchangeUrl {string}
 * @param [options.timeoutMs] {number}
 * @param [options.intervalMs] {number}   How often to poll.
 * @returns {Promise<IZcap[]>}
 */
export async function awaitGrantedCapabilities({
  exchangeUrl,
  timeoutMs = DEFAULT_TIMEOUT_MS,
  intervalMs
}: {
  exchangeUrl: string
  timeoutMs?: number
  intervalMs?: number
}): Promise<IZcap[]> {
  let response: unknown
  try {
    response = await pollEphemeralExchange({
      exchangeUrl,
      timeoutMs,
      ...(intervalMs !== undefined && { intervalMs }),
      ...(exchangeFetch && { fetch: exchangeFetch })
    })
  } catch (err) {
    // The transport is injected and may resolve to a different copy of
    // wallet-core, so the error name is the stable contract here.
    if ((err as Error).name === 'EphemeralExchangeGoneError') {
      throw new GrantRequestError(
        'The request expired before it was approved (the server keeps an ' +
          'exchange for ten minutes). Run the command again for a fresh link.',
        { cause: err }
      )
    }
    if ((err as Error).name === 'EphemeralExchangeTimeoutError') {
      throw new GrantRequestError(
        `Gave up waiting for approval after ${Math.round(timeoutMs / 1000)}s. ` +
          'The request may still be approvable; raise --timeout, or run the ' +
          'command again for a fresh link.',
        { cause: err }
      )
    }
    throw err
  }
  return extractCapabilities(response)
}
