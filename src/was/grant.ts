/**
 * Capability-grant assembly for `was grant`: normalizes the requested actions,
 * resolves the delegatee DID, signs the delegated capability via the WAS
 * client, encodes it, and (optionally) persists it to the local zcap store.
 * The CLI `runGrant` layer only parses options, calls `grantAccess`, and
 * prints -- this module owns the cross-module assembly/encoding/persistence.
 */
import { type WasClient } from '@interop/was-client'
import { resolveDidRef } from '../meta.js'
import { sanitizeStorageId, saveToCollection } from '../storage.js'
import { encodeCapability } from '../zcap/encoding.js'
import { expiresFromTtl } from '../zcap/ttl.js'
import { writeCreateMeta } from '../commands/collection-command.js'

/** The zcap wallet collection grants are saved into with `--save`. */
const ZCAP_COLLECTION = 'zcaps'

/** The capability actions WAS servers match against (HTTP verbs). */
const WAS_ACTIONS = ['GET', 'PUT', 'POST', 'DELETE'] as const
type WasAction = (typeof WAS_ACTIONS)[number]

/**
 * Normalizes grant action verbs to their canonical uppercase form,
 * rejecting anything that is not a WAS-supported HTTP verb.
 *
 * @param actions {string[]}
 * @returns {WasAction[]}
 */
function normalizeActions(actions: string[]): WasAction[] {
  return actions.map(action => {
    const verb = action.toUpperCase() as WasAction
    if (!WAS_ACTIONS.includes(verb)) {
      throw new Error(
        `Unknown action "${action}" (supported: GET, PUT, POST, DELETE).`
      )
    }
    return verb
  })
}

/**
 * Delegates access to a WAS target: resolves the `to` DID, signs a capability
 * for the given actions and expiration via the client, encodes it, and saves
 * it to the local zcap store when `save` is set. Returns the signed
 * capability, its encoded form, and the saved file path (when saved) for the
 * caller to print.
 *
 * @param options {object}
 * @param options.client {WasClient}   The signing WAS client.
 * @param options.target {string}   The invocation target URL.
 * @param options.to {string}   The delegatee DID or stored-DID handle.
 * @param options.actions {string[]}   Requested actions (HTTP verbs).
 * @param [options.ttl] {string}   Time-to-live for expiration (default 1y).
 * @param [options.expires] {string}   Explicit ISO 8601 expiration (overrides
 *   ttl).
 * @param [options.save] {boolean}   Save the capability to the zcap store.
 * @param [options.handle] {string}   Short tag for the saved zcap.
 * @param [options.description] {string}   Longer description for the saved zcap.
 * @returns {Promise<{delegatedCapability: object, encoded: string, savedPath?: string}>}
 */
export async function grantAccess({
  client,
  target,
  to,
  actions,
  ttl,
  expires,
  save,
  handle,
  description
}: {
  client: WasClient
  target: string
  to: string
  actions: string[]
  ttl?: string
  expires?: string
  save?: boolean
  handle?: string
  description?: string
}): Promise<{
  delegatedCapability: Awaited<ReturnType<WasClient['grant']>>
  encoded: string
  savedPath?: string
}> {
  const normalizedActions = normalizeActions(actions)
  const delegatee = await resolveDidRef({ ref: to })
  if (!delegatee) {
    throw new Error(`No locally stored DID found for "${to}".`)
  }
  const expiresAt = expires ?? expiresFromTtl(ttl ?? '1y').toISOString()
  const delegatedCapability = await client.grant({
    to: delegatee,
    actions: normalizedActions,
    expires: expiresAt,
    target
  })
  const encoded = encodeCapability(delegatedCapability)
  if (!save) {
    return { delegatedCapability, encoded }
  }
  const storageId = sanitizeStorageId(delegatedCapability.id)
  const savedPath = await saveToCollection(
    ZCAP_COLLECTION,
    storageId,
    delegatedCapability
  )
  await writeCreateMeta({
    collection: ZCAP_COLLECTION,
    storageId,
    created: new Date().toISOString(),
    handle,
    description
  })
  return { delegatedCapability, encoded, savedPath }
}
