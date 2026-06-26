/**
 * `was publish`/`unpublish` (the world-readable `PublicCanRead` toggle) and
 * `was grant` (delegate a signed capability to another DID) run functions.
 */
import { resolveDidRef } from '../../meta.js'
import { saveToCollection } from '../../storage.js'
import { encodeCapability } from '../../zcap/encoding.js'
import { expiresFromTtl } from '../../zcap/ttl.js'
import { resolveWasTarget } from '../../was/client.js'
import { storageIdFor } from '../zcap.js'
import { writeCreateMeta } from '../collection-command.js'
import { handleForTarget, reportError, wasUrl } from './shared.js'

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
 * Makes a space, collection, or resource world-readable (the
 * `PublicCanRead` policy) and prints its public URL -- the "share via
 * public link" case.
 *
 * @param options {object}
 * @param options.address {string}   A space/collection/resource address.
 * @param [options.server] {string}   The server base URL.
 * @param [options.did] {string}   The signing DID or stored-DID handle.
 * @returns {Promise<number>}   The process exit code.
 */
export async function runPublish(options: {
  address: string
  server?: string
  did?: string
}): Promise<number> {
  try {
    const target = await resolveWasTarget({
      address: options.address,
      server: options.server,
      did: options.did
    })
    const { handle, url } = handleForTarget(target)
    await handle.setPublic()
    console.error(`Published (world-readable): ${url}`)
    console.log(url)
    return 0
  } catch (err) {
    return reportError({ action: 'publish the path', err })
  }
}

/**
 * Reverts a published space, collection, or resource to capability-only
 * access (clears its policy). Idempotent.
 *
 * @param options {object}
 * @param options.address {string}   A space/collection/resource address.
 * @param [options.server] {string}   The server base URL.
 * @param [options.did] {string}   The signing DID or stored-DID handle.
 * @returns {Promise<number>}   The process exit code.
 */
export async function runUnpublish(options: {
  address: string
  server?: string
  did?: string
}): Promise<number> {
  try {
    const target = await resolveWasTarget({
      address: options.address,
      server: options.server,
      did: options.did
    })
    const { handle, url } = handleForTarget(target)
    await handle.clearPolicy()
    console.error(`Unpublished (capability-only access): ${url}`)
    return 0
  } catch (err) {
    return reportError({ action: 'unpublish the path', err })
  }
}

/**
 * Delegates access to a space, collection, or resource: signs a capability
 * for the `--to` DID with the given actions and expiration, and prints
 * `{ delegatedCapability, encoded }` (the same shape as `zcap delegate`).
 * `--save` stores the capability in the local zcap store
 * (`~/.config/did-cli-wallet/zcaps/`).
 *
 * @param options {object}
 * @param options.address {string}   The space/collection/resource address.
 * @param options.to {string}   The delegatee DID (or stored-DID handle).
 * @param options.action {string[]}   Allowed actions (HTTP verbs; lowercase
 *   accepted).
 * @param [options.ttl] {string}   Time-to-live for expiration (default 1y).
 * @param [options.expires] {string}   Explicit ISO 8601 expiration
 *   (overrides --ttl).
 * @param [options.save] {boolean}   Save the capability to the zcap store.
 * @param [options.handle] {string}   Short tag for the saved zcap.
 * @param [options.description] {string}   Longer description for the saved
 *   zcap.
 * @param [options.server] {string}   The server base URL.
 * @param [options.did] {string}   The signing DID or stored-DID handle.
 * @returns {Promise<number>}   The process exit code.
 */
export async function runGrant(options: {
  address: string
  to: string
  action: string[]
  ttl?: string
  expires?: string
  save?: boolean
  handle?: string
  description?: string
  server?: string
  did?: string
}): Promise<number> {
  try {
    const actions = normalizeActions(options.action)
    const delegatee = await resolveDidRef({ ref: options.to })
    if (!delegatee) {
      throw new Error(`No locally stored DID found for "${options.to}".`)
    }
    const expires =
      options.expires ?? expiresFromTtl(options.ttl ?? '1y').toISOString()
    const target = await resolveWasTarget({
      address: options.address,
      server: options.server,
      did: options.did
    })
    const url = wasUrl({
      server: target.server,
      spaceId: target.spaceId,
      collectionId: target.collectionId,
      resourceId: target.resourceId
    })
    const delegatedCapability = await target.client.grant({
      to: delegatee,
      actions,
      expires,
      target: url
    })
    const encoded = encodeCapability(delegatedCapability)
    if (options.save) {
      const storageId = storageIdFor(delegatedCapability.id)
      const filePath = await saveToCollection(
        'zcaps',
        storageId,
        delegatedCapability
      )
      await writeCreateMeta({
        collection: 'zcaps',
        storageId,
        created: new Date().toISOString(),
        handle: options.handle,
        description: options.description
      })
      console.error(`Capability saved to ${filePath}`)
    }
    console.log(JSON.stringify({ delegatedCapability, encoded }, null, 2))
    return 0
  } catch (err) {
    return reportError({ action: 'grant access', err })
  }
}
