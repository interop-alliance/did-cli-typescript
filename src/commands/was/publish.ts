/**
 * `was publish`/`unpublish` (the world-readable `PublicCanRead` toggle) and
 * `was grant` (delegate a signed capability to another DID) run functions.
 */
import { resolveWasTarget } from '../../was/client.js'
import { grantAccess } from '../../was/grant.js'
import { requireSaveForMetaFlags } from '../collection-command.js'
import { handleForTarget, reportError, wasUrl } from './shared.js'

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
    if (!requireSaveForMetaFlags(options)) {
      return 2
    }
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
    const { delegatedCapability, encoded, savedPath } = await grantAccess({
      client: target.client,
      target: url,
      to: options.to,
      actions: options.action,
      ttl: options.ttl,
      expires: options.expires,
      save: options.save,
      handle: options.handle,
      description: options.description
    })
    if (savedPath) {
      console.error(`Capability saved to ${savedPath}`)
    }
    console.log(JSON.stringify({ delegatedCapability, encoded }, null, 2))
    return 0
  } catch (err) {
    return reportError({ action: 'grant access', err })
  }
}
