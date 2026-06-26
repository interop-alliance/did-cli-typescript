/**
 * The depth-dispatching `was` shorthands `ls` and `rm`: they inspect the
 * path (or a `--capability`'s invocation target) and delegate to the right
 * space/collection/resource run function, mirroring the client's
 * uniform-verbs-at-every-level design.
 */
import { parseWasAddress } from '../../was/address.js'
import { resolveCapabilityTarget } from '../../was/capability.js'
import {
  assertOneAddressing,
  printCollectionListing,
  printResourceListing,
  reportDeleted,
  reportError,
  reportNotFound
} from './shared.js'
import { runCollectionDelete, runCollectionList } from './collection.js'
import { runResourceDelete, runResourceList } from './resource.js'
import { runSpaceDelete } from './space.js'

/**
 * The `was ls` shorthand: lists the collections of a space or the resources
 * of a collection, depending on the depth of the path (or of a
 * `--capability`'s invocation target).
 *
 * @param options {object}
 * @param [options.address] {string}   A space or collection address.
 * @param [options.capability] {string}   A capability reference instead of
 *   a path.
 * @param [options.json] {boolean}   Output the raw listing JSON.
 * @param [options.plain] {boolean}   Output one id per line.
 * @param [options.server] {string}   The server base URL.
 * @param [options.did] {string}   The signing DID or stored-DID handle.
 * @returns {Promise<number>}   The process exit code.
 */
export async function runLs(options: {
  address?: string
  capability?: string
  json?: boolean
  plain?: boolean
  server?: string
  did?: string
}): Promise<number> {
  if (options.capability) {
    try {
      assertOneAddressing(options)
      const resolved = await resolveCapabilityTarget({
        ref: options.capability,
        did: options.did
      })
      if (resolved.depth === 'resource') {
        throw new Error(
          'the capability targets a resource; ' +
            'ls takes a space or collection capability.'
        )
      }
      if (resolved.depth === 'space') {
        const listing = await resolved.handle.collections()
        if (listing === null) {
          return reportNotFound(resolved.url)
        }
        printCollectionListing({
          listing,
          json: options.json,
          plain: options.plain
        })
      } else {
        const listing = await resolved.handle.list()
        if (listing === null) {
          return reportNotFound(resolved.url)
        }
        printResourceListing({
          listing,
          json: options.json,
          plain: options.plain
        })
      }
      return 0
    } catch (err) {
      return reportError({ action: 'list the path', err })
    }
  }
  let parsed
  try {
    assertOneAddressing(options)
    parsed = parseWasAddress(options.address as string)
  } catch (err) {
    return reportError({ action: 'list the path', err })
  }
  if (parsed.resourceId !== undefined) {
    console.error(
      `Could not list the path: "${options.address}" is a resource; ` +
        'ls takes a space or collection address.'
    )
    return 2
  }
  if (parsed.collectionId !== undefined) {
    return runResourceList({ ...options, address: options.address as string })
  }
  return runCollectionList({ ...options, address: options.address as string })
}

/**
 * The `was rm` shorthand: deletes whatever the path (or a `--capability`'s
 * invocation target) points at -- a space, a collection, or a resource (the
 * client's uniform `delete()` design).
 *
 * @param options {object}
 * @param [options.address] {string}   A space, collection, or resource
 *   address.
 * @param [options.capability] {string}   A capability reference instead of
 *   a path.
 * @param [options.server] {string}   The server base URL.
 * @param [options.did] {string}   The signing DID or stored-DID handle.
 * @returns {Promise<number>}   The process exit code.
 */
export async function runRm(options: {
  address?: string
  capability?: string
  server?: string
  did?: string
}): Promise<number> {
  if (options.capability) {
    try {
      assertOneAddressing(options)
      const resolved = await resolveCapabilityTarget({
        ref: options.capability,
        did: options.did
      })
      await resolved.handle.delete()
      reportDeleted(resolved.url)
      return 0
    } catch (err) {
      return reportError({ action: 'delete the path', err })
    }
  }
  let parsed
  try {
    assertOneAddressing(options)
    parsed = parseWasAddress(options.address as string)
  } catch (err) {
    return reportError({ action: 'delete the path', err })
  }
  const pathOptions = { ...options, address: options.address as string }
  if (parsed.resourceId !== undefined) {
    return runResourceDelete(pathOptions)
  }
  if (parsed.collectionId !== undefined) {
    return runCollectionDelete(pathOptions)
  }
  return runSpaceDelete(pathOptions)
}
