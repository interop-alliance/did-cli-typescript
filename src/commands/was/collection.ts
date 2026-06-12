/**
 * `was collection` run functions: create, list, show, update, and delete a
 * collection within a space.
 */
import { resolveWasTarget } from '../../was/client.js'
import {
  parseSpaceAddress,
  printCollectionListing,
  reportError,
  requireCollectionTarget,
  wasUrl
} from './shared.js'

/**
 * Creates a collection within a space and prints `{ id, url, name? }`.
 *
 * @param options {object}
 * @param options.address {string}   The space address.
 * @param [options.name] {string}   The collection's display name.
 * @param [options.id] {string}   A caller-chosen collection id.
 * @param [options.server] {string}   The server base URL.
 * @param [options.did] {string}   The signing DID or stored-DID handle.
 * @returns {Promise<number>}   The process exit code.
 */
export async function runCollectionCreate(options: {
  address: string
  name?: string
  id?: string
  server?: string
  did?: string
}): Promise<number> {
  try {
    parseSpaceAddress(options.address)
    const target = await resolveWasTarget({
      address: options.address,
      server: options.server,
      did: options.did
    })
    const collection = await target.client
      .space(target.spaceId)
      .createCollection({
        ...(options.name !== undefined && { name: options.name }),
        ...(options.id !== undefined && { id: options.id })
      })
    const url = wasUrl({
      server: target.server,
      spaceId: target.spaceId,
      collectionId: collection.id
    })
    console.log(
      JSON.stringify(
        {
          id: collection.id,
          url,
          ...(options.name !== undefined && { name: options.name })
        },
        null,
        2
      )
    )
    return 0
  } catch (err) {
    return reportError({ action: 'create the collection', err })
  }
}

/**
 * Lists the collections in a space.
 *
 * @param options {object}
 * @param options.address {string}   The space address.
 * @param [options.json] {boolean}   Output the raw listing JSON.
 * @param [options.plain] {boolean}   Output one collection id per line.
 * @param [options.server] {string}   The server base URL.
 * @param [options.did] {string}   The signing DID or stored-DID handle.
 * @returns {Promise<number>}   The process exit code.
 */
export async function runCollectionList(options: {
  address: string
  json?: boolean
  plain?: boolean
  server?: string
  did?: string
}): Promise<number> {
  try {
    parseSpaceAddress(options.address)
    const target = await resolveWasTarget({
      address: options.address,
      server: options.server,
      did: options.did
    })
    const listing = await target.client.space(target.spaceId).collections()
    if (listing === null) {
      console.error(
        'Not found (or not visible to you): ' +
          wasUrl({ server: target.server, spaceId: target.spaceId })
      )
      return 1
    }
    printCollectionListing({
      listing,
      json: options.json,
      plain: options.plain
    })
    return 0
  } catch (err) {
    return reportError({ action: 'list collections', err })
  }
}

/**
 * Shows a collection's description from the server.
 *
 * @param options {object}
 * @param options.address {string}   The collection address.
 * @param [options.server] {string}   The server base URL.
 * @param [options.did] {string}   The signing DID or stored-DID handle.
 * @returns {Promise<number>}   The process exit code.
 */
export async function runCollectionShow(options: {
  address: string
  server?: string
  did?: string
}): Promise<number> {
  try {
    const target = requireCollectionTarget({
      target: await resolveWasTarget({
        address: options.address,
        server: options.server,
        did: options.did
      }),
      address: options.address
    })
    const description = await target.client
      .space(target.spaceId)
      .collection(target.collectionId)
      .describe()
    if (description === null) {
      console.error(
        'Not found (or not visible to you): ' +
          wasUrl({
            server: target.server,
            spaceId: target.spaceId,
            collectionId: target.collectionId
          })
      )
      return 1
    }
    console.log(JSON.stringify(description, null, 2))
    return 0
  } catch (err) {
    return reportError({ action: 'show the collection', err })
  }
}

/**
 * Updates a collection's description fields on the server (upsert via
 * `configure()`).
 *
 * @param options {object}
 * @param options.address {string}   The collection address.
 * @param options.name {string}   The collection's new display name.
 * @param [options.server] {string}   The server base URL.
 * @param [options.did] {string}   The signing DID or stored-DID handle.
 * @returns {Promise<number>}   The process exit code.
 */
export async function runCollectionUpdate(options: {
  address: string
  name: string
  server?: string
  did?: string
}): Promise<number> {
  try {
    const target = requireCollectionTarget({
      target: await resolveWasTarget({
        address: options.address,
        server: options.server,
        did: options.did
      }),
      address: options.address
    })
    const description = await target.client
      .space(target.spaceId)
      .collection(target.collectionId)
      .configure({ name: options.name })
    console.log(JSON.stringify(description, null, 2))
    return 0
  } catch (err) {
    return reportError({ action: 'update the collection', err })
  }
}

/**
 * Deletes a whole collection and its contents on the server. Idempotent.
 *
 * @param options {object}
 * @param options.address {string}   The collection address.
 * @param [options.server] {string}   The server base URL.
 * @param [options.did] {string}   The signing DID or stored-DID handle.
 * @returns {Promise<number>}   The process exit code.
 */
export async function runCollectionDelete(options: {
  address: string
  server?: string
  did?: string
}): Promise<number> {
  try {
    const target = requireCollectionTarget({
      target: await resolveWasTarget({
        address: options.address,
        server: options.server,
        did: options.did
      }),
      address: options.address
    })
    await target.client
      .space(target.spaceId)
      .collection(target.collectionId)
      .delete()
    console.error(
      'Deleted ' +
        wasUrl({
          server: target.server,
          spaceId: target.spaceId,
          collectionId: target.collectionId
        }) +
        ' on the server.'
    )
    return 0
  } catch (err) {
    return reportError({ action: 'delete the collection', err })
  }
}
