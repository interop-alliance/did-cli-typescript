/**
 * `was collection` run functions: create, list, show, update, delete, and the
 * read-only `backend` (the storage backend the collection is stored on) and
 * `quota` (the collection's storage usage, scoped to that backend) for a
 * collection within a space.
 */
import { resolveWasTarget } from '../../was/client.js'
import {
  parseSpaceAddress,
  printCollectionListing,
  printFieldValueTable,
  reportDeleted,
  reportError,
  reportNotFound,
  resolveCollectionTarget,
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
      return reportNotFound(
        wasUrl({ server: target.server, spaceId: target.spaceId })
      )
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
    const target = await resolveCollectionTarget(options)
    const description = await target.client
      .space(target.spaceId)
      .collection(target.collectionId)
      .describe()
    if (description === null) {
      return reportNotFound(
        wasUrl({
          server: target.server,
          spaceId: target.spaceId,
          collectionId: target.collectionId
        })
      )
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
    const target = await resolveCollectionTarget(options)
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
    const target = await resolveCollectionTarget(options)
    await target.client
      .space(target.spaceId)
      .collection(target.collectionId)
      .delete()
    reportDeleted(
      wasUrl({
        server: target.server,
        spaceId: target.spaceId,
        collectionId: target.collectionId
      })
    )
    return 0
  } catch (err) {
    return reportError({ action: 'delete the collection', err })
  }
}

/**
 * Shows the storage backend a collection is stored on (its "Collection Backend
 * Selected" descriptor). A missing/not-visible collection returns `null` (a
 * 404), reported as not-found; a server without backend support surfaces its
 * 501 as a typed error.
 *
 * @param options {object}
 * @param options.address {string}   The collection address.
 * @param [options.json] {boolean}   Output the raw backend JSON.
 * @param [options.server] {string}   The server base URL.
 * @param [options.did] {string}   The signing DID or stored-DID handle.
 * @returns {Promise<number>}   The process exit code.
 */
export async function runCollectionBackend(options: {
  address: string
  json?: boolean
  server?: string
  did?: string
}): Promise<number> {
  try {
    const target = await resolveCollectionTarget(options)
    const backend = await target.client
      .space(target.spaceId)
      .collection(target.collectionId)
      .backend()
    if (backend === null) {
      return reportNotFound(
        wasUrl({
          server: target.server,
          spaceId: target.spaceId,
          collectionId: target.collectionId
        })
      )
    }
    if (options.json) {
      console.log(JSON.stringify(backend, null, 2))
      return 0
    }
    printFieldValueTable([
      ['ID', backend.id],
      ['Name', backend.name ?? ''],
      ['Managed By', backend.managedBy ?? ''],
      ['Storage Mode', backend.storageMode?.join(', ') ?? ''],
      ['Persistence', backend.persistence ?? '']
    ])
    return 0
  } catch (err) {
    return reportError({ action: 'show the collection backend', err })
  }
}

/**
 * Shows a collection's storage usage report, scoped to its backend (one
 * `BackendUsage` entry: state, usage, limit, and any restricted actions). A
 * missing/not-visible collection returns `null` (a 404), reported as
 * not-found; a backend that cannot account per-collection surfaces its 501 as
 * a typed error.
 *
 * @param options {object}
 * @param options.address {string}   The collection address.
 * @param [options.json] {boolean}   Output the raw usage JSON.
 * @param [options.server] {string}   The server base URL.
 * @param [options.did] {string}   The signing DID or stored-DID handle.
 * @returns {Promise<number>}   The process exit code.
 */
export async function runCollectionQuota(options: {
  address: string
  json?: boolean
  server?: string
  did?: string
}): Promise<number> {
  try {
    const target = await resolveCollectionTarget(options)
    const usage = await target.client
      .space(target.spaceId)
      .collection(target.collectionId)
      .quota()
    if (usage === null) {
      return reportNotFound(
        wasUrl({
          server: target.server,
          spaceId: target.spaceId,
          collectionId: target.collectionId
        })
      )
    }
    if (options.json) {
      console.log(JSON.stringify(usage, null, 2))
      return 0
    }
    printFieldValueTable([
      ['Backend', usage.name ? `${usage.id} (${usage.name})` : usage.id],
      ['Managed By', usage.managedBy],
      ['State', usage.state],
      ['Usage (B)', String(usage.usageBytes)],
      [
        'Limit (B)',
        usage.limit.isUnlimited
          ? 'unlimited'
          : String(usage.limit.capacityBytes ?? '')
      ],
      ['Restricted', usage.restrictedActions.join(', ')],
      ['Measured At', usage.measuredAt]
    ])
    return 0
  } catch (err) {
    return reportError({ action: 'get the collection quota', err })
  }
}
