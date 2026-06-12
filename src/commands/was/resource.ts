/**
 * `was resource` run functions: add (server-generated id), put (upsert at a
 * known id), get (JSON or binary), list, and delete. Each addressing-capable
 * verb accepts either a path or a `--capability` targeting the resource or
 * its collection.
 */
import { type Collection, type Resource } from '@interop/was-client'
import { resolveWasTarget } from '../../was/client.js'
import { resolveCapabilityTarget } from '../../was/capability.js'
import { readPayload, writeResourceOutput } from '../../was/io.js'
import {
  assertOneAddressing,
  printResourceListing,
  reportError,
  requireCollectionTarget,
  requireResourceTarget,
  wasUrl
} from './shared.js'

/**
 * Adds a resource to a collection (server-generated id) and prints the
 * `{ id, url, contentType }` add result. The collection comes from a path
 * or a `--capability` targeting one.
 *
 * @param options {object}
 * @param [options.address] {string}   The collection address.
 * @param [options.capability] {string}   A capability reference instead of
 *   a path.
 * @param [options.file] {string}   The payload file; stdin when omitted.
 * @param [options.contentType] {string}   Explicit payload content type.
 * @param [options.server] {string}   The server base URL.
 * @param [options.did] {string}   The signing DID or stored-DID handle.
 * @returns {Promise<number>}   The process exit code.
 */
export async function runResourceAdd(options: {
  address?: string
  capability?: string
  file?: string
  contentType?: string
  server?: string
  did?: string
}): Promise<number> {
  try {
    assertOneAddressing(options)
    let collection: Collection
    if (options.capability) {
      const resolved = await resolveCapabilityTarget({
        ref: options.capability,
        did: options.did
      })
      if (resolved.depth !== 'collection') {
        throw new Error(
          `The capability targets a ${resolved.depth}; ` +
            'add needs a collection capability.'
        )
      }
      collection = resolved.handle
    } else {
      const target = requireCollectionTarget({
        target: await resolveWasTarget({
          address: options.address as string,
          server: options.server,
          did: options.did
        }),
        address: options.address as string
      })
      collection = target.client
        .space(target.spaceId)
        .collection(target.collectionId)
    }
    const payload = await readPayload({
      file: options.file,
      contentType: options.contentType
    })
    const result = await collection.add(payload.data, {
      ...(payload.contentType !== undefined && {
        contentType: payload.contentType
      })
    })
    console.log(JSON.stringify(result, null, 2))
    return 0
  } catch (err) {
    return reportError({ action: 'add the resource', err })
  }
}

/**
 * Creates or replaces a resource at a known id (upsert) and prints
 * `{ id, url }`. The resource comes from a path or a `--capability`
 * targeting one.
 *
 * @param options {object}
 * @param [options.address] {string}   The resource address.
 * @param [options.capability] {string}   A capability reference instead of
 *   a path.
 * @param [options.file] {string}   The payload file; stdin when omitted.
 * @param [options.contentType] {string}   Explicit payload content type.
 * @param [options.server] {string}   The server base URL.
 * @param [options.did] {string}   The signing DID or stored-DID handle.
 * @returns {Promise<number>}   The process exit code.
 */
export async function runResourcePut(options: {
  address?: string
  capability?: string
  file?: string
  contentType?: string
  server?: string
  did?: string
}): Promise<number> {
  try {
    assertOneAddressing(options)
    let resource: Resource
    let url: string
    if (options.capability) {
      const resolved = await resolveCapabilityTarget({
        ref: options.capability,
        did: options.did
      })
      if (resolved.depth !== 'resource') {
        throw new Error(
          `The capability targets a ${resolved.depth}; ` +
            'put needs a resource capability.'
        )
      }
      resource = resolved.handle
      url = resolved.url
    } else {
      const target = requireResourceTarget({
        target: await resolveWasTarget({
          address: options.address as string,
          server: options.server,
          did: options.did
        }),
        address: options.address as string
      })
      resource = target.client
        .space(target.spaceId)
        .collection(target.collectionId)
        .resource(target.resourceId)
      url = wasUrl({
        server: target.server,
        spaceId: target.spaceId,
        collectionId: target.collectionId,
        resourceId: target.resourceId
      })
    }
    const payload = await readPayload({
      file: options.file,
      contentType: options.contentType
    })
    await resource.put(payload.data, {
      ...(payload.contentType !== undefined && {
        contentType: payload.contentType
      })
    })
    console.log(JSON.stringify({ id: resource.id, url }, null, 2))
    return 0
  } catch (err) {
    return reportError({ action: 'put the resource', err })
  }
}

/**
 * Reads a resource: JSON pretty-printed to stdout, binary written raw
 * (`--output` for files). The resource comes from a path or a
 * `--capability` targeting one.
 *
 * @param options {object}
 * @param [options.address] {string}   The resource address.
 * @param [options.capability] {string}   A capability reference instead of
 *   a path.
 * @param [options.output] {string}   The output file path; stdout when
 *   omitted.
 * @param [options.server] {string}   The server base URL.
 * @param [options.did] {string}   The signing DID or stored-DID handle.
 * @returns {Promise<number>}   The process exit code.
 */
export async function runResourceGet(options: {
  address?: string
  capability?: string
  output?: string
  server?: string
  did?: string
}): Promise<number> {
  try {
    assertOneAddressing(options)
    let resource: Resource
    let url: string
    if (options.capability) {
      const resolved = await resolveCapabilityTarget({
        ref: options.capability,
        did: options.did
      })
      if (resolved.depth !== 'resource') {
        throw new Error(
          `The capability targets a ${resolved.depth}; ` +
            'get needs a resource capability.'
        )
      }
      resource = resolved.handle
      url = resolved.url
    } else {
      const target = requireResourceTarget({
        target: await resolveWasTarget({
          address: options.address as string,
          server: options.server,
          did: options.did
        }),
        address: options.address as string
      })
      resource = target.client
        .space(target.spaceId)
        .collection(target.collectionId)
        .resource(target.resourceId)
      url = wasUrl({
        server: target.server,
        spaceId: target.spaceId,
        collectionId: target.collectionId,
        resourceId: target.resourceId
      })
    }
    const data = await resource.get()
    if (data === null) {
      console.error(`Not found (or not visible to you): ${url}`)
      return 1
    }
    await writeResourceOutput({ data, output: options.output })
    return 0
  } catch (err) {
    return reportError({ action: 'get the resource', err })
  }
}

/**
 * Lists the resources in a collection.
 *
 * @param options {object}
 * @param options.address {string}   The collection address.
 * @param [options.json] {boolean}   Output the raw listing JSON.
 * @param [options.plain] {boolean}   Output one resource id per line.
 * @param [options.server] {string}   The server base URL.
 * @param [options.did] {string}   The signing DID or stored-DID handle.
 * @returns {Promise<number>}   The process exit code.
 */
export async function runResourceList(options: {
  address: string
  json?: boolean
  plain?: boolean
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
    const listing = await target.client
      .space(target.spaceId)
      .collection(target.collectionId)
      .list()
    if (listing === null) {
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
    printResourceListing({ listing, json: options.json, plain: options.plain })
    return 0
  } catch (err) {
    return reportError({ action: 'list resources', err })
  }
}

/**
 * Deletes a resource on the server. Idempotent.
 *
 * @param options {object}
 * @param options.address {string}   The resource address.
 * @param [options.server] {string}   The server base URL.
 * @param [options.did] {string}   The signing DID or stored-DID handle.
 * @returns {Promise<number>}   The process exit code.
 */
export async function runResourceDelete(options: {
  address: string
  server?: string
  did?: string
}): Promise<number> {
  try {
    const target = requireResourceTarget({
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
      .resource(target.resourceId)
      .delete()
    console.error(
      'Deleted ' +
        wasUrl({
          server: target.server,
          spaceId: target.spaceId,
          collectionId: target.collectionId,
          resourceId: target.resourceId
        }) +
        ' on the server.'
    )
    return 0
  } catch (err) {
    return reportError({ action: 'delete the resource', err })
  }
}
