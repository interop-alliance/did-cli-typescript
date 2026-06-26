/**
 * `was resource` run functions: add (server-generated id), put (upsert at a
 * known id), get (JSON or binary), list, delete, and the resource-metadata
 * verbs `meta get` / `meta put`. Each addressing-capable verb accepts either
 * a path or a `--capability` targeting the resource or its collection.
 */
import { readFile } from 'node:fs/promises'
import {
  type Collection,
  type Resource,
  type ResourceMetadataCustom
} from '@interop/was-client'
import { resolveCapabilityTarget } from '../../was/capability.js'
import { readPayload, writeResourceOutput } from '../../was/io.js'
import {
  assertOneAddressing,
  printResourceListing,
  reportDeleted,
  reportError,
  reportNotFound,
  resolveCollectionTarget,
  resolveResourceTarget,
  wasUrl
} from './shared.js'

/**
 * Resolves a single resource handle and its URL from either a path address
 * or a `--capability` targeting a resource -- the shared addressing logic of
 * the resource verbs that operate on one resource (`put`, `get`, `meta`).
 *
 * @param options {object}
 * @param [options.address] {string}   The resource address.
 * @param [options.capability] {string}   A capability reference instead of
 *   a path.
 * @param options.verb {string}   The verb name, for the capability-depth
 *   error message.
 * @param [options.server] {string}   The server base URL.
 * @param [options.did] {string}   The signing DID or stored-DID handle.
 * @returns {Promise<{resource: Resource, url: string}>}
 */
async function resolveResourceHandle({
  address,
  capability,
  verb,
  server,
  did
}: {
  address?: string
  capability?: string
  verb: string
  server?: string
  did?: string
}): Promise<{ resource: Resource; url: string }> {
  assertOneAddressing({ address, capability })
  if (capability) {
    const resolved = await resolveCapabilityTarget({ ref: capability, did })
    if (resolved.depth !== 'resource') {
      throw new Error(
        `The capability targets a ${resolved.depth}; ` +
          `${verb} needs a resource capability.`
      )
    }
    return { resource: resolved.handle, url: resolved.url }
  }
  const target = await resolveResourceTarget({
    address: address as string,
    server,
    did
  })
  const resource = target.client
    .space(target.spaceId)
    .collection(target.collectionId)
    .resource(target.resourceId)
  const url = wasUrl({
    server: target.server,
    spaceId: target.spaceId,
    collectionId: target.collectionId,
    resourceId: target.resourceId
  })
  return { resource, url }
}

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
      const target = await resolveCollectionTarget({
        address: options.address as string,
        server: options.server,
        did: options.did
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
    const { resource, url } = await resolveResourceHandle({
      ...options,
      verb: 'put'
    })
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
    const { resource, url } = await resolveResourceHandle({
      ...options,
      verb: 'get'
    })
    const data = await resource.get()
    if (data === null) {
      return reportNotFound(url)
    }
    await writeResourceOutput({ data, output: options.output })
    return 0
  } catch (err) {
    return reportError({ action: 'get the resource', err })
  }
}

/**
 * Reads a resource's metadata object (server-managed `contentType` / `size` /
 * timestamps plus the user-writable `custom`) and pretty-prints it. The
 * resource comes from a path or a `--capability` targeting one.
 *
 * @param options {object}
 * @param [options.address] {string}   The resource address.
 * @param [options.capability] {string}   A capability reference instead of
 *   a path.
 * @param [options.server] {string}   The server base URL.
 * @param [options.did] {string}   The signing DID or stored-DID handle.
 * @returns {Promise<number>}   The process exit code.
 */
export async function runResourceMetaGet(options: {
  address?: string
  capability?: string
  server?: string
  did?: string
}): Promise<number> {
  try {
    const { resource, url } = await resolveResourceHandle({
      ...options,
      verb: 'meta get'
    })
    const meta = await resource.meta()
    if (meta === null) {
      return reportNotFound(url)
    }
    console.log(JSON.stringify(meta, null, 2))
    return 0
  } catch (err) {
    return reportError({ action: 'get the resource metadata', err })
  }
}

/**
 * Parses the repeatable `--tag key=value` flags into a tags record. Returns
 * `undefined` when no `--tag` was given (so the caller can leave tags
 * untouched).
 *
 * @param rawTags {string[]}   The raw `key=value` strings, as collected.
 * @returns {Record<string, string> | undefined}
 */
function parseTags(rawTags: string[]): Record<string, string> | undefined {
  if (rawTags.length === 0) {
    return undefined
  }
  const tags: Record<string, string> = {}
  for (const entry of rawTags) {
    const separator = entry.indexOf('=')
    const key = separator === -1 ? entry : entry.slice(0, separator)
    if (separator === -1 || key === '') {
      throw new Error(`Invalid --tag "${entry}"; expected key=value.`)
    }
    tags[key] = entry.slice(separator + 1)
  }
  return tags
}

/**
 * Parses the `--json` escape hatch -- inline JSON, or a path to a JSON file
 * when the value does not itself parse -- into a `custom` metadata object.
 *
 * @param input {string}   Inline JSON or a JSON file path.
 * @returns {Promise<ResourceMetadataCustom>}
 */
async function parseCustomJson(input: string): Promise<ResourceMetadataCustom> {
  let parsed: unknown
  try {
    parsed = JSON.parse(input)
  } catch {
    let contents: string
    try {
      contents = await readFile(input, 'utf8')
    } catch {
      throw new Error(
        `--json is neither valid JSON nor a readable file: ${input}`
      )
    }
    parsed = JSON.parse(contents)
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new Error('--json must be a JSON object (the custom metadata).')
  }
  return parsed as ResourceMetadataCustom
}

/**
 * Updates a resource's user-writable metadata and prints the resulting
 * metadata. `--name`/`--tag` are read-modify-write sugar that preserve the
 * other field; giving both, or `--json`, is a full `custom` replacement so
 * any omitted property is cleared. The resource comes from a path or a
 * `--capability` targeting one.
 *
 * @param options {object}
 * @param [options.address] {string}   The resource address.
 * @param [options.capability] {string}   A capability reference instead of
 *   a path.
 * @param [options.name] {string}   The resource's display name.
 * @param options.tag {string[]}   Repeatable `key=value` tag pairs.
 * @param [options.json] {string}   Full `custom` JSON (inline or a file
 *   path); mutually exclusive with `--name`/`--tag`.
 * @param [options.server] {string}   The server base URL.
 * @param [options.did] {string}   The signing DID or stored-DID handle.
 * @returns {Promise<number>}   The process exit code.
 */
export async function runResourceMetaPut(options: {
  address?: string
  capability?: string
  name?: string
  tag: string[]
  json?: string
  server?: string
  did?: string
}): Promise<number> {
  try {
    const tags = parseTags(options.tag)
    const hasName = options.name !== undefined
    const hasTags = tags !== undefined
    const hasJson = options.json !== undefined
    if (hasJson && (hasName || hasTags)) {
      throw new Error('Provide either --json or --name/--tag, not both.')
    }
    if (!hasJson && !hasName && !hasTags) {
      throw new Error('Provide --name, --tag <key=value>, or --json.')
    }
    const { resource, url } = await resolveResourceHandle({
      ...options,
      verb: 'meta put'
    })
    if (hasJson) {
      await resource.setMeta({ custom: await parseCustomJson(options.json!) })
    } else if (hasName && hasTags) {
      await resource.setMeta({ custom: { name: options.name, tags } })
    } else if (hasName) {
      await resource.setName(options.name!)
    } else {
      await resource.setTags(tags!)
    }
    console.error(`Updated metadata for ${url}`)
    const meta = await resource.meta()
    console.log(JSON.stringify(meta, null, 2))
    return 0
  } catch (err) {
    return reportError({ action: 'update the resource metadata', err })
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
    const target = await resolveCollectionTarget(options)
    const listing = await target.client
      .space(target.spaceId)
      .collection(target.collectionId)
      .list()
    if (listing === null) {
      return reportNotFound(
        wasUrl({
          server: target.server,
          spaceId: target.spaceId,
          collectionId: target.collectionId
        })
      )
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
    const target = await resolveResourceTarget(options)
    await target.client
      .space(target.spaceId)
      .collection(target.collectionId)
      .resource(target.resourceId)
      .delete()
    reportDeleted(
      wasUrl({
        server: target.server,
        spaceId: target.spaceId,
        collectionId: target.collectionId,
        resourceId: target.resourceId
      })
    )
    return 0
  } catch (err) {
    return reportError({ action: 'delete the resource', err })
  }
}
