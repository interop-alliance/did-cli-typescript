/**
 * `was` command -- Wallet Attached Storage (WAS) operations.
 *
 * Talks to WAS servers via `@interop/was-client`, signing every request with
 * a `did:key` DID stored in the local wallet. Spaces are addressed by a
 * single positional WAS path -- `SPACE[/COLLECTION[/RESOURCE]]` -- where the
 * space part is a local registry handle, a bare space id, or a full space
 * https URL (see `src/was/address.ts`). The local space registry
 * (`~/.wallet/was-spaces/`) records each space's server URL and controller
 * DID so day-to-day commands need no `--server`/`--did` flags.
 *
 * Subcommand groups: `space` (`create`, `list`, `show`, `update` alias
 * `configure`, `delete`, `forget`, `add`), `collection` (alias `coll`;
 * `create`, `list`, `show`, `update`, `delete`), and `resource` (alias
 * `res`; `add`, `put`, `get`, `list`, `delete`). The top-level shorthand
 * verbs `ls`, `get`, `put`, and `rm` dispatch on the path depth, mirroring
 * the client's uniform-verbs-at-every-level design. Resource payloads come
 * from a file argument or stdin, with JSON-vs-binary detection in
 * `src/was/io.ts`.
 *
 * Data goes to stdout, diagnostics to stderr. Exit codes: 0 success, 1
 * operation error (typed WAS errors and not-found/not-visible reads), 2
 * input error (bad path syntax, unknown handle/DID, missing server URL).
 */
import { readFile } from 'node:fs/promises'
import { Command, Option } from 'commander'
import {
  WasError,
  type Collection,
  type CollectionListing,
  type PolicyDocument,
  type Resource,
  type ResourceListing,
  type Space
} from '@interop/was-client'
import { parseWasAddress } from '../was/address.js'
import {
  buildWasClient,
  resolveWasTarget,
  type ResolvedWasTarget
} from '../was/client.js'
import { resolveCapabilityTarget } from '../was/capability.js'
import {
  readInputBytes,
  readPayload,
  writeBytesOutput,
  writeResourceOutput
} from '../was/io.js'
import {
  listSpaceRecords,
  removeSpaceRecord,
  resolveSpaceRef,
  saveSpaceRecord
} from '../was/registry.js'
import { resolveDidRef } from '../meta.js'
import { saveToCollection } from '../storage.js'
import { encodeCapability } from '../zcap/encoding.js'
import { expiresFromTtl } from '../zcap/ttl.js'
import { storageIdFor, writeCreateMeta } from './zcap.js'
import { renderTable, type Column } from '../table.js'

/**
 * Awaits a command's run function and exits the process with its code when
 * non-zero -- the shared tail of every `was` command action.
 *
 * @param run {Promise<number>}
 * @returns {Promise<void>}
 */
async function runAndExit(run: Promise<number>): Promise<void> {
  const code = await run
  if (code !== 0) {
    process.exit(code)
  }
}

/**
 * The shared command options, as factories (commander `Option` instances
 * are bound to the command they are added to, so they cannot be shared).
 * Centralizing them keeps the flag names and help text consistent across
 * the whole command tree.
 *
 * @returns {Option}
 */
function serverOption(): Option {
  return new Option(
    '--server <url>',
    'the WAS server base URL (or WAS_SERVER_URL)'
  )
}

function didOption(): Option {
  return new Option(
    '--did <did>',
    'DID or stored-DID handle to sign with (or WAS_DID)'
  )
}

function capabilityOption(): Option {
  return new Option(
    '--capability <ref>',
    'a received capability (encoded string, JSON file, or stored zcap ' +
      'id/handle) instead of a path'
  )
}

function contentTypeOption(): Option {
  return new Option(
    '--content-type <type>',
    'send the payload as-is with this content type (skips JSON detection)'
  )
}

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
 * Guards a run function against receiving both path- and capability-based
 * addressing (or neither).
 *
 * @param options {object}
 * @param [options.address] {string}
 * @param [options.capability] {string}
 * @returns {void}
 */
function assertOneAddressing({
  address,
  capability
}: {
  address?: string
  capability?: string
}): void {
  if (address && capability) {
    throw new Error('Provide either a path or --capability, not both.')
  }
  if (!address && !capability) {
    throw new Error('Provide a path or --capability.')
  }
}

/**
 * Builds the canonical URL of a space, collection, or resource on its
 * server, for messages and output.
 *
 * @param options {object}
 * @param options.server {string}
 * @param options.spaceId {string}
 * @param [options.collectionId] {string}
 * @param [options.resourceId] {string}
 * @returns {string}
 */
function wasUrl({
  server,
  spaceId,
  collectionId,
  resourceId
}: {
  server: string
  spaceId: string
  collectionId?: string
  resourceId?: string
}): string {
  const segments = [spaceId, collectionId, resourceId]
    .filter((segment): segment is string => segment !== undefined)
    .map(encodeURIComponent)
  return `${server.replace(/\/$/, '')}/space/${segments.join('/')}`
}

/**
 * Prints a one-line error for a failed command and classifies its exit code:
 * 1 for operation errors (typed WAS errors from the server exchange), 2 for
 * input errors (bad addresses, unknown handles/DIDs, missing server URL).
 *
 * @param options {object}
 * @param options.action {string}   What failed, e.g. `create the space`.
 * @param options.err {unknown}
 * @returns {number}   The process exit code.
 */
function reportError({
  action,
  err
}: {
  action: string
  err: unknown
}): number {
  const message = err instanceof Error ? err.message : String(err)
  console.error(`Could not ${action}: ${message}`)
  return err instanceof WasError ? 1 : 2
}

/**
 * Parses a WAS address and asserts it addresses a space only (no
 * collection/resource segments), as the `space` subcommands require.
 *
 * @param address {string}
 * @returns {{server?: string, spaceRef: string}}
 */
function parseSpaceAddress(address: string): {
  server?: string
  spaceRef: string
} {
  const parsed = parseWasAddress(address)
  if (parsed.collectionId !== undefined) {
    throw new Error(
      `"${address}" addresses a collection or resource; ` +
        'space commands take a space address.'
    )
  }
  return parsed
}

/**
 * Asserts a resolved target addresses a collection (`SPACE/COLLECTION`,
 * no resource segment) and narrows its type accordingly.
 *
 * @param options {object}
 * @param options.target {ResolvedWasTarget}
 * @param options.address {string}   The original address, for error messages.
 * @returns {ResolvedWasTarget & {collectionId: string}}
 */
function requireCollectionTarget({
  target,
  address
}: {
  target: ResolvedWasTarget
  address: string
}): ResolvedWasTarget & { collectionId: string } {
  if (target.collectionId === undefined || target.resourceId !== undefined) {
    throw new Error(
      `"${address}" must address a collection (SPACE/COLLECTION).`
    )
  }
  return target as ResolvedWasTarget & { collectionId: string }
}

/**
 * Asserts a resolved target addresses a resource
 * (`SPACE/COLLECTION/RESOURCE`) and narrows its type accordingly.
 *
 * @param options {object}
 * @param options.target {ResolvedWasTarget}
 * @param options.address {string}   The original address, for error messages.
 * @returns {ResolvedWasTarget & {collectionId: string, resourceId: string}}
 */
function requireResourceTarget({
  target,
  address
}: {
  target: ResolvedWasTarget
  address: string
}): ResolvedWasTarget & { collectionId: string; resourceId: string } {
  if (target.collectionId === undefined || target.resourceId === undefined) {
    throw new Error(
      `"${address}" must address a resource (SPACE/COLLECTION/RESOURCE).`
    )
  }
  return target as ResolvedWasTarget & {
    collectionId: string
    resourceId: string
  }
}

/**
 * Creates a space on the server and prints `{ id, url, name?, controller }`.
 *
 * @param options {object}
 * @param [options.name] {string}   The space's display name.
 * @param [options.server] {string}   The server base URL.
 * @param [options.did] {string}   The signing DID or stored-DID handle.
 * @param [options.id] {string}   A caller-chosen space id.
 * @param [options.save] {boolean}   Register the space in the local wallet.
 * @param [options.handle] {string}   Short tag for the registry entry.
 * @param [options.description] {string}   Longer registry entry description.
 * @returns {Promise<number>}   The process exit code.
 */
export async function runSpaceCreate(options: {
  name?: string
  server?: string
  did?: string
  id?: string
  save?: boolean
  handle?: string
  description?: string
}): Promise<number> {
  try {
    const { client, server, did } = await buildWasClient({
      server: options.server,
      did: options.did
    })
    const space = await client.createSpace({
      ...(options.name !== undefined && { name: options.name }),
      ...(options.id !== undefined && { id: options.id })
    })
    const url = wasUrl({ server, spaceId: space.id })
    if (options.save) {
      const filePath = await saveSpaceRecord({
        record: {
          id: space.id,
          ...(options.name !== undefined && { name: options.name }),
          server,
          controller: did
        },
        handle: options.handle,
        description: options.description
      })
      console.error(`Space registered in ${filePath}`)
    }
    console.log(
      JSON.stringify(
        {
          id: space.id,
          url,
          ...(options.name !== undefined && { name: options.name }),
          controller: did
        },
        null,
        2
      )
    )
    return 0
  } catch (err) {
    return reportError({ action: 'create the space', err })
  }
}

/**
 * Lists the locally registered spaces (the working model while servers do
 * not implement List Spaces); `--remote` asks the server instead.
 *
 * @param options {object}
 * @param [options.json] {boolean}   Output a JSON array with metadata.
 * @param [options.plain] {boolean}   Output one space id per line.
 * @param [options.remote] {boolean}   List spaces on the server instead.
 * @param [options.server] {string}   The server base URL (with `--remote`).
 * @param [options.did] {string}   The signing DID (with `--remote`).
 * @returns {Promise<number>}   The process exit code.
 */
export async function runSpaceList(options: {
  json?: boolean
  plain?: boolean
  remote?: boolean
  server?: string
  did?: string
}): Promise<number> {
  try {
    if (options.remote) {
      const { client } = await buildWasClient({
        server: options.server,
        did: options.did
      })
      const listing = await client.listSpaces()
      console.log(JSON.stringify(listing, null, 2))
      return 0
    }

    const entries = await listSpaceRecords()
    if (options.plain) {
      const spaceIds = entries.map(entry => entry.record.id).sort()
      for (const spaceId of spaceIds) {
        console.log(spaceId)
      }
      return 0
    }
    if (options.json) {
      const output = entries.map(entry => ({
        id: entry.record.id,
        server: entry.record.server,
        ...(entry.record.name && { name: entry.record.name }),
        ...(entry.record.controller && {
          controller: entry.record.controller
        }),
        ...(entry.meta?.created && { created: entry.meta.created }),
        ...(entry.meta?.handle && { handle: entry.meta.handle }),
        ...(entry.meta?.description && {
          description: entry.meta.description
        })
      }))
      console.log(JSON.stringify(output, null, 2))
      return 0
    }
    if (entries.length === 0) {
      return 0
    }
    const rows = entries.map(entry => [
      entry.meta?.handle ?? '',
      entry.record.name ?? '',
      entry.record.id,
      entry.record.server,
      entry.meta?.created?.slice(0, 10) ?? ''
    ])
    console.log(
      renderTable({
        columns: [
          { header: 'HANDLE', maxWidth: 16 },
          { header: 'NAME', maxWidth: 20 },
          { header: 'SPACE ID', maxWidth: 40 },
          { header: 'SERVER', maxWidth: 32 },
          { header: 'CREATED' }
        ],
        rows
      })
    )
    return 0
  } catch (err) {
    return reportError({ action: 'list spaces', err })
  }
}

/**
 * Shows a space: its Space Description from the server, or (`--meta`) its
 * local registry record and metadata.
 *
 * @param options {object}
 * @param options.address {string}   The space address.
 * @param [options.meta] {boolean}   Show the local registry metadata instead.
 * @param [options.json] {boolean}   With `--meta`, output JSON.
 * @param [options.server] {string}   The server base URL.
 * @param [options.did] {string}   The signing DID or stored-DID handle.
 * @returns {Promise<number>}   The process exit code.
 */
export async function runSpaceShow(options: {
  address: string
  meta?: boolean
  json?: boolean
  server?: string
  did?: string
}): Promise<number> {
  try {
    const parsed = parseSpaceAddress(options.address)
    if (options.meta) {
      const entry = await resolveSpaceRef({ ref: parsed.spaceRef })
      if (!entry) {
        throw new Error(
          `No locally registered space found for "${parsed.spaceRef}".`
        )
      }
      if (options.json) {
        const output = {
          id: entry.record.id,
          server: entry.record.server,
          ...(entry.record.name && { name: entry.record.name }),
          ...(entry.record.controller && {
            controller: entry.record.controller
          }),
          ...(entry.meta?.created && { created: entry.meta.created }),
          ...(entry.meta?.handle && { handle: entry.meta.handle }),
          ...(entry.meta?.description && {
            description: entry.meta.description
          })
        }
        console.log(JSON.stringify(output, null, 2))
        return 0
      }
      const rows = [
        ['ID', entry.record.id],
        ['Name', entry.record.name ?? ''],
        ['Server', entry.record.server],
        ['Controller', entry.record.controller ?? ''],
        ['Handle', entry.meta?.handle ?? ''],
        ['Created', entry.meta?.created ?? ''],
        ['Description', entry.meta?.description ?? '']
      ]
      console.log(
        renderTable({
          columns: [{ header: 'FIELD' }, { header: 'VALUE' }],
          rows
        })
      )
      return 0
    }

    const target = await resolveWasTarget({
      address: options.address,
      server: options.server,
      did: options.did
    })
    const description = await target.client.space(target.spaceId).describe()
    if (description === null) {
      console.error(
        'Not found (or not visible to you): ' +
          wasUrl({ server: target.server, spaceId: target.spaceId })
      )
      return 1
    }
    console.log(JSON.stringify(description, null, 2))
    return 0
  } catch (err) {
    return reportError({ action: 'show the space', err })
  }
}

/**
 * Updates a space's description fields on the server (upsert via
 * `configure()`), refreshing the name in the local registry entry when one
 * exists.
 *
 * @param options {object}
 * @param options.address {string}   The space address.
 * @param [options.name] {string}   The new display name.
 * @param [options.server] {string}   The server base URL.
 * @param [options.did] {string}   The signing DID or stored-DID handle.
 * @returns {Promise<number>}   The process exit code.
 */
export async function runSpaceUpdate(options: {
  address: string
  name?: string
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
    const description = await target.client.space(target.spaceId).configure({
      ...(options.name !== undefined && { name: options.name })
    })
    if (target.entry && options.name !== undefined) {
      await saveSpaceRecord({
        record: { ...target.entry.record, name: options.name }
      })
    }
    console.log(JSON.stringify(description, null, 2))
    return 0
  } catch (err) {
    return reportError({ action: 'update the space', err })
  }
}

/**
 * Deletes a space on the server (idempotent) and removes its local registry
 * entry when one exists. The local-only counterpart is `forget`.
 *
 * @param options {object}
 * @param options.address {string}   The space address.
 * @param [options.server] {string}   The server base URL.
 * @param [options.did] {string}   The signing DID or stored-DID handle.
 * @returns {Promise<number>}   The process exit code.
 */
export async function runSpaceDelete(options: {
  address: string
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
    await target.client.space(target.spaceId).delete()
    console.error(
      'Deleted ' +
        wasUrl({ server: target.server, spaceId: target.spaceId }) +
        ' on the server.'
    )
    if (target.entry) {
      const removed = await removeSpaceRecord({
        storageId: target.entry.storageId
      })
      for (const filePath of removed) {
        console.error(`Removed ${filePath}`)
      }
    }
    return 0
  } catch (err) {
    return reportError({ action: 'delete the space', err })
  }
}

/**
 * Removes a space's local registry entry only; the server-side space is
 * untouched. The remote counterpart is `delete`.
 *
 * @param options {object}
 * @param options.address {string}   The space address.
 * @returns {Promise<number>}   The process exit code.
 */
export async function runSpaceForget(options: {
  address: string
}): Promise<number> {
  try {
    const parsed = parseSpaceAddress(options.address)
    const entry = await resolveSpaceRef({ ref: parsed.spaceRef })
    if (!entry) {
      throw new Error(
        `No locally registered space found for "${parsed.spaceRef}".`
      )
    }
    const removed = await removeSpaceRecord({ storageId: entry.storageId })
    for (const filePath of removed) {
      console.error(`Removed ${filePath}`)
    }
    return 0
  } catch (err) {
    return reportError({ action: 'forget the space', err })
  }
}

/**
 * Registers an existing remote space (e.g. created elsewhere or received via
 * delegation) in the local registry, verifying it first with `describe()`.
 *
 * @param options {object}
 * @param options.address {string}   A full space https URL or a bare space id.
 * @param [options.server] {string}   The server base URL (with a bare id).
 * @param [options.did] {string}   The signing DID or stored-DID handle.
 * @param [options.handle] {string}   Short tag for the registry entry.
 * @param [options.description] {string}   Longer registry entry description.
 * @returns {Promise<number>}   The process exit code.
 */
export async function runSpaceAdd(options: {
  address: string
  server?: string
  did?: string
  handle?: string
  description?: string
}): Promise<number> {
  try {
    parseSpaceAddress(options.address)
    const target = await resolveWasTarget({
      address: options.address,
      server: options.server,
      did: options.did
    })
    const description = await target.client.space(target.spaceId).describe()
    if (description === null) {
      console.error(
        'Not found (or not visible to you): ' +
          wasUrl({ server: target.server, spaceId: target.spaceId })
      )
      return 1
    }
    const filePath = await saveSpaceRecord({
      record: {
        id: target.spaceId,
        ...(description.name && { name: description.name }),
        server: target.server,
        controller: description.controller ?? target.did
      },
      handle: options.handle,
      description: options.description
    })
    console.error(`Space registered in ${filePath}`)
    console.log(JSON.stringify(description, null, 2))
    return 0
  } catch (err) {
    return reportError({ action: 'add the space', err })
  }
}

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
 * Renders a listing as a table, raw JSON, or one item id per line -- the
 * shared output logic of `collection list`, `resource list`, and `ls`.
 *
 * @param options {object}
 * @param options.listing {{items: T[]}}
 * @param [options.json] {boolean}
 * @param [options.plain] {boolean}
 * @param options.columns {Column[]}
 * @param options.toRow {(item: T) => string[]}
 * @returns {void}
 */
function printListing<T extends { id: string }>({
  listing,
  json,
  plain,
  columns,
  toRow
}: {
  listing: { items: T[] }
  json?: boolean
  plain?: boolean
  columns: Column[]
  toRow: (item: T) => string[]
}): void {
  if (json) {
    console.log(JSON.stringify(listing, null, 2))
    return
  }
  if (plain) {
    const ids = listing.items.map(item => item.id).sort()
    for (const id of ids) {
      console.log(id)
    }
    return
  }
  if (listing.items.length === 0) {
    return
  }
  console.log(renderTable({ columns, rows: listing.items.map(toRow) }))
}

/**
 * Renders a collection listing as a table, raw JSON, or one id per line.
 *
 * @param options {object}
 * @param options.listing {CollectionListing}
 * @param [options.json] {boolean}
 * @param [options.plain] {boolean}
 * @returns {void}
 */
function printCollectionListing({
  listing,
  json,
  plain
}: {
  listing: CollectionListing
  json?: boolean
  plain?: boolean
}): void {
  printListing({
    listing,
    json,
    plain,
    columns: [
      { header: 'ID', maxWidth: 30 },
      { header: 'NAME', maxWidth: 20 },
      { header: 'URL' }
    ],
    toRow: item => [item.id, item.name, item.url]
  })
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
 * Renders a resource listing as a table, raw JSON, or one id per line.
 *
 * @param options {object}
 * @param options.listing {ResourceListing}
 * @param [options.json] {boolean}
 * @param [options.plain] {boolean}
 * @returns {void}
 */
function printResourceListing({
  listing,
  json,
  plain
}: {
  listing: ResourceListing
  json?: boolean
  plain?: boolean
}): void {
  printListing({
    listing,
    json,
    plain,
    columns: [
      { header: 'ID', maxWidth: 30 },
      { header: 'CONTENT TYPE', maxWidth: 24 },
      { header: 'URL' }
    ],
    toRow: item => [item.id, item.contentType, item.url]
  })
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
          console.error(`Not found (or not visible to you): ${resolved.url}`)
          return 1
        }
        printCollectionListing({
          listing,
          json: options.json,
          plain: options.plain
        })
      } else {
        const listing = await resolved.handle.list()
        if (listing === null) {
          console.error(`Not found (or not visible to you): ${resolved.url}`)
          return 1
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
      console.error(`Deleted ${resolved.url} on the server.`)
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

/**
 * Builds the access handle (space, collection, or resource) a resolved
 * target addresses, together with its URL. Policies and publishing work at
 * every depth, so these commands dispatch through this helper.
 *
 * @param target {ResolvedWasTarget}
 * @returns {{handle: Space | Collection | Resource, url: string}}
 */
function handleForTarget(target: ResolvedWasTarget): {
  handle: Space | Collection | Resource
  url: string
} {
  const url = wasUrl({
    server: target.server,
    spaceId: target.spaceId,
    collectionId: target.collectionId,
    resourceId: target.resourceId
  })
  const space = target.client.space(target.spaceId)
  if (target.collectionId === undefined) {
    return { handle: space, url }
  }
  const collection = space.collection(target.collectionId)
  if (target.resourceId === undefined) {
    return { handle: collection, url }
  }
  return { handle: collection.resource(target.resourceId), url }
}

/**
 * Shows the access-control policy of a space, collection, or resource.
 *
 * @param options {object}
 * @param options.address {string}   A space/collection/resource address.
 * @param [options.server] {string}   The server base URL.
 * @param [options.did] {string}   The signing DID or stored-DID handle.
 * @returns {Promise<number>}   The process exit code.
 */
export async function runPolicyShow(options: {
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
    const policy = await handle.getPolicy()
    if (policy === null) {
      console.error(`No policy set (or not visible to you): ${url}`)
      return 1
    }
    console.log(JSON.stringify(policy, null, 2))
    return 0
  } catch (err) {
    return reportError({ action: 'show the policy', err })
  }
}

/**
 * Parses the `policy set` arguments -- `--type <type>` for a simple
 * type-only policy, or a JSON file for richer ones -- into a policy
 * document.
 *
 * @param options {object}
 * @param [options.type] {string}
 * @param [options.file] {string}
 * @returns {Promise<PolicyDocument>}
 */
async function resolvePolicyInput({
  type,
  file
}: {
  type?: string
  file?: string
}): Promise<PolicyDocument> {
  if (type && file) {
    throw new Error('Provide either --type or a policy file, not both.')
  }
  if (type) {
    return { type }
  }
  if (!file) {
    throw new Error('Provide --type <type> or a policy JSON file.')
  }
  let parsed: unknown
  try {
    parsed = JSON.parse(await readFile(file, 'utf8'))
  } catch (err) {
    throw new Error(
      `${file} does not contain policy JSON: ` +
        `${err instanceof Error ? err.message : String(err)}`,
      { cause: err }
    )
  }
  if (
    parsed === null ||
    typeof parsed !== 'object' ||
    Array.isArray(parsed) ||
    typeof (parsed as { type?: unknown }).type !== 'string'
  ) {
    throw new Error(`${file} must hold a policy object with a "type" field.`)
  }
  return parsed as PolicyDocument
}

/**
 * Sets (creates or replaces) the access-control policy of a space,
 * collection, or resource, and prints the policy document that was set.
 *
 * @param options {object}
 * @param options.address {string}   A space/collection/resource address.
 * @param [options.file] {string}   A policy JSON file.
 * @param [options.type] {string}   A simple type-only policy (e.g.
 *   PublicCanRead).
 * @param [options.server] {string}   The server base URL.
 * @param [options.did] {string}   The signing DID or stored-DID handle.
 * @returns {Promise<number>}   The process exit code.
 */
export async function runPolicySet(options: {
  address: string
  file?: string
  type?: string
  server?: string
  did?: string
}): Promise<number> {
  try {
    const policy = await resolvePolicyInput({
      type: options.type,
      file: options.file
    })
    const target = await resolveWasTarget({
      address: options.address,
      server: options.server,
      did: options.did
    })
    const { handle, url } = handleForTarget(target)
    await handle.setPolicy(policy)
    console.error(`Policy set on ${url}`)
    console.log(JSON.stringify(policy, null, 2))
    return 0
  } catch (err) {
    return reportError({ action: 'set the policy', err })
  }
}

/**
 * Removes the access-control policy of a space, collection, or resource,
 * reverting it to capability-only access. Idempotent.
 *
 * @param options {object}
 * @param options.address {string}   A space/collection/resource address.
 * @param [options.server] {string}   The server base URL.
 * @param [options.did] {string}   The signing DID or stored-DID handle.
 * @returns {Promise<number>}   The process exit code.
 */
export async function runPolicyClear(options: {
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
    console.error(`Cleared the policy on ${url} (capability-only access).`)
    return 0
  } catch (err) {
    return reportError({ action: 'clear the policy', err })
  }
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
 * Exports a whole space as a tar archive, written to `--output` or raw to
 * stdout.
 *
 * @param options {object}
 * @param options.address {string}   The space address.
 * @param [options.output] {string}   The output file path; stdout when
 *   omitted.
 * @param [options.server] {string}   The server base URL.
 * @param [options.did] {string}   The signing DID or stored-DID handle.
 * @returns {Promise<number>}   The process exit code.
 */
export async function runSpaceExport(options: {
  address: string
  output?: string
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
    const bytes = await target.client.space(target.spaceId).export()
    await writeBytesOutput({ bytes, output: options.output })
    return 0
  } catch (err) {
    return reportError({ action: 'export the space', err })
  }
}

/**
 * Imports (merges) a tar archive into a space and prints the import stats
 * summary.
 *
 * @param options {object}
 * @param options.address {string}   The space address.
 * @param [options.file] {string}   The tar file; stdin when omitted.
 * @param [options.server] {string}   The server base URL.
 * @param [options.did] {string}   The signing DID or stored-DID handle.
 * @returns {Promise<number>}   The process exit code.
 */
export async function runSpaceImport(options: {
  address: string
  file?: string
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
    const tar = await readInputBytes({ file: options.file })
    const stats = await target.client.space(target.spaceId).import(tar)
    console.log(JSON.stringify(stats, null, 2))
    return 0
  } catch (err) {
    return reportError({ action: 'import into the space', err })
  }
}

/**
 * Delegates access to a space, collection, or resource: signs a capability
 * for the `--to` DID with the given actions and expiration, and prints
 * `{ delegatedCapability, encoded }` (the same shape as `zcap delegate`).
 * `--save` stores the capability in the local zcap store
 * (`~/.wallet/zcaps/`).
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

export function makeWasCommand(): Command {
  const was = new Command('was').description(
    'Wallet Attached Storage (WAS) operations'
  )

  const space = new Command('space').description('Manage WAS spaces')

  space
    .command('create')
    .description('Create a new space on a WAS server')
    .option('--name <name>', "the space's display name")
    .addOption(serverOption())
    .addOption(didOption())
    .option(
      '--id <id>',
      'a caller-chosen space id (server-generated otherwise)'
    )
    .option(
      '--save',
      'register the space in the local wallet (~/.wallet/was-spaces/)'
    )
    .option(
      '--handle <handle>',
      'short tag for the registered space (requires --save)'
    )
    .option(
      '--description <description>',
      'longer description of the registered space (requires --save)'
    )
    .action(
      async (options: {
        name?: string
        server?: string
        did?: string
        id?: string
        save?: boolean
        handle?: string
        description?: string
      }) => {
        if (
          (options.handle !== undefined || options.description !== undefined) &&
          !options.save
        ) {
          console.error('--handle and --description require --save')
          process.exit(2)
          return
        }
        await runAndExit(runSpaceCreate(options))
      }
    )

  space
    .command('list')
    .description('List locally registered spaces')
    .option(
      '--json',
      'output the list as a JSON array of objects with metadata'
    )
    .option('--plain', 'output one space id per line, sorted (no metadata)')
    .option(
      '--remote',
      'list the spaces on the server instead (requires server support)'
    )
    .option('--server <url>', 'the WAS server base URL (with --remote)')
    .option(
      '--did <did>',
      'DID or stored-DID handle to sign with (with --remote)'
    )
    .action(
      async (options: {
        json?: boolean
        plain?: boolean
        remote?: boolean
        server?: string
        did?: string
      }) => {
        await runAndExit(runSpaceList(options))
      }
    )

  space
    .command('show <space>')
    .aliases(['view', 'cat'])
    .description(
      "Show a space's description from the server (--meta for its local " +
        'registry metadata)'
    )
    .option('--meta', 'show the local registry metadata instead')
    .option('--json', 'with --meta, output the metadata as JSON')
    .addOption(serverOption())
    .addOption(didOption())
    .action(
      async (
        address: string,
        options: {
          meta?: boolean
          json?: boolean
          server?: string
          did?: string
        }
      ) => {
        await runAndExit(runSpaceShow({ address, ...options }))
      }
    )

  space
    .command('update <space>')
    .alias('configure')
    .description("Update a space's description fields on the server (upsert)")
    .option('--name <name>', "the space's new display name")
    .addOption(serverOption())
    .addOption(didOption())
    .action(
      async (
        address: string,
        options: { name?: string; server?: string; did?: string }
      ) => {
        await runAndExit(runSpaceUpdate({ address, ...options }))
      }
    )

  space
    .command('delete <space>')
    .alias('rm')
    .description(
      'Delete a space on the server (idempotent) and remove its local ' +
        'registry entry'
    )
    .addOption(serverOption())
    .addOption(didOption())
    .action(
      async (address: string, options: { server?: string; did?: string }) => {
        await runAndExit(runSpaceDelete({ address, ...options }))
      }
    )

  space
    .command('forget <space>')
    .description(
      'Remove only the local registry entry of a space (the server-side ' +
        'space is untouched)'
    )
    .action(async (address: string) => {
      await runAndExit(runSpaceForget({ address }))
    })

  space
    .command('add <space>')
    .description(
      'Register an existing remote space (a full space URL, or a space id ' +
        'plus --server) in the local registry'
    )
    .addOption(serverOption())
    .addOption(didOption())
    .option('--handle <handle>', 'short tag for the registered space')
    .option(
      '--description <description>',
      'longer description of the registered space'
    )
    .action(
      async (
        address: string,
        options: {
          server?: string
          did?: string
          handle?: string
          description?: string
        }
      ) => {
        await runAndExit(runSpaceAdd({ address, ...options }))
      }
    )

  space
    .command('export <space>')
    .description('Export a whole space as a tar archive')
    .option('--output <file>', 'write the tar to a file (stdout otherwise)')
    .addOption(serverOption())
    .addOption(didOption())
    .action(
      async (
        address: string,
        options: { output?: string; server?: string; did?: string }
      ) => {
        await runAndExit(runSpaceExport({ address, ...options }))
      }
    )

  space
    .command('import <space> [file]')
    .description(
      'Import (merge) a tar archive into a space; tar from file or stdin'
    )
    .addOption(serverOption())
    .addOption(didOption())
    .action(
      async (
        address: string,
        file: string | undefined,
        options: { server?: string; did?: string }
      ) => {
        await runAndExit(runSpaceImport({ address, file, ...options }))
      }
    )

  was.addCommand(space)

  const collection = new Command('collection')
    .alias('coll')
    .description('Manage WAS collections')

  collection
    .command('create <space>')
    .description('Create a new collection within a space')
    .option('--name <name>', "the collection's display name")
    .option(
      '--id <id>',
      'a caller-chosen collection id (server-generated otherwise)'
    )
    .addOption(serverOption())
    .addOption(didOption())
    .action(
      async (
        address: string,
        options: { name?: string; id?: string; server?: string; did?: string }
      ) => {
        await runAndExit(runCollectionCreate({ address, ...options }))
      }
    )

  collection
    .command('list <space>')
    .description('List the collections in a space')
    .option('--json', 'output the raw listing JSON')
    .option('--plain', 'output one collection id per line, sorted')
    .addOption(serverOption())
    .addOption(didOption())
    .action(
      async (
        address: string,
        options: {
          json?: boolean
          plain?: boolean
          server?: string
          did?: string
        }
      ) => {
        await runAndExit(runCollectionList({ address, ...options }))
      }
    )

  collection
    .command('show <path>')
    .aliases(['view', 'cat'])
    .description(
      "Show a collection's description from the server (SPACE/COLLECTION)"
    )
    .addOption(serverOption())
    .addOption(didOption())
    .action(
      async (address: string, options: { server?: string; did?: string }) => {
        await runAndExit(runCollectionShow({ address, ...options }))
      }
    )

  collection
    .command('update <path>')
    .alias('configure')
    .description(
      "Update a collection's description fields on the server (upsert)"
    )
    .requiredOption('--name <name>', "the collection's new display name")
    .addOption(serverOption())
    .addOption(didOption())
    .action(
      async (
        address: string,
        options: { name: string; server?: string; did?: string }
      ) => {
        await runAndExit(runCollectionUpdate({ address, ...options }))
      }
    )

  collection
    .command('delete <path>')
    .alias('rm')
    .description(
      'Delete a whole collection and its contents on the server (idempotent)'
    )
    .addOption(serverOption())
    .addOption(didOption())
    .action(
      async (address: string, options: { server?: string; did?: string }) => {
        await runAndExit(runCollectionDelete({ address, ...options }))
      }
    )

  was.addCommand(collection)

  const resource = new Command('resource')
    .alias('res')
    .description('Manage WAS resources')

  resource
    .command('add [path] [file]')
    .description(
      'Add a resource to a collection (server-generated id); payload from ' +
        'file or stdin'
    )
    .addOption(contentTypeOption())
    .addOption(capabilityOption())
    .addOption(serverOption())
    .addOption(didOption())
    .action(
      async (
        address: string | undefined,
        file: string | undefined,
        options: {
          contentType?: string
          capability?: string
          server?: string
          did?: string
        }
      ) => {
        // With --capability the path is omitted, so a single positional
        // argument is the payload file.
        if (options.capability && file === undefined) {
          file = address
          address = undefined
        }
        await runAndExit(runResourceAdd({ address, file, ...options }))
      }
    )

  resource
    .command('put [path] [file]')
    .description(
      'Create or replace a resource at a known id (upsert); payload from ' +
        'file or stdin'
    )
    .addOption(contentTypeOption())
    .addOption(capabilityOption())
    .addOption(serverOption())
    .addOption(didOption())
    .action(
      async (
        address: string | undefined,
        file: string | undefined,
        options: {
          contentType?: string
          capability?: string
          server?: string
          did?: string
        }
      ) => {
        // With --capability the path is omitted, so a single positional
        // argument is the payload file.
        if (options.capability && file === undefined) {
          file = address
          address = undefined
        }
        await runAndExit(runResourcePut({ address, file, ...options }))
      }
    )

  resource
    .command('get [path]')
    .description(
      'Read a resource: JSON pretty-printed to stdout, binary written raw'
    )
    .option('--output <file>', 'write the resource content to a file')
    .addOption(capabilityOption())
    .addOption(serverOption())
    .addOption(didOption())
    .action(
      async (
        address: string | undefined,
        options: {
          output?: string
          capability?: string
          server?: string
          did?: string
        }
      ) => {
        await runAndExit(runResourceGet({ address, ...options }))
      }
    )

  resource
    .command('list <path>')
    .description('List the resources in a collection (SPACE/COLLECTION)')
    .option('--json', 'output the raw listing JSON')
    .option('--plain', 'output one resource id per line, sorted')
    .addOption(serverOption())
    .addOption(didOption())
    .action(
      async (
        address: string,
        options: {
          json?: boolean
          plain?: boolean
          server?: string
          did?: string
        }
      ) => {
        await runAndExit(runResourceList({ address, ...options }))
      }
    )

  resource
    .command('delete <path>')
    .alias('rm')
    .description('Delete a resource on the server (idempotent)')
    .addOption(serverOption())
    .addOption(didOption())
    .action(
      async (address: string, options: { server?: string; did?: string }) => {
        await runAndExit(runResourceDelete({ address, ...options }))
      }
    )

  was.addCommand(resource)

  was
    .command('ls [path]')
    .description(
      'List the collections of a space, or the resources of a collection'
    )
    .option('--json', 'output the raw listing JSON')
    .option('--plain', 'output one id per line, sorted')
    .addOption(capabilityOption())
    .addOption(serverOption())
    .addOption(didOption())
    .action(
      async (
        address: string | undefined,
        options: {
          json?: boolean
          plain?: boolean
          capability?: string
          server?: string
          did?: string
        }
      ) => {
        await runAndExit(runLs({ address, ...options }))
      }
    )

  was
    .command('get [path]')
    .description('Read a resource (shorthand for "resource get")')
    .option('--output <file>', 'write the resource content to a file')
    .addOption(capabilityOption())
    .addOption(serverOption())
    .addOption(didOption())
    .action(
      async (
        address: string | undefined,
        options: {
          output?: string
          capability?: string
          server?: string
          did?: string
        }
      ) => {
        await runAndExit(runResourceGet({ address, ...options }))
      }
    )

  was
    .command('put [path] [file]')
    .description('Create or replace a resource (shorthand for "resource put")')
    .addOption(contentTypeOption())
    .addOption(capabilityOption())
    .addOption(serverOption())
    .addOption(didOption())
    .action(
      async (
        address: string | undefined,
        file: string | undefined,
        options: {
          contentType?: string
          capability?: string
          server?: string
          did?: string
        }
      ) => {
        // With --capability the path is omitted, so a single positional
        // argument is the payload file.
        if (options.capability && file === undefined) {
          file = address
          address = undefined
        }
        await runAndExit(runResourcePut({ address, file, ...options }))
      }
    )

  was
    .command('rm [path]')
    .description(
      'Delete whatever the path points at: a space, a collection, or a ' +
        'resource'
    )
    .addOption(capabilityOption())
    .addOption(serverOption())
    .addOption(didOption())
    .action(
      async (
        address: string | undefined,
        options: { capability?: string; server?: string; did?: string }
      ) => {
        await runAndExit(runRm({ address, ...options }))
      }
    )

  const policy = new Command('policy').description(
    'Manage access-control policies (at space, collection, or resource depth)'
  )

  policy
    .command('show <path>')
    .aliases(['view', 'cat'])
    .description('Show the access-control policy of a path')
    .addOption(serverOption())
    .addOption(didOption())
    .action(
      async (address: string, options: { server?: string; did?: string }) => {
        await runAndExit(runPolicyShow({ address, ...options }))
      }
    )

  policy
    .command('set <path> [file]')
    .description(
      'Set the access-control policy of a path: --type for a simple ' +
        'type-only policy, or a policy JSON file'
    )
    .option('--type <type>', 'a simple type-only policy, e.g. PublicCanRead')
    .addOption(serverOption())
    .addOption(didOption())
    .action(
      async (
        address: string,
        file: string | undefined,
        options: { type?: string; server?: string; did?: string }
      ) => {
        await runAndExit(runPolicySet({ address, file, ...options }))
      }
    )

  policy
    .command('clear <path>')
    .description(
      'Remove the access-control policy of a path (back to capability-only ' +
        'access; idempotent)'
    )
    .addOption(serverOption())
    .addOption(didOption())
    .action(
      async (address: string, options: { server?: string; did?: string }) => {
        await runAndExit(runPolicyClear({ address, ...options }))
      }
    )

  was.addCommand(policy)

  was
    .command('publish <path>')
    .description(
      'Make a space, collection, or resource world-readable and print its ' +
        'public URL'
    )
    .addOption(serverOption())
    .addOption(didOption())
    .action(
      async (address: string, options: { server?: string; did?: string }) => {
        await runAndExit(runPublish({ address, ...options }))
      }
    )

  was
    .command('unpublish <path>')
    .description(
      'Revert a published space, collection, or resource to capability-only ' +
        'access'
    )
    .addOption(serverOption())
    .addOption(didOption())
    .action(
      async (address: string, options: { server?: string; did?: string }) => {
        await runAndExit(runUnpublish({ address, ...options }))
      }
    )

  was
    .command('grant <path>')
    .description(
      'Delegate access to a space, collection, or resource (prints the ' +
        'signed capability and its encoded form)'
    )
    .requiredOption(
      '--to <did>',
      'the DID (or stored-DID handle) to delegate to'
    )
    .requiredOption(
      '--action <verb...>',
      'allowed action(s): GET, PUT, POST, DELETE (lowercase accepted)'
    )
    .option('--ttl <duration>', 'time to live, e.g. 1y, 30d, 24h', '1y')
    .option('--expires <iso>', 'explicit ISO 8601 expiration (overrides --ttl)')
    .option(
      '--save',
      'save the capability to local wallet storage (~/.wallet/zcaps/)'
    )
    .option(
      '--handle <handle>',
      'short tag for the saved capability (requires --save)'
    )
    .option(
      '--description <description>',
      'longer description of the saved capability (requires --save)'
    )
    .addOption(serverOption())
    .addOption(didOption())
    .action(
      async (
        address: string,
        options: {
          to: string
          action: string[]
          ttl?: string
          expires?: string
          save?: boolean
          handle?: string
          description?: string
          server?: string
          did?: string
        }
      ) => {
        if (
          (options.handle !== undefined || options.description !== undefined) &&
          !options.save
        ) {
          console.error('--handle and --description require --save')
          process.exit(2)
          return
        }
        await runAndExit(runGrant({ address, ...options }))
      }
    )

  return was
}
