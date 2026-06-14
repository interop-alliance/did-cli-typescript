/**
 * Shared helpers for the `was` command group: option factories, address
 * parsing/assertion, URL building, error reporting, listing renderers, and
 * the run-and-exit wrapper. Commander `Option` instances are bound to the
 * command they are added to, so the options are exposed as factories.
 */
import { Option } from 'commander'
import {
  WasError,
  type Collection,
  type CollectionsList,
  type Resource,
  type CollectionResourcesList,
  type Space
} from '@interop/was-client'
import { parseWasAddress } from '../../was/address.js'
import { type ResolvedWasTarget } from '../../was/client.js'
import { renderTable, type Column } from '../../table.js'

/**
 * Awaits a command's run function and exits the process with its code when
 * non-zero -- the shared tail of every `was` command action.
 *
 * @param run {Promise<number>}
 * @returns {Promise<void>}
 */
export async function runAndExit(run: Promise<number>): Promise<void> {
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
export function serverOption(): Option {
  return new Option(
    '--server <url>',
    'the WAS server base URL (or WAS_SERVER_URL)'
  )
}

export function didOption(): Option {
  return new Option(
    '--did <did>',
    'DID or stored-DID handle to sign with (or WAS_DID)'
  )
}

export function capabilityOption(): Option {
  return new Option(
    '--capability <ref>',
    'a received capability (encoded string, JSON file, or stored zcap ' +
      'id/handle) instead of a path'
  )
}

export function contentTypeOption(): Option {
  return new Option(
    '--content-type <type>',
    'send the payload as-is with this content type (skips JSON detection)'
  )
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
export function assertOneAddressing({
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
export function wasUrl({
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
export function reportError({
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
export function parseSpaceAddress(address: string): {
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
export function requireCollectionTarget({
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
export function requireResourceTarget({
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
 * @param options.listing {CollectionsList}
 * @param [options.json] {boolean}
 * @param [options.plain] {boolean}
 * @returns {void}
 */
export function printCollectionListing({
  listing,
  json,
  plain
}: {
  listing: CollectionsList
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
 * Renders a resource listing as a table, raw JSON, or one id per line.
 *
 * @param options {object}
 * @param options.listing {CollectionResourcesList}
 * @param [options.json] {boolean}
 * @param [options.plain] {boolean}
 * @returns {void}
 */
export function printResourceListing({
  listing,
  json,
  plain
}: {
  listing: CollectionResourcesList
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
 * Builds the access handle (space, collection, or resource) a resolved
 * target addresses, together with its URL. Policies and publishing work at
 * every depth, so these commands dispatch through this helper.
 *
 * @param target {ResolvedWasTarget}
 * @returns {{handle: Space | Collection | Resource, url: string}}
 */
export function handleForTarget(target: ResolvedWasTarget): {
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
