/**
 * Shared helpers for the `was` command group: option factories, address
 * parsing/assertion, URL building, error reporting, listing renderers, and
 * the run-and-exit wrapper. Commander `Option` instances are bound to the
 * command they are added to, so the options are exposed as factories.
 */
import { STATUS_CODES } from 'node:http'
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
import { resolveWasTarget, type ResolvedWasTarget } from '../../was/client.js'
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
 * For a `WasError` the HTTP status and its reason phrase (e.g.
 * `HTTP 415 Unsupported Media Type`) plus any server-provided problem details
 * are appended, so a generic client message like `Request error` still carries
 * the actionable status instead of hiding it.
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
  if (err instanceof WasError) {
    const detail: string[] = []
    if (typeof err.status === 'number') {
      const reason = STATUS_CODES[err.status]
      detail.push(`HTTP ${err.status}${reason ? ` ${reason}` : ''}`)
    }
    if (err.details?.length) {
      detail.push(...err.details)
    }
    const suffix = detail.length > 0 ? ` (${detail.join('; ')})` : ''
    console.error(`Could not ${action}: ${err.message}${suffix}`)
    return 1
  }
  const message = err instanceof Error ? err.message : String(err)
  console.error(`Could not ${action}: ${message}`)
  return 2
}

/**
 * Reports a missing or not-visible read target (a `null` server response)
 * with the standard message and returns the not-found exit code (1).
 *
 * @param url {string}   The canonical URL of the target.
 * @returns {number}   The process exit code (1).
 */
export function reportNotFound(url: string): number {
  console.error(`Not found (or not visible to you): ${url}`)
  return 1
}

/**
 * Reports a successful server-side deletion with the standard message.
 *
 * @param url {string}   The canonical URL of the deleted target.
 * @returns {void}
 */
export function reportDeleted(url: string): void {
  console.error(`Deleted ${url} on the server.`)
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
 * Resolves a WAS address and asserts it addresses a collection -- the
 * `resolveWasTarget` + `requireCollectionTarget` pair the collection/resource
 * verbs repeat.
 *
 * @param options {object}
 * @param options.address {string}   The collection address.
 * @param [options.server] {string}   The server base URL.
 * @param [options.did] {string}   The signing DID or stored-DID handle.
 * @returns {Promise<ResolvedWasTarget & {collectionId: string}>}
 */
export async function resolveCollectionTarget({
  address,
  server,
  did
}: {
  address: string
  server?: string
  did?: string
}): Promise<ResolvedWasTarget & { collectionId: string }> {
  return requireCollectionTarget({
    target: await resolveWasTarget({ address, server, did }),
    address
  })
}

/**
 * Resolves a WAS address and asserts it addresses a resource -- the
 * `resolveWasTarget` + `requireResourceTarget` pair the resource verbs repeat.
 *
 * @param options {object}
 * @param options.address {string}   The resource address.
 * @param [options.server] {string}   The server base URL.
 * @param [options.did] {string}   The signing DID or stored-DID handle.
 * @returns {Promise<ResolvedWasTarget & {collectionId: string, resourceId: string}>}
 */
export async function resolveResourceTarget({
  address,
  server,
  did
}: {
  address: string
  server?: string
  did?: string
}): Promise<ResolvedWasTarget & { collectionId: string; resourceId: string }> {
  return requireResourceTarget({
    target: await resolveWasTarget({ address, server, did }),
    address
  })
}

/**
 * Resolves the `--capability`/positional payload-argument ambiguity for the
 * resource `add`/`put` verbs: with `--capability` the path is omitted, so a
 * single positional argument is the payload file, not the address.
 *
 * @param options {object}
 * @param [options.address] {string}   The first positional argument.
 * @param [options.file] {string}   The second positional argument.
 * @param [options.capability] {string}   The capability reference, if any.
 * @returns {{address?: string, file?: string}}
 */
export function disambiguatePayloadArgs({
  address,
  file,
  capability
}: {
  address?: string
  file?: string
  capability?: string
}): { address?: string; file?: string } {
  if (capability && file === undefined) {
    return { address: undefined, file: address }
  }
  return { address, file }
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
 * Renders a two-column FIELD/VALUE detail table -- the shared layout of the
 * single-record `show`/`backend`/`quota` views.
 *
 * @param rows {string[][]}   The `[field, value]` pairs.
 * @returns {void}
 */
export function printFieldValueTable(rows: string[][]): void {
  console.log(
    renderTable({
      columns: [{ header: 'FIELD' }, { header: 'VALUE' }],
      rows
    })
  )
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
