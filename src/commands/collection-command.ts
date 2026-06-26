/**
 * Shared helpers for the wallet "collection" command families (`vc`, `key`,
 * and `zcap`), whose `list` / `show` / `meta` / `remove` subcommands and
 * metadata handling are otherwise near-identical clones. Each command file
 * declares its collection name and supplies the per-collection projection
 * (how to load an item, turn it into a table row / JSON object, and resolve a
 * reference); the control flow -- plain/json/empty/table listing, the
 * set-or-clear metadata edits, and the resolve-then-validate preamble -- lives
 * here once.
 */
import {
  listCollection,
  loadFromCollection,
  loadMetaFromCollection,
  removeFromCollection,
  saveMetaToCollection,
  type ItemMetadata,
  type KeyMetadata
} from '../storage.js'
import { renderTable, type Column } from '../table.js'

/**
 * Guards the `--handle` / `--description` metadata flags against being given
 * without `--save`. Prints the standard message to stderr and returns false
 * when the combination is invalid; the caller chooses the exit code.
 *
 * @param options {object}
 * @param [options.save] {boolean}
 * @param [options.handle] {string}
 * @param [options.description] {string}
 * @returns {boolean}   true when the flags are valid.
 */
export function requireSaveForMetaFlags({
  save,
  handle,
  description
}: {
  save?: boolean
  handle?: string
  description?: string
}): boolean {
  if ((handle !== undefined || description !== undefined) && !save) {
    console.error('--handle and --description require --save')
    return false
  }
  return true
}

/**
 * Apply the `--handle` / `--description` set-or-clear edits to a metadata
 * object in place: a defined non-empty value sets the field, an empty string
 * clears it, and an undefined value leaves it untouched.
 *
 * @param meta {ItemMetadata}   The metadata object to mutate.
 * @param edits {object}
 * @param [edits.handle] {string}
 * @param [edits.description] {string}
 * @returns {void}
 */
export function applyMetaEdits(
  meta: ItemMetadata,
  { handle, description }: { handle?: string; description?: string }
): void {
  if (handle !== undefined) {
    if (handle === '') {
      delete meta.handle
    } else {
      meta.handle = handle
    }
  }
  if (description !== undefined) {
    if (description === '') {
      delete meta.description
    } else {
      meta.description = description
    }
  }
}

/**
 * Write the `.meta.json` metadata sidecar of a freshly saved wallet item: the
 * creation timestamp plus the handle and description when given. When
 * `mergeExisting` is set, any existing sidecar is loaded first and its fields
 * take precedence over `created` (so re-saving an already-stored item keeps
 * its original timestamp) -- used by `vc import` / `vc issue --save`, which may
 * re-store a credential that is already in the wallet.
 *
 * @param options {object}
 * @param options.collection {string}
 * @param options.storageId {string}
 * @param options.created {string}
 * @param [options.handle] {string}
 * @param [options.description] {string}
 * @param [options.mergeExisting] {boolean}
 * @returns {Promise<void>}
 */
export async function writeCreateMeta({
  collection,
  storageId,
  created,
  handle,
  description,
  mergeExisting
}: {
  collection: string
  storageId: string
  created: string
  handle?: string
  description?: string
  mergeExisting?: boolean
}): Promise<void> {
  const existing = mergeExisting
    ? await loadMetaFromCollection({ collection, storageId })
    : undefined
  const meta: ItemMetadata = { created, ...existing }
  if (handle) {
    meta.handle = handle
  }
  if (description) {
    meta.description = description
  }
  await saveMetaToCollection({ collection, storageId, meta })
}

/**
 * Resolve a wallet item reference, reporting failures to stderr and returning
 * undefined: prints the thrown error message on an ambiguous handle, or the
 * standard "No locally stored <noun> found for <ref>" message when nothing
 * matches. Collapses the resolve-then-validate preamble shared by the
 * `show` / `meta` / `remove` subcommands; callers do `if (!resolved) return 1`.
 *
 * @param options {object}
 * @param options.resolve {(ref: string) => Promise<T | undefined>}
 * @param options.ref {string}
 * @param options.noun {string}   The item noun for the not-found message.
 * @returns {Promise<T | undefined>}
 */
export async function resolveRefOrReport<T>({
  resolve,
  ref,
  noun
}: {
  resolve: (ref: string) => Promise<T | undefined>
  ref: string
  noun: string
}): Promise<T | undefined> {
  let resolved: T | undefined
  try {
    resolved = await resolve(ref)
  } catch (err) {
    console.error((err as Error).message)
    return undefined
  }
  if (!resolved) {
    console.error(`No locally stored ${noun} found for ${ref}`)
    return undefined
  }
  return resolved
}

/**
 * Render a wallet collection listing: one id per line with `plain`, a JSON
 * array with `json`, an empty result as no output, otherwise a column-aligned
 * table. Shared by `vc list`, `key list`, and `zcap list`; each caller
 * supplies how to load an item, project it to a row / JSON object, and the
 * table columns. A `toEntry` returning undefined drops the item from the
 * non-plain output (e.g. an id-less zcap).
 *
 * @param options {object}
 * @param options.collection {string}
 * @param [options.plain] {boolean}
 * @param [options.json] {boolean}
 * @param options.plainId {(item: Item, storageId: string) => string | undefined}
 *   The id to print in `--plain` mode; undefined skips the item.
 * @param options.toEntry {(args: {storageId: string, item: Item, meta?: KeyMetadata}) => Entry | undefined | Promise<Entry | undefined>}
 * @param options.toJson {(entry: Entry) => object}
 * @param options.columns {Column[]}
 * @param options.toRow {(entry: Entry) => string[]}
 * @returns {Promise<number>}   The process exit code.
 */
export async function runListCollection<Item, Entry>({
  collection,
  plain,
  json,
  plainId,
  toEntry,
  toJson,
  columns,
  toRow
}: {
  collection: string
  plain?: boolean
  json?: boolean
  plainId: (item: Item, storageId: string) => string | undefined
  toEntry: (args: {
    storageId: string
    item: Item
    meta?: KeyMetadata
  }) => Entry | undefined | Promise<Entry | undefined>
  toJson: (entry: Entry) => object
  columns: Column[]
  toRow: (entry: Entry) => string[]
}): Promise<number> {
  const storageIds = await listCollection(collection)
  if (plain) {
    const ids: string[] = []
    for (const storageId of storageIds) {
      const item = await loadFromCollection<Item>({ collection, storageId })
      const id = plainId(item, storageId)
      if (id !== undefined) {
        ids.push(id)
      }
    }
    ids.sort()
    for (const id of ids) {
      console.log(id)
    }
    return 0
  }

  const entries: Entry[] = []
  for (const storageId of storageIds) {
    const item = await loadFromCollection<Item>({ collection, storageId })
    const meta = await loadMetaFromCollection<KeyMetadata>({
      collection,
      storageId
    })
    const entry = await toEntry({ storageId, item, meta })
    if (entry !== undefined) {
      entries.push(entry)
    }
  }

  if (json) {
    console.log(JSON.stringify(entries.map(toJson), null, 2))
    return 0
  }

  if (entries.length === 0) {
    return 0
  }
  console.log(renderTable({ columns, rows: entries.map(toRow) }))
  return 0
}

/**
 * Show or edit the metadata of a wallet item (by id or handle): with no
 * `--handle` / `--description` edits, prints the current metadata; otherwise
 * applies the set-or-clear edits, saves the sidecar, and prints the result.
 * Shared by `vc meta` and `zcap meta`. (`key meta` keeps its own runner: it
 * additionally backfills the created date and refreshes the cached DID
 * associations.)
 *
 * @param options {object}
 * @param options.collection {string}
 * @param options.noun {string}
 * @param options.resolve {(ref: string) => Promise<{storageId: string, meta?: ItemMetadata} | undefined>}
 * @param options.ref {string}
 * @param [options.handle] {string}
 * @param [options.description] {string}
 * @returns {Promise<number>}   The process exit code.
 */
export async function runMetaCollection({
  collection,
  noun,
  resolve,
  ref,
  handle,
  description
}: {
  collection: string
  noun: string
  resolve: (
    ref: string
  ) => Promise<{ storageId: string; meta?: ItemMetadata } | undefined>
  ref: string
  handle?: string
  description?: string
}): Promise<number> {
  const resolved = await resolveRefOrReport({ resolve, ref, noun })
  if (!resolved) {
    return 1
  }

  const hasEdits = handle !== undefined || description !== undefined
  if (!hasEdits) {
    console.log(JSON.stringify(resolved.meta ?? {}, null, 2))
    return 0
  }

  const meta: ItemMetadata = { ...(resolved.meta ?? {}) }
  applyMetaEdits(meta, { handle, description })
  const filePath = await saveMetaToCollection({
    collection,
    storageId: resolved.storageId,
    meta
  })
  console.error(`Metadata saved to ${filePath}`)
  console.log(JSON.stringify(meta, null, 2))
  return 0
}

/**
 * Resolve a wallet item by reference and remove it (and its metadata sidecar),
 * printing each removed file path to stderr. Shared by `vc remove`,
 * `key remove`, and `zcap remove`.
 *
 * @param options {object}
 * @param options.collection {string}
 * @param options.noun {string}
 * @param options.resolve {(ref: string) => Promise<{storageId: string} | undefined>}
 * @param options.ref {string}
 * @returns {Promise<number>}   The process exit code.
 */
export async function runRemoveCollection({
  collection,
  noun,
  resolve,
  ref
}: {
  collection: string
  noun: string
  resolve: (ref: string) => Promise<{ storageId: string } | undefined>
  ref: string
}): Promise<number> {
  const resolved = await resolveRefOrReport({ resolve, ref, noun })
  if (!resolved) {
    return 1
  }
  const removed = await removeFromCollection({
    collection,
    storageId: resolved.storageId
  })
  for (const filePath of removed) {
    console.error(`Removed ${filePath}`)
  }
  return 0
}
