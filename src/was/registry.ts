/**
 * Local space registry: records of WAS spaces the user works with, stored in
 * the `was-spaces` wallet collection (`~/.config/did-cli-wallet/was-spaces/`). Each entry
 * carries the space id, its display name, the server base URL, and the
 * controller DID, with the usual `.meta.json` sidecar (created / handle /
 * description). The registry is what lets `was space list` work without the
 * (unimplemented) server-side List Spaces operation, and what supplies
 * server URL and signing DID defaults so commands can be as short as
 * `di was get home/credentials/vc-1`.
 */

import {
  listCollection,
  loadFromCollection,
  loadMetaFromCollection,
  removeFromCollection,
  saveMetaToCollection,
  saveToCollection,
  sanitizeStorageId,
  type ItemMetadata
} from '../storage.js'

const COLLECTION = 'was-spaces'

/**
 * A registered space, as stored in a `was-spaces` item file.
 */
export interface SpaceRecord {
  /** The space id (server-generated uuid or urn). */
  id: string
  /** The space's display name. */
  name?: string
  /** The server base URL (origin). */
  server: string
  /** The controller DID, used as the default signing DID. */
  controller?: string
}

/**
 * Saves (or overwrites) a space registry entry and its metadata sidecar.
 * The `created` timestamp of an existing sidecar is preserved; `handle` and
 * `description` overwrite only when given, and an empty string clears the
 * field.
 *
 * @param options {object}
 * @param options.record {SpaceRecord}
 * @param [options.handle] {string}
 * @param [options.description] {string}
 * @returns {Promise<string>}   The saved item file path.
 */
export async function saveSpaceRecord({
  record,
  handle,
  description
}: {
  record: SpaceRecord
  handle?: string
  description?: string
}): Promise<string> {
  const storageId = sanitizeStorageId(record.id)
  const filePath = await saveToCollection({
    collection: COLLECTION,
    storageId,
    data: record
  })
  const existing = await loadMetaFromCollection({
    collection: COLLECTION,
    storageId
  })
  const meta: ItemMetadata = {
    ...existing,
    created: existing?.created ?? new Date().toISOString()
  }
  if (handle !== undefined) {
    if (handle) {
      meta.handle = handle
    } else {
      delete meta.handle
    }
  }
  if (description !== undefined) {
    if (description) {
      meta.description = description
    } else {
      delete meta.description
    }
  }
  await saveMetaToCollection({ collection: COLLECTION, storageId, meta })
  return filePath
}

/**
 * Lists all registered spaces with their metadata sidecars.
 *
 * @returns {Promise<{storageId: string, record: SpaceRecord, meta?: ItemMetadata}[]>}
 */
export async function listSpaceRecords(): Promise<
  { storageId: string; record: SpaceRecord; meta?: ItemMetadata }[]
> {
  const storageIds = await listCollection(COLLECTION)
  const entries: {
    storageId: string
    record: SpaceRecord
    meta?: ItemMetadata
  }[] = []
  for (const storageId of storageIds) {
    const record = await loadFromCollection<SpaceRecord>({
      collection: COLLECTION,
      storageId
    })
    const meta = await loadMetaFromCollection({
      collection: COLLECTION,
      storageId
    })
    entries.push({ storageId, record, meta })
  }
  return entries
}

/**
 * Resolve a user-supplied space reference -- a space id or a metadata handle
 * -- to a registered space. Space id matches take precedence; otherwise the
 * metadata sidecars are searched for a matching handle. Throws when a handle
 * matches more than one space (handles are not unique). Returns undefined
 * when nothing matches.
 *
 * @param options {object}
 * @param options.ref {string}
 * @returns {Promise<{storageId: string, record: SpaceRecord, meta?: ItemMetadata} | undefined>}
 */
export async function resolveSpaceRef({ ref }: { ref: string }): Promise<
  | {
      storageId: string
      record: SpaceRecord
      meta?: ItemMetadata
    }
  | undefined
> {
  const entries = await listSpaceRecords()
  const byId = entries.find(entry => entry.record.id === ref)
  if (byId) {
    return byId
  }
  const matches = entries.filter(entry => entry.meta?.handle === ref)
  if (matches.length === 0) {
    return undefined
  }
  if (matches.length > 1) {
    throw new Error(
      `Handle "${ref}" matches ${matches.length} spaces; ` +
        'use the space id instead.'
    )
  }
  return matches[0]
}

/**
 * Removes a space registry entry (the item file plus its metadata sidecar).
 *
 * @param options {object}
 * @param options.storageId {string}
 * @returns {Promise<string[]>}   The file paths that were deleted.
 */
export async function removeSpaceRecord({
  storageId
}: {
  storageId: string
}): Promise<string[]> {
  return removeFromCollection({ collection: COLLECTION, storageId })
}
