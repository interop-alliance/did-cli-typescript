import { mkdir, readFile, readdir, unlink, writeFile } from 'node:fs/promises'
import { homedir } from 'node:os'
import { join } from 'node:path'

function getWalletDir(): string {
  if (process.env.WALLET_DIR) {
    return process.env.WALLET_DIR
  }
  const configHome = process.env.XDG_CONFIG_HOME ?? join(homedir(), '.config')
  return join(configHome, 'did-cli-wallet')
}

/**
 * Derives a filesystem-safe storage id from an item identifier (a
 * capability urn, a space id, etc.), replacing characters that are awkward
 * in file names.
 *
 * @param id {string}
 * @returns {string}
 */
export function sanitizeStorageId(id: string): string {
  return id.replaceAll(':', '_').replaceAll('%', '_').replaceAll('/', '_')
}

/**
 * User-editable metadata stored in a `.meta.json` sidecar next to a wallet
 * item or DID document. All fields are optional; a missing sidecar simply
 * means "no metadata".
 */
export interface ItemMetadata {
  /** ISO 8601 timestamp recorded when the item was saved. */
  created?: string
  /** Short user-defined tag for telling items apart. */
  handle?: string
  /** Longer free-text description. */
  description?: string
}

/**
 * Metadata for a stored key. `dids` caches the DIDs whose documents reference
 * the key; the displayed value is always re-derived from the stored DID
 * documents, so this cache may lag without harm.
 */
export interface KeyMetadata extends ItemMetadata {
  dids?: string[]
}

/**
 * List the storage IDs of all items saved in a wallet collection.
 *
 * The storage ID of an item is its file name without the `.json` extension --
 * an internal addressing detail used to load the item back from storage.
 * `.meta.json` metadata sidecars are not items and are excluded. Returns
 * an empty array if the collection has no directory yet.
 *
 * @param collection {string}
 * @returns {Promise<string[]>}
 */
export async function listCollection(collection: string): Promise<string[]> {
  const dir = join(getWalletDir(), collection)
  let fileNames: string[]
  try {
    fileNames = await readdir(dir)
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
      return []
    }
    throw err
  }
  return fileNames
    .filter(name => name.endsWith('.json') && !name.endsWith('.meta.json'))
    .map(name => name.slice(0, -'.json'.length))
    .sort()
}

/**
 * Load and JSON-parse a single item from a wallet collection.
 *
 * @param collection {string}
 * @param storageId {string}
 * @returns {Promise<T>}
 */
export async function loadFromCollection<T = unknown>(
  collection: string,
  storageId: string
): Promise<T> {
  const filePath = join(getWalletDir(), collection, `${storageId}.json`)
  return JSON.parse(await readFile(filePath, 'utf8')) as T
}

export async function saveToCollection(
  collection: string,
  storageId: string,
  data: object
): Promise<string> {
  const dir = join(getWalletDir(), collection)
  await mkdir(dir, { recursive: true })
  const filePath = join(dir, `${storageId}.json`)
  await writeFile(filePath, JSON.stringify(data, null, 2), 'utf8')
  return filePath
}

/**
 * Load the `.meta.json` metadata sidecar of a wallet collection item.
 *
 * @param options {object}
 * @param options.collection {string}
 * @param options.storageId {string}
 * @returns {Promise<KeyMetadata | undefined>} undefined when no sidecar exists.
 */
export async function loadMetaFromCollection({
  collection,
  storageId
}: {
  collection: string
  storageId: string
}): Promise<KeyMetadata | undefined> {
  const filePath = join(getWalletDir(), collection, `${storageId}.meta.json`)
  try {
    return JSON.parse(await readFile(filePath, 'utf8')) as KeyMetadata
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
      return undefined
    }
    throw err
  }
}

/**
 * Save the `.meta.json` metadata sidecar of a wallet collection item.
 *
 * @param options {object}
 * @param options.collection {string}
 * @param options.storageId {string}
 * @param options.meta {KeyMetadata}
 * @returns {Promise<string>} the sidecar file path.
 */
export async function saveMetaToCollection({
  collection,
  storageId,
  meta
}: {
  collection: string
  storageId: string
  meta: KeyMetadata
}): Promise<string> {
  const dir = join(getWalletDir(), collection)
  await mkdir(dir, { recursive: true })
  const filePath = join(dir, `${storageId}.meta.json`)
  await writeFile(filePath, JSON.stringify(meta, null, 2), 'utf8')
  return filePath
}

/**
 * Delete a file, ignoring the case where it does not exist.
 *
 * @param filePath {string}
 * @returns {Promise<boolean>} true when the file existed and was deleted.
 */
async function unlinkIfExists(filePath: string): Promise<boolean> {
  try {
    await unlink(filePath)
    return true
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
      return false
    }
    throw err
  }
}

/**
 * Remove an item from a wallet collection: the item file itself plus its
 * `.meta.json` metadata sidecar (when one exists).
 *
 * @param options {object}
 * @param options.collection {string}
 * @param options.storageId {string}
 * @returns {Promise<string[]>} the file paths that were deleted.
 */
export async function removeFromCollection({
  collection,
  storageId
}: {
  collection: string
  storageId: string
}): Promise<string[]> {
  const dir = join(getWalletDir(), collection)
  const removed: string[] = []
  const filePath = join(dir, `${storageId}.json`)
  await unlink(filePath)
  removed.push(filePath)
  const metaPath = join(dir, `${storageId}.meta.json`)
  if (await unlinkIfExists(metaPath)) {
    removed.push(metaPath)
  }
  return removed
}

/**
 * Find a stored wallet key by its publicKeyMultibase fingerprint or its key id.
 *
 * Neither identifier is the file name (storage IDs carry a date/type prefix and
 * may encode a full verification method id), so the lookup scans every key file
 * in the collection. Matching by `id` lets symmetric keys with no public
 * fingerprint (e.g. an HMAC key) be resolved.
 *
 * @param options {object}
 * @param options.fingerprint {string}
 * @returns {Promise<{storageId: string, key: object} | undefined>}
 */
export async function findStoredKey({
  fingerprint
}: {
  fingerprint: string
}): Promise<
  | {
      storageId: string
      key: {
        id?: string
        publicKeyMultibase?: string
        secretKeyMultibase?: string
      }
    }
  | undefined
> {
  const storageIds = await listCollection('keys')
  for (const storageId of storageIds) {
    const key = await loadFromCollection<{
      id?: string
      publicKeyMultibase?: string
      secretKeyMultibase?: string
    }>('keys', storageId)
    if (key.publicKeyMultibase === fingerprint || key.id === fingerprint) {
      return { storageId, key }
    }
  }
  return undefined
}

function getDidsDir(): string {
  return process.env.DIDS_DIR ?? join(getWalletDir(), 'dids')
}

/**
 * Extract the method name from a DID -- the segment between the first two
 * colons (`did:web:example.com` -> `web`). Used to pick the per-method storage
 * subdirectory and to label DIDs in listings.
 *
 * @param did {string}
 * @returns {string}
 */
export function methodOf(did: string): string {
  return did.split(':')[1]
}

/**
 * List the DIDs saved in local storage, across all method subdirectories.
 *
 * Each saved DID is stored as `<did>.json` (the DID document) alongside a
 * `<did>.keys.json` key file and an optional `<did>.meta.json` metadata
 * sidecar; only the first is reported, and the DID is its file name without
 * the `.json` extension. Returns an empty array if no DIDs have been saved
 * yet.
 *
 * @returns {Promise<string[]>}
 */
export async function listDids(): Promise<string[]> {
  const baseDir = getDidsDir()
  let methodEntries
  try {
    methodEntries = await readdir(baseDir, { withFileTypes: true })
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
      return []
    }
    throw err
  }
  const dids: string[] = []
  for (const methodEntry of methodEntries) {
    if (!methodEntry.isDirectory()) {
      continue
    }
    const fileNames = await readdir(join(baseDir, methodEntry.name))
    for (const fileName of fileNames) {
      if (
        !fileName.endsWith('.json') ||
        fileName.endsWith('.keys.json') ||
        fileName.endsWith('.update-keys.json') ||
        fileName.endsWith('.meta.json')
      ) {
        continue
      }
      dids.push(fileName.slice(0, -'.json'.length))
    }
  }
  return dids.sort()
}

/**
 * Load and JSON-parse the DID document saved for a DID.
 *
 * Reads `<did>.json` from the method subdirectory of the DIDs storage dir, where
 * the method is derived from the DID (e.g. `did:key:...` lives under `key/`).
 *
 * @param did {string}
 * @returns {Promise<T>}
 */
export async function loadDidDocument<T = unknown>(did: string): Promise<T> {
  const method = methodOf(did)
  const filePath = join(getDidsDir(), method, `${did}.json`)
  return JSON.parse(await readFile(filePath, 'utf8')) as T
}

/**
 * Load and JSON-parse the exported key pair saved alongside a DID document.
 *
 * Reads the `<did>.keys.json` key file written by `saveToDids` with the `keys`
 * suffix; it carries the DID's signing key material (including the secret key).
 *
 * @param did {string}
 * @returns {Promise<T>}
 */
export async function loadDidKeys<T = unknown>(did: string): Promise<T> {
  const method = methodOf(did)
  const filePath = join(getDidsDir(), method, `${did}.keys.json`)
  return JSON.parse(await readFile(filePath, 'utf8')) as T
}

/**
 * Load the `<did>.meta.json` metadata sidecar saved alongside a DID document.
 *
 * @param options {object}
 * @param options.did {string}
 * @returns {Promise<ItemMetadata | undefined>} undefined when no sidecar exists.
 */
export async function loadDidMeta({
  did
}: {
  did: string
}): Promise<ItemMetadata | undefined> {
  const method = methodOf(did)
  const filePath = join(getDidsDir(), method, `${did}.meta.json`)
  try {
    return JSON.parse(await readFile(filePath, 'utf8')) as ItemMetadata
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
      return undefined
    }
    throw err
  }
}

/**
 * Save the `<did>.meta.json` metadata sidecar alongside a DID document.
 *
 * @param options {object}
 * @param options.did {string}
 * @param options.meta {ItemMetadata}
 * @returns {Promise<string>} the sidecar file path.
 */
export async function saveDidMeta({
  did,
  meta
}: {
  did: string
  meta: ItemMetadata
}): Promise<string> {
  const method = methodOf(did)
  return saveToDids({ method, did, suffix: 'meta', data: meta })
}

/**
 * Remove a DID from local storage: the `<did>.json` DID document plus its
 * `<did>.keys.json` key file and `<did>.meta.json` metadata sidecar (when
 * they exist).
 *
 * @param options {object}
 * @param options.did {string}
 * @returns {Promise<string[]>} the file paths that were deleted.
 */
export async function removeDidFiles({
  did
}: {
  did: string
}): Promise<string[]> {
  const method = methodOf(did)
  const dir = join(getDidsDir(), method)
  const removed: string[] = []
  const docPath = join(dir, `${did}.json`)
  await unlink(docPath)
  removed.push(docPath)
  for (const suffix of ['keys', 'update-keys', 'meta']) {
    const sidecarPath = join(dir, `${did}.${suffix}.json`)
    if (await unlinkIfExists(sidecarPath)) {
      removed.push(sidecarPath)
    }
  }
  // did:webvh additionally stores a `.jsonl` history log; only that method has
  // one, so unlink it conditionally.
  const logPath = join(dir, `${did}.jsonl`)
  if (await unlinkIfExists(logPath)) {
    removed.push(logPath)
  }
  return removed
}

/**
 * Save a did:webvh history log as a raw newline-delimited JSON (`.jsonl`) file
 * alongside the DID document, under the method subdirectory.
 *
 * Unlike `saveToDids`, the log is written as raw text -- each entry serialized
 * on its own line with a trailing newline -- not as a pretty-printed JSON
 * object, so it round-trips as a valid `did.jsonl`.
 *
 * @param options {object}
 * @param options.did {string}
 * @param options.log {object[]} the array of signed log entries.
 * @returns {Promise<string>} the log file path.
 */
export async function saveDidLog({
  did,
  log
}: {
  did: string
  log: object[]
}): Promise<string> {
  const method = methodOf(did)
  const dir = join(getDidsDir(), method)
  await mkdir(dir, { recursive: true })
  const filePath = join(dir, `${did}.jsonl`)
  const serialized = log.map(entry => JSON.stringify(entry)).join('\n') + '\n'
  await writeFile(filePath, serialized, 'utf8')
  return filePath
}

/**
 * Load the raw did:webvh history log (`.jsonl`) saved for a DID.
 *
 * Returns the file's raw text (newline-delimited JSON), suitable for feeding to
 * `resolveDIDFromLog` after splitting on newlines.
 *
 * @param did {string}
 * @returns {Promise<string>}
 */
export async function loadDidLog(did: string): Promise<string> {
  const method = methodOf(did)
  const filePath = join(getDidsDir(), method, `${did}.jsonl`)
  return readFile(filePath, 'utf8')
}

/**
 * A did:webvh update (authorization) key pair. Update keys authorize new log
 * entries and are deliberately kept separate from the document's
 * verification-method keys (`<did>.keys.json`). `secretKeyMultibase` is absent
 * only for an externally-held key supplied by public value alone.
 */
export interface WebvhUpdateKey {
  publicKeyMultibase: string
  secretKeyMultibase?: string
}

/**
 * The update-key state of a did:webvh DID, persisted in the
 * `<did>.update-keys.json` sidecar: the key authorized right now (`active`)
 * and, when pre-rotation is armed, the pre-committed next key (`staged`) whose
 * hash is published in the log's `nextKeyHashes`. `staged` is absent only when
 * pre-rotation is off. `retired` keeps superseded secrets when a rotation is
 * asked to preserve them (`rotate-keys --keep-old-key`); they are needed only
 * to verify historic entries, so the default is to drop them.
 */
export interface WebvhUpdateKeys {
  active: WebvhUpdateKey
  staged?: WebvhUpdateKey & { nextKeyHash: string }
  retired?: WebvhUpdateKey[]
}

/**
 * Save the `<did>.update-keys.json` sidecar holding a did:webvh DID's update
 * (authorization) keys, alongside its DID document under the method subdir.
 *
 * @param options {object}
 * @param options.did {string}
 * @param options.updateKeys {WebvhUpdateKeys}
 * @returns {Promise<string>} the sidecar file path.
 */
export async function saveDidUpdateKeys({
  did,
  updateKeys
}: {
  did: string
  updateKeys: WebvhUpdateKeys
}): Promise<string> {
  const method = methodOf(did)
  return saveToDids({ method, did, suffix: 'update-keys', data: updateKeys })
}

/**
 * Load the `<did>.update-keys.json` sidecar of a did:webvh DID. Throws (ENOENT)
 * when no sidecar exists -- e.g. a DID created before pre-rotation support.
 *
 * @param did {string}
 * @returns {Promise<WebvhUpdateKeys>}
 */
export async function loadDidUpdateKeys(did: string): Promise<WebvhUpdateKeys> {
  const method = methodOf(did)
  const filePath = join(getDidsDir(), method, `${did}.update-keys.json`)
  return JSON.parse(await readFile(filePath, 'utf8')) as WebvhUpdateKeys
}

/**
 * @param options {object}
 * @param options.method {string}
 * @param options.did {string}
 * @param options.suffix {string}
 * @param options.data {object}
 * @returns {Promise<string>}
 */
export async function saveToDids({
  method,
  did,
  suffix,
  data
}: {
  method: string
  did: string
  suffix?: string
  data: object
}): Promise<string> {
  const dir = join(getDidsDir(), method)
  await mkdir(dir, { recursive: true })
  const fileName = suffix ? `${did}.${suffix}.json` : `${did}.json`
  const filePath = join(dir, fileName)
  await writeFile(filePath, JSON.stringify(data, null, 2), 'utf8')
  return filePath
}
