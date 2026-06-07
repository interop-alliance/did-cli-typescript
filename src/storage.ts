import { mkdir, readFile, readdir, writeFile } from 'node:fs/promises'
import { homedir } from 'node:os'
import { join } from 'node:path'

function getWalletDir(): string {
  return process.env.WALLET_DIR ?? join(homedir(), '.wallet')
}

/**
 * List the storage IDs of all items saved in a wallet collection.
 *
 * The storage ID of an item is its file name without the `.json` extension --
 * an internal addressing detail used to load the item back from storage. Returns
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
    .filter(name => name.endsWith('.json'))
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

function getDidsDir(): string {
  return process.env.DIDS_DIR ?? join(homedir(), '.dids')
}

/**
 * List the DIDs saved in local storage, across all method subdirectories.
 *
 * Each saved DID is stored as `<did>.json` (the DID document) alongside a
 * `<did>.keys.json` key file; only the former is reported, and the DID is its
 * file name without the `.json` extension. Returns an empty array if no DIDs
 * have been saved yet.
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
      if (!fileName.endsWith('.json') || fileName.endsWith('.keys.json')) {
        continue
      }
      dids.push(fileName.slice(0, -'.json'.length))
    }
  }
  return dids.sort()
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
