import { mkdir, writeFile } from 'node:fs/promises'
import { homedir } from 'node:os'
import { join } from 'node:path'

function getWalletDir(): string {
  return process.env.WALLET_DIR ?? join(homedir(), '.wallet')
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
