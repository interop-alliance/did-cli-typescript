import { mkdir, writeFile } from 'node:fs/promises'
import { homedir } from 'node:os'
import { join } from 'node:path'

function getWalletDir(): string {
  return process.env.WALLET_DIR ?? join(homedir(), '.wallet')
}

export async function saveToCollection(
  collection: string,
  storageId: string,
  data: object,
): Promise<string> {
  const dir = join(getWalletDir(), collection)
  await mkdir(dir, { recursive: true })
  const filePath = join(dir, `${storageId}.json`)
  await writeFile(filePath, JSON.stringify(data, null, 2), 'utf8')
  return filePath
}
