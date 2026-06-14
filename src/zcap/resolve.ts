/**
 * Capability reference resolution shared by the `was` commands and
 * `zcap delegate`: resolves a `--capability` value -- a multibase-encoded
 * capability string, a JSON file path, or the id/handle of a zcap stored in
 * `~/.config/did-cli-wallet/zcaps/` -- to the capability object it denotes.
 */
import { access, readFile } from 'node:fs/promises'
import type { IZcap } from '@interop/data-integrity-core/zcap'
import { resolveZcapRef } from '../meta.js'
import { decodeCapability } from './encoding.js'

/**
 * Returns true when the path exists on disk.
 *
 * @param filePath {string}
 * @returns {Promise<boolean>}
 */
async function fileExists(filePath: string): Promise<boolean> {
  try {
    await access(filePath)
    return true
  } catch {
    return false
  }
}

/**
 * Resolves a `--capability` reference to a capability object. A value
 * beginning with `z` is decoded as a multibase capability string; a path to
 * an existing file is parsed as capability JSON; anything else is looked up
 * in the local zcap store by capability id or metadata handle.
 *
 * @param options {object}
 * @param options.ref {string}
 * @returns {Promise<IZcap>}
 */
export async function resolveCapabilityInput({
  ref
}: {
  ref: string
}): Promise<IZcap> {
  if (ref.startsWith('z')) {
    return decodeCapability(ref)
  }
  if (await fileExists(ref)) {
    try {
      return JSON.parse(await readFile(ref, 'utf8')) as IZcap
    } catch (err) {
      throw new Error(
        `${ref} does not contain capability JSON: ` +
          `${err instanceof Error ? err.message : String(err)}`,
        { cause: err }
      )
    }
  }
  const stored = await resolveZcapRef({ ref })
  if (!stored) {
    throw new Error(
      `No capability found for "${ref}" (not an encoded string, a file, ` +
        'or a stored zcap id/handle).'
    )
  }
  return stored.zcap as IZcap
}
