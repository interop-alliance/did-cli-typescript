/**
 * HMAC key (`SHA256HMACKey`) resolution for EDV index blinding. The
 * concrete key implementation -- the reference `IHMAC` impl -- lives in
 * `@interop/data-integrity-core`; this module only adapts it to the CLI's
 * wallet storage: it finds the blinding key the `edv encrypt --index` flow
 * should use (by id, handle, or storage id, or by auto-selecting the lone HMAC
 * key) and reconstructs it from its persisted JWK secret.
 */
import {
  SHA256HMACKey,
  type ISHA256HMACKey
} from '@interop/data-integrity-core'
import {
  listCollection,
  loadFromCollection,
  loadMetaFromCollection
} from '../storage.js'

/** The stored `type` value of an HMAC blinding key (the EDV protocol string). */
export const HMAC_KEY_TYPE = 'Sha256HmacKey2019'

/** A stored HMAC key paired with its storage id (for handle/id matching). */
interface StoredHmac {
  storageId: string
  stored: ISHA256HMACKey
}

/**
 * Collect every `SHA256HMACKey` stored in the wallet keys collection.
 *
 * @returns {Promise<StoredHmac[]>}
 */
async function listStoredHmacs(): Promise<StoredHmac[]> {
  const storageIds = await listCollection('keys')
  const stored = await Promise.all(
    storageIds.map(storageId =>
      loadFromCollection<ISHA256HMACKey>('keys', storageId)
    )
  )
  return storageIds
    .map((storageId, index) => ({ storageId, stored: stored[index] }))
    .filter(({ stored }) => stored.type === HMAC_KEY_TYPE)
}

/**
 * Resolve the HMAC blinding key for index operations. With `ref`, match a
 * stored HMAC key by its id, its storage id, or its metadata handle; without
 * `ref`, auto-select when the wallet holds exactly one HMAC key. Throws with a
 * clear message when nothing matches, the handle/ref is ambiguous, or no HMAC
 * key exists yet.
 *
 * @param options {object}
 * @param [options.ref] {string}   The `--hmac` value; auto-select when omitted.
 * @returns {Promise<SHA256HMACKey>}
 */
export async function resolveHmac({
  ref
}: {
  ref?: string
}): Promise<SHA256HMACKey> {
  const candidates = await listStoredHmacs()
  if (candidates.length === 0) {
    throw new Error(
      'No HMAC key found in the wallet; create one with ' +
        '`di key create --type hmac --save`.'
    )
  }

  if (ref === undefined) {
    if (candidates.length > 1) {
      throw new Error(
        `The wallet has ${candidates.length} HMAC keys; ` +
          'pass --hmac to choose one.'
      )
    }
    return SHA256HMACKey.from(candidates[0].stored)
  }

  const direct = candidates.find(
    candidate => candidate.stored.id === ref || candidate.storageId === ref
  )
  if (direct) {
    return SHA256HMACKey.from(direct.stored)
  }

  const metas = await Promise.all(
    candidates.map(candidate =>
      loadMetaFromCollection({
        collection: 'keys',
        storageId: candidate.storageId
      })
    )
  )
  const byHandle = candidates.filter(
    (_candidate, index) => metas[index]?.handle === ref
  )
  if (byHandle.length === 0) {
    throw new Error(`No HMAC key found for "${ref}".`)
  }
  if (byHandle.length > 1) {
    throw new Error(
      `Handle "${ref}" matches ${byHandle.length} HMAC keys; ` +
        'use the key id instead.'
    )
  }
  return SHA256HMACKey.from(byHandle[0].stored)
}
