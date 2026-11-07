/**
 * Shared helpers over a stored DID's `<did>.keys.json` file: how to name the
 * key a DID document authorizes for a purpose, and how to turn the stored key
 * pair into a signer. Both the `vc issue` and `zcap delegate` signing paths go
 * through here, so the stored-key to key-class mapping lives in one place.
 */
import { driver } from '@interop/did-method-key'
import * as EcdsaMultikey from '@interop/ecdsa-multikey'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'
import { createSigner } from '@interop/ed25519-signature'
import type { IDidDocument, ISigner } from '@interop/data-integrity-core'
import { isEcdsaPublicKeyMultibase } from './ecdsa.js'
import {
  loadDidKeys,
  selectStoredKey,
  type StoredKeyPair,
  type StoredKeys
} from '../storage.js'

/**
 * The signing key types the CLI stores: ed25519 and ecdsa keys both export as
 * `type: "Multikey"` and are told apart by their multibase header.
 */
export type KeyType = 'ed25519' | 'ecdsa'

/**
 * Returns the id of the verification method a DID document names for
 * `purpose` (`assertionMethod`, `capabilityDelegation`, ...): the first entry
 * of that relationship, with a key reference resolved against the document.
 *
 * @param options {object}
 * @param options.didDocument {IDidDocument}
 * @param options.purpose {string}   The verification relationship.
 * @returns {string}   The verification method id.
 */
export function keyIdForPurpose({
  didDocument,
  purpose
}: {
  didDocument: IDidDocument
  purpose: string
}): string {
  const { id } = driver().publicMethodFor({ didDocument, purpose })
  if (!id) {
    throw new Error(
      `The ${purpose} key of DID ${didDocument.id} has no verification method id`
    )
  }
  return id
}

/**
 * Loads the stored secret key `keyId` of a locally-stored DID and derives a
 * signer from it. The key type is returned alongside so the caller can pick
 * the matching signature suite.
 *
 * @param options {object}
 * @param options.did {string}   The id of the stored DID.
 * @param options.keyId {string}   The verification method id to sign with.
 * @returns {Promise<{signer: ISigner, keyType: KeyType}>}
 */
export async function loadStoredSigner({
  did,
  keyId
}: {
  did: string
  keyId: string
}): Promise<{ signer: ISigner; keyType: KeyType }> {
  const keysData = await loadDidKeys<StoredKeys>(did)
  const storedKey = selectStoredKey({ keysData, keyId })
  if (!storedKey) {
    throw new Error(
      `No stored secret key found for key id ${keyId} in DID ${did}`
    )
  }
  return signerForStoredKey({ storedKey })
}

/**
 * Imports a stored key pair with the key class its type calls for and derives
 * a signer from it. Both ed25519 and ecdsa keys export with
 * `type: "Multikey"`, so the multibase prefix is what tells them apart: ecdsa
 * P-256/P-384/P-521 keys carry the ecdsa-multikey headers, and everything else
 * is treated as ed25519.
 *
 * @param options {object}
 * @param options.storedKey {StoredKeyPair}   The exported key pair, secret
 *   half included.
 * @returns {Promise<{signer: ISigner, keyType: KeyType}>}
 */
async function signerForStoredKey({
  storedKey
}: {
  storedKey: StoredKeyPair
}): Promise<{ signer: ISigner; keyType: KeyType }> {
  if (
    isEcdsaPublicKeyMultibase({
      publicKeyMultibase: storedKey.publicKeyMultibase
    })
  ) {
    const keyPair = await EcdsaMultikey.from(storedKey)
    return { signer: keyPair.signer(), keyType: 'ecdsa' }
  }
  const keyPair = await Ed25519VerificationKey.from(storedKey)
  return { signer: createSigner(keyPair), keyType: 'ed25519' }
}
