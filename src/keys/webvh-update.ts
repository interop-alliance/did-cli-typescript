/**
 * Helpers for did:webvh update (authorization) keys and key pre-rotation.
 *
 * Update keys are decoupled from the document's verification-method keys: they
 * only authorize new log entries, and pre-rotation commits, in advance, to the
 * hash of the key allowed to perform the next update. These helpers generate
 * update keys, reconstruct them from their stored multibase secret, and derive
 * the `nextKeyHash` committed in a log entry's `nextKeyHashes`. The hash is the
 * one the library validates -- `deriveNextKeyHash(pub) =
 * base58btc(multihash_sha2_256(sha256(utf8Bytes(pub))))` -- imported from
 * `@interop/did-method-webvh` rather than re-implemented here.
 */
import { deriveNextKeyHash } from '@interop/did-method-webvh'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'
import type { WebvhUpdateKey } from '../storage.js'

/**
 * Reconstruct an update key pair from its stored `{ publicKeyMultibase,
 * secretKeyMultibase }` record, so it can sign a new log entry.
 *
 * @param key {WebvhUpdateKey} must carry a `secretKeyMultibase`.
 * @returns {Promise<Ed25519VerificationKey>}
 */
export async function loadUpdateKey(
  key: WebvhUpdateKey
): Promise<Ed25519VerificationKey> {
  if (!key.secretKeyMultibase) {
    throw new Error('Cannot load an update key without its secret key.')
  }
  // `Ed25519VerificationKey.from` only loads the secret half (making the key
  // able to sign) when the `Multikey` type is present, matching how the key is
  // exported; the stored record omits it, so it is supplied here.
  return Ed25519VerificationKey.from({
    type: 'Multikey',
    publicKeyMultibase: key.publicKeyMultibase,
    secretKeyMultibase: key.secretKeyMultibase
  })
}

/**
 * Export an update key pair to its persisted record.
 *
 * @param keyPair {Ed25519VerificationKey}
 * @returns {Promise<{ publicKeyMultibase: string, secretKeyMultibase: string }>}
 */
export async function exportUpdateKey(
  keyPair: Ed25519VerificationKey
): Promise<{ publicKeyMultibase: string; secretKeyMultibase: string }> {
  const { publicKeyMultibase, secretKeyMultibase } = await keyPair.export({
    publicKey: true,
    secretKey: true
  })
  return { publicKeyMultibase, secretKeyMultibase }
}

/**
 * Generate a fresh staged (pre-committed next) update key as the `staged` record
 * to persist -- its public and secret multibase together with the `nextKeyHash`
 * to commit in this entry's `nextKeyHashes`. The secret is carried in the record
 * (and reconstructed via `loadUpdateKey` at the next rotation), so the key pair
 * itself is not returned.
 *
 * @param [options] {object}
 * @param [options.seed] {Uint8Array}   derive the key deterministically from
 *   this seed (e.g. for `--with-seed`); generated randomly when omitted.
 * @returns {Promise<WebvhUpdateKey & { nextKeyHash: string }>}
 */
export async function generateStagedKey({
  seed
}: { seed?: Uint8Array } = {}): Promise<
  WebvhUpdateKey & { nextKeyHash: string }
> {
  const { publicKeyMultibase, secretKeyMultibase } = await exportUpdateKey(
    await Ed25519VerificationKey.generate({ seed })
  )
  const nextKeyHash = await deriveNextKeyHash(publicKeyMultibase)
  return { publicKeyMultibase, secretKeyMultibase, nextKeyHash }
}
