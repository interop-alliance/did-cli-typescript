/**
 * Loads the `capabilityDelegation` signer used to sign delegated capabilities.
 *
 * Two key-sourcing modes are supported, mirroring the rest of the CLI and the
 * legacy did-cli respectively:
 *
 * - Stored DID (`--did`): the DID document and its secret key are read from
 *   local storage (`~/.wallet/dids/`, the store written by `id create --save`),
 *   exactly as `vc issue` loads its signing key. For `did:key` the single key
 *   serves the `capabilityDelegation` relationship.
 * - Env seed (`ZCAP_CONTROLLER_KEY_SEED` + `--controller`): the `did:key` is
 *   regenerated from the seed, its id is checked against `--controller`, and the
 *   `capabilityDelegation` key is used to sign.
 */
import { decodeSecretKeySeed } from '@digitalcredentials/bnid'
import { driver } from '@interop/did-method-key'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'
import { createSigner } from '@interop/ed25519-signature'
import type { ISigner } from '@interop/data-integrity-core'
import { loadDidDocument, loadDidKeys } from '../storage.js'

/**
 * The shape of the exported key pair saved in a `<did>.keys.json` file.
 */
interface StoredKeyPair {
  id: string
  controller?: string
  type?: string
  publicKeyMultibase?: string
  secretKeyMultibase?: string
}

/**
 * A key pair that can produce a signer, as returned by `methodFor`.
 */
interface SignableKeyPair {
  signer(): ISigner
}

/**
 * Loads the delegation signer for `zcap delegate`.
 *
 * When `did` is given, the signer is loaded from the locally-stored DID and its
 * secret key file. Otherwise the `ZCAP_CONTROLLER_KEY_SEED` environment variable
 * is required and the `did:key` is regenerated from it, with `controller` used
 * to verify the regenerated DID matches the caller's expectation.
 *
 * @param options {object}
 * @param [options.did] {string}   The id of a locally-stored DID to sign with.
 * @param [options.controller] {string}   The expected controller DID, required
 *   (and verified) when signing via `ZCAP_CONTROLLER_KEY_SEED`.
 * @returns {Promise<ISigner>}   The `capabilityDelegation` signer.
 */
export async function loadDelegationSigner({
  did,
  controller
}: {
  did?: string
  controller?: string
}): Promise<ISigner> {
  if (did) {
    await loadDidDocument(did)
    const keysData = await loadDidKeys<StoredKeyPair>(did)
    const keyPair = await Ed25519VerificationKey.from(keysData)
    return createSigner(keyPair)
  }

  const secretKeySeed = process.env.ZCAP_CONTROLLER_KEY_SEED
  if (!secretKeySeed) {
    throw new Error(
      'Provide --did (a stored DID) or set ZCAP_CONTROLLER_KEY_SEED with ' +
        '--controller to sign the delegation.'
    )
  }
  if (!controller) {
    throw new Error(
      '--controller is required when signing via ZCAP_CONTROLLER_KEY_SEED.'
    )
  }
  const seedBytes = decodeSecretKeySeed({ secretKeySeed })
  const didDriver = driver()
  didDriver.use({ keyPairClass: Ed25519VerificationKey })
  const { didDocument, methodFor } = await didDriver.generate({
    seed: seedBytes
  })
  if (didDocument.id !== controller) {
    throw new Error(
      `The DID generated from ZCAP_CONTROLLER_KEY_SEED (${didDocument.id}) ` +
        `does not match --controller (${controller}).`
    )
  }
  const delegationKey = (
    methodFor as (options: { purpose: string }) => SignableKeyPair
  )({ purpose: 'capabilityDelegation' })
  return createSigner(delegationKey)
}
