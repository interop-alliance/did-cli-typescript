/**
 * Loads the `capabilityDelegation` signer used to sign delegated capabilities,
 * paired with the signature suite class that matches the key's type.
 *
 * Two key-sourcing modes are supported, mirroring the rest of the CLI and the
 * legacy did-cli respectively:
 *
 * - Stored DID (`--did`): the DID document and its secret key are read from
 *   local storage (`~/.config/did-cli-wallet/dids/`, the store written by
 *   `did create --save`), exactly as `vc issue` loads its signing key. The
 *   DID document's `capabilityDelegation` relationship names the key, which is
 *   then picked out of the keys file (a single key pair for did:key, a map
 *   keyed by verification-method id for did:web, did:webvh and did:peer). The
 *   stored key's type selects the suite: an ecdsa key signs with
 *   `ecdsa-jcs-2019`, an ed25519 key with `Ed25519Signature2020`.
 * - Env seed (`ZCAP_CONTROLLER_KEY_SEED` + `--controller`): the `did:key` is
 *   regenerated from the seed, its id is checked against `--controller`, and the
 *   `capabilityDelegation` key is used to sign.
 */
import { decodeSecretKeySeed } from '@digitalcredentials/bnid'
import { driver } from '@interop/did-method-key'
import { EcdsaJcs2019 } from '@interop/ecdsa-signature'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'
import { createSigner, Ed25519Signature2020 } from '@interop/ed25519-signature'
import type { IDidDocument, ISigner } from '@interop/data-integrity-core'
import type { SignatureSuiteClass } from '@interop/data-integrity-proof'
import {
  keyIdForPurpose,
  loadStoredSigner,
  type KeyType
} from '../keys/stored-key.js'
import { loadDidDocument } from '../storage.js'

/**
 * The suite class `ZcapClient` signs a delegation with, per stored key type.
 */
const SUITE_CLASS: Record<KeyType, SignatureSuiteClass> = {
  ed25519: Ed25519Signature2020,
  ecdsa: EcdsaJcs2019
}

/**
 * Loads the delegation signer for `zcap delegate`.
 *
 * When `did` is given, the signer is loaded from the locally-stored DID and its
 * secret key file, and the suite class follows the key's type. Otherwise the
 * `ZCAP_CONTROLLER_KEY_SEED` environment variable is required and the `did:key`
 * is regenerated from it, with `controller` used to verify the regenerated DID
 * matches the caller's expectation.
 *
 * @param options {object}
 * @param [options.did] {string}   The id of a locally-stored DID to sign with.
 * @param [options.controller] {string}   The expected controller DID, required
 *   (and verified) when signing via `ZCAP_CONTROLLER_KEY_SEED`.
 * @returns {Promise<{signer: ISigner, SuiteClass: SignatureSuiteClass}>}   The
 *   `capabilityDelegation` signer and its suite class.
 */
export async function loadDelegationSigner({
  did,
  controller
}: {
  did?: string
  controller?: string
}): Promise<{ signer: ISigner; SuiteClass: SignatureSuiteClass }> {
  if (did) {
    const didDocument = await loadDidDocument<IDidDocument>(did)
    const keyId = keyIdForPurpose({
      didDocument,
      purpose: 'capabilityDelegation'
    })
    const { signer, keyType } = await loadStoredSigner({ did, keyId })
    return { signer, SuiteClass: SUITE_CLASS[keyType] }
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
  const delegationKey = methodFor({ purpose: 'capabilityDelegation' })
  return {
    signer: createSigner(delegationKey),
    SuiteClass: SUITE_CLASS.ed25519
  }
}
