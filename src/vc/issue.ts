/**
 * Credential issuance (signing) adapter over @interop/vc.
 *
 * `issueCredential` loads a locally-stored DID and one of its assertionMethod
 * keys, builds a signature suite, and hands an unsigned credential to
 * @interop/vc's `issue()`, which returns the credential with a proof attached.
 * If the input already carries a proof, `issue()` appends an additional one.
 * The credential's `issuer` is set to the signing DID when absent, and must
 * match the signing DID when present (otherwise issuance is aborted) -- a
 * credential cannot be issued by a DID other than the one named as its issuer.
 * The signing key is read from the DID's `<did>.keys.json` file (the secret key
 * store written by `did create --save`). A did:peer DID may be given by either
 * form; its stored document carries the long form, which becomes the issuer.
 * All knowledge of the @interop/vc and suite contracts is isolated to this
 * file.
 */
import { Ed25519Signature2020, eddsaRdfc2022 } from '@interop/ed25519-signature'
import { ecdsaRdfc2019 } from '@interop/ecdsa-signature'
import { DataIntegrityProof } from '@interop/data-integrity-proof'
import { issue, type IssueCredentialOptions } from '@interop/vc'
import type { IDidDocument, ISigner } from '@interop/data-integrity-core'
import { documentLoader } from '../documentLoader.js'
import { loadDidDocument } from '../storage.js'
import {
  keyIdForPurpose,
  loadStoredSigner,
  type KeyType
} from '../keys/stored-key.js'

/**
 * The supported `--suite` values per key type. The signing key's type (read
 * from its multibase header) determines which suites are usable; an ed25519 key
 * cannot sign with an ecdsa cryptosuite and vice versa.
 */
const SUPPORTED_SUITES: Record<KeyType, readonly string[]> = {
  ed25519: ['eddsa-rdfc-2022', 'Ed25519Signature2020'],
  ecdsa: ['ecdsa-rdfc-2019']
}

/**
 * The default `--suite` for each key type, used when no `--suite` is given.
 */
const DEFAULT_SUITE: Record<KeyType, string> = {
  ed25519: 'eddsa-rdfc-2022',
  ecdsa: 'ecdsa-rdfc-2019'
}

/**
 * A credential's `issuer` property: either a DID string or an object with an
 * `id`.
 */
type IssuerProperty = string | { id?: string } | undefined

/**
 * Reconciles a credential's existing `issuer` property with the signing DID.
 * When the credential has no `issuer`, the signing DID is set as the issuer.
 * When it already has one, it must match the signing DID, otherwise issuance is
 * aborted -- a credential must be issued by the DID named as its issuer.
 *
 * @param options {object}
 * @param options.credential {object}   The credential being issued (mutated in
 *   place when the issuer is absent).
 * @param options.did {string}   The id of the DID issuing (signing) the
 *   credential.
 */
function reconcileIssuer({
  credential,
  did
}: {
  credential: { issuer?: IssuerProperty }
  did: string
}): void {
  const issuer = credential.issuer
  if (issuer === undefined) {
    credential.issuer = did
    return
  }
  const issuerId = typeof issuer === 'string' ? issuer : issuer?.id
  if (issuerId !== did) {
    throw new Error(
      "Signing DID does not match the existing 'issuer' property. " +
        'Remove existing issuer, or pass in a matching DID.'
    )
  }
}

/**
 * Returns whether the given key id appears in the DID document's
 * `assertionMethod` relationship, matching either a string reference or the
 * `id` of an embedded verification method object.
 *
 * @param options {object}
 * @param options.didDocument {IDidDocument}
 * @param options.keyId {string}
 * @returns {boolean}
 */
function isAuthorizedForAssertion({
  didDocument,
  keyId
}: {
  didDocument: IDidDocument
  keyId: string
}): boolean {
  const assertionMethod = didDocument.assertionMethod
  const entries = Array.isArray(assertionMethod)
    ? assertionMethod
    : assertionMethod
      ? [assertionMethod]
      : []
  return entries.some(entry =>
    typeof entry === 'string' ? entry === keyId : entry.id === keyId
  )
}

/**
 * Builds the @interop/vc signature suite around a stored key's signer, wiring
 * the requested (or default) cryptosuite. The signing key's type selects the
 * available suites: ed25519 keys sign with `eddsa-rdfc-2022` (default) or
 * `Ed25519Signature2020`, and ecdsa keys sign with `ecdsa-rdfc-2019`.
 *
 * @param options {object}
 * @param options.signer {ISigner}   The stored key's signer.
 * @param options.keyType {KeyType}   The stored key's type.
 * @param [options.suite] {string}   The requested suite, or undefined to use
 *   the key type's default.
 * @returns {DataIntegrityProof | Ed25519Signature2020}
 */
function buildSuite({
  signer,
  keyType,
  suite
}: {
  signer: ISigner
  keyType: KeyType
  suite?: string
}): DataIntegrityProof | Ed25519Signature2020 {
  const resolvedSuite = suite ?? DEFAULT_SUITE[keyType]
  const supported = SUPPORTED_SUITES[keyType]
  if (!supported.includes(resolvedSuite)) {
    throw new Error(
      `Suite ${resolvedSuite} is not supported for ${keyType} keys. ` +
        `Supported: ${supported.join(', ')}`
    )
  }

  switch (resolvedSuite) {
    case 'ecdsa-rdfc-2019':
      return new DataIntegrityProof({ signer, cryptosuite: ecdsaRdfc2019 })
    case 'eddsa-rdfc-2022':
      return new DataIntegrityProof({ signer, cryptosuite: eddsaRdfc2022 })
    case 'Ed25519Signature2020':
      return new Ed25519Signature2020({ signer })
    default:
      // Unreachable: resolvedSuite was validated against SUPPORTED_SUITES above.
      throw new Error(`Unknown suite: ${resolvedSuite}`)
  }
}

/**
 * Issues (signs) a credential with a locally-stored DID's assertionMethod key.
 *
 * When `keyId` is given it must be authorized by the DID's `assertionMethod`
 * relationship; otherwise the first `assertionMethod` key is used. The matching
 * secret key is loaded from the DID's `<did>.keys.json` file. The credential's
 * `issuer` is set to the signing DID when absent, and must match it when present.
 *
 * @param options {object}
 * @param options.credential {object}   The unsigned credential to issue.
 * @param options.did {string}   The id of the stored DID to issue (sign) with.
 * @param [options.keyId] {string}   The verification method id to use.
 * @param [options.suite] {string}   The signature suite. Defaults to the signing
 *   key type's default (`eddsa-rdfc-2022` for ed25519, `ecdsa-rdfc-2019` for
 *   ecdsa).
 * @returns {Promise<object>}   The issued credential.
 */
export async function issueCredential({
  credential,
  did,
  keyId,
  suite
}: {
  credential: object
  did: string
  keyId?: string
  suite?: string
}): Promise<object> {
  const didDocument = await loadDidDocument<IDidDocument>(did)

  reconcileIssuer({
    credential: credential as { issuer?: IssuerProperty },
    did: didDocument.id
  })

  let selectedKeyId: string
  if (keyId) {
    if (!isAuthorizedForAssertion({ didDocument, keyId })) {
      throw new Error(
        "Specified key is not authorized by the DID's assertionMethod array"
      )
    }
    selectedKeyId = keyId
  } else {
    selectedKeyId = keyIdForPurpose({ didDocument, purpose: 'assertionMethod' })
  }

  const { signer, keyType } = await loadStoredSigner({
    did,
    keyId: selectedKeyId
  })
  const signatureSuite = buildSuite({ signer, keyType, suite })

  // The local credential / suite / loader shapes satisfy @interop/vc's
  // contracts structurally but are typed independently here; cast to the option
  // types rather than the blanket `as never`.
  return issue({
    credential: credential as unknown as IssueCredentialOptions['credential'],
    suite: signatureSuite as unknown as IssueCredentialOptions['suite'],
    documentLoader:
      documentLoader as unknown as IssueCredentialOptions['documentLoader']
  })
}
