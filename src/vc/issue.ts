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
 * store written by `id create --save`). All knowledge of the @interop/vc and
 * suite contracts is isolated to this file.
 */
import { driver } from '@interop/did-method-key'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'
import {
  Ed25519Signature2020,
  createSigner,
  eddsaRdfc2022
} from '@interop/ed25519-signature'
import { DataIntegrityProof } from '@interop/data-integrity-proof'
import { issue } from '@interop/vc'
import { securityLoader } from '@interop/security-document-loader'
import { loadDidDocument, loadDidKeys } from '../storage.js'

/**
 * Offline document loader for signing: bundles the VC / Data Integrity / suite
 * contexts (including the `ed25519-2020` suite context) and a did:key resolver.
 * Built once and reused across calls.
 */
const documentLoader = securityLoader().build()

/**
 * The supported `--suite` values and their human-readable list (for errors).
 */
const SUPPORTED_SUITES = ['eddsa-rdfc-2022', 'Ed25519Signature2020'] as const

/**
 * A DID document verification method entry: either a key id reference (string)
 * or an embedded verification method object.
 */
type VerificationMethodEntry = string | { id?: string }

interface DidDocument {
  id: string
  assertionMethod?: VerificationMethodEntry | VerificationMethodEntry[]
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
 * The two on-disk shapes of a `<did>.keys.json` file: a single exported key pair
 * (written by `id create --save` for did:key), or a map of exported key pairs
 * keyed by verification-method id (written by `id create web --save` and
 * `id add-key` for did:web, which may carry more than one key).
 */
type StoredKeys = StoredKeyPair | Record<string, StoredKeyPair>

/**
 * Resolves the exported key pair for `keyId` out of a loaded `<did>.keys.json`,
 * accommodating both the single-key (did:key) and the keyed-map (did:web)
 * storage shapes.
 *
 * @param options {object}
 * @param options.keysData {StoredKeys}   The parsed key file contents.
 * @param options.keyId {string}   The verification method id to find.
 * @returns {StoredKeyPair | undefined}   The matching key pair, or undefined.
 */
function selectStoredKey({
  keysData,
  keyId
}: {
  keysData: StoredKeys
  keyId: string
}): StoredKeyPair | undefined {
  if ((keysData as StoredKeyPair).id === keyId) {
    return keysData as StoredKeyPair
  }
  const entry = (keysData as Record<string, StoredKeyPair>)[keyId]
  return entry?.id === keyId ? entry : undefined
}

/**
 * Returns whether the given key id appears in the DID document's
 * `assertionMethod` relationship, matching either a string reference or the
 * `id` of an embedded verification method object.
 *
 * @param options {object}
 * @param options.didDocument {DidDocument}
 * @param options.keyId {string}
 * @returns {boolean}
 */
function isAuthorizedForAssertion({
  didDocument,
  keyId
}: {
  didDocument: DidDocument
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
 * Builds the @interop/vc signature suite for the requested cryptosuite name.
 *
 * @param options {object}
 * @param options.suite {string}   One of `SUPPORTED_SUITES`.
 * @param options.signer {object}   The signer produced from the key pair.
 * @returns {DataIntegrityProof | Ed25519Signature2020}
 */
function buildSuite({
  suite,
  signer
}: {
  suite: string
  signer: ReturnType<typeof createSigner>
}): DataIntegrityProof | Ed25519Signature2020 {
  switch (suite) {
    case 'eddsa-rdfc-2022':
      return new DataIntegrityProof({ signer, cryptosuite: eddsaRdfc2022 })
    case 'Ed25519Signature2020':
      return new Ed25519Signature2020({ signer })
    default:
      throw new Error(
        `Unknown suite: ${suite}. Supported: ${SUPPORTED_SUITES.join(', ')}`
      )
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
 * @param [options.suite] {string}   The signature suite (default
 *   `eddsa-rdfc-2022`).
 * @returns {Promise<object>}   The issued credential.
 */
export async function issueCredential({
  credential,
  did,
  keyId,
  suite = 'eddsa-rdfc-2022'
}: {
  credential: object
  did: string
  keyId?: string
  suite?: string
}): Promise<object> {
  const didDocument = await loadDidDocument<DidDocument>(did)

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
    const method = driver().publicMethodFor({
      didDocument: didDocument as never,
      purpose: 'assertionMethod'
    }) as { id: string }
    selectedKeyId = method.id
  }

  const keysData = await loadDidKeys<StoredKeys>(did)
  const storedKey = selectStoredKey({ keysData, keyId: selectedKeyId })
  if (!storedKey) {
    throw new Error(
      `No stored secret key found for key id ${selectedKeyId} in DID ${did}`
    )
  }

  const keyPair = await Ed25519VerificationKey.from(storedKey)
  const signer = createSigner(keyPair)
  const signatureSuite = buildSuite({ suite, signer })

  return issue({
    credential: credential as never,
    suite: signatureSuite as never,
    documentLoader: documentLoader as never
  })
}
