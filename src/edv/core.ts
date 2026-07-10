/**
 * EDV Document encryption via `@interop/edv-client`'s `EdvDocumentCipher`. The
 * `{ id, sequence, indexed, jwe }` envelope is not assembled here; it is routed
 * through the reference codec instead, so the envelope -- and the HMAC-blinded
 * `indexed` array -- is correct-by-construction against the implementation an
 * EDV / WAS server expects.
 *
 * Only the transport-free helpers are used: `EdvDocumentCipher.encrypt` /
 * `decrypt` (the envelope + index blinding), plus `EdvClientCore.ensureIndex`
 * (declaring indexable attributes, which registers them on the core's
 * `indexHelper` -- and so on the `documentCipher` that shares it) and
 * `generateId` (the document id). The chunked-stream bytes are still produced
 * by the cipher directly (see `./stream.ts`), since the core's stream path
 * requires a server transport; only the stream document's envelope passes
 * through here.
 */
import { Cipher } from '@interop/minimal-cipher'
import { EdvClientCore, EdvDocumentCipher } from '@interop/edv-client'
import type {
  IEDVDocument,
  IEncryptedDocument,
  IHMAC
} from '@interop/data-integrity-core'
import type { DocumentPayload } from './document.js'
import type { KeyAgreementKey } from './recipients.js'

/** A declared indexable attribute: a dotted path into `content`/`meta`. */
export interface IndexDeclaration {
  attribute: string
  unique?: boolean
}

/**
 * The prior-document base carried into an `--update`: the existing envelope's
 * id, sequence (the core increments it), and `indexed` (the matching HMAC's
 * entry is replaced, others preserved).
 */
export interface UpdateBase {
  id: string
  sequence: number
  indexed: IEncryptedDocument['indexed']
}

/**
 * Encrypt an EDV Document through `EdvDocumentCipher.encrypt`: serialize the
 * document's `{ content, meta, stream }` into a single JWE for the recipients,
 * blind any declared indexable attributes with `hmac`, and assemble the
 * `{ id, sequence, indexed, jwe }` envelope (plus `stream` when present).
 *
 * Without `base` this is a new document: the core mints a fresh id and
 * `sequence: 0`. With `base` it is an update: the prior id/sequence/`indexed`
 * are stamped onto `doc` so the core increments the sequence and merges the
 * index entry. Recipient union across an update is handled by the caller, so
 * `doc.jwe` is not passed in.
 *
 * @param options {object}
 * @param options.doc {IEDVDocument}   The cleartext document to encrypt.
 * @param options.keys {KeyAgreementKey[]}   The recipients to encrypt to.
 * @param [options.hmac] {IHMAC}   Blinding key; required for `indexes`.
 * @param [options.indexes] {IndexDeclaration[]}   Attributes to index.
 * @param [options.base] {UpdateBase}   Prior document; omit for a new document.
 * @returns {Promise<IEncryptedDocument>}
 */
export async function encryptDocument({
  doc,
  keys,
  hmac,
  indexes,
  base
}: {
  doc: IEDVDocument
  keys: KeyAgreementKey[]
  hmac?: IHMAC
  indexes?: IndexDeclaration[]
  base?: UpdateBase
}): Promise<IEncryptedDocument> {
  if (base) {
    Object.assign(doc, base)
  } else {
    doc.id = await EdvClientCore.generateId()
  }
  const core = new EdvClientCore({ hmac })
  for (const { attribute, unique } of indexes ?? []) {
    core.ensureIndex({ attribute, unique })
  }
  const { recipients, keyResolver } = new Cipher().createRecipients({ keys })
  return core.documentCipher.encrypt({
    doc,
    recipients,
    keyResolver,
    hmac,
    update: Boolean(base)
  })
}

/**
 * Decrypt an EDV Document envelope through `EdvDocumentCipher.decrypt`,
 * returning its cleartext payload (`content`, plus `meta`/`stream` when
 * present). Decryption reads no index, so the codec needs no `indexHelper`. A
 * wrong key surfaces as a thrown error (the codec rejects a `null` decrypt).
 *
 * @param options {object}
 * @param options.encryptedDoc {IEncryptedDocument}
 * @param options.keyAgreementKey {KeyAgreementKey}
 * @returns {Promise<DocumentPayload>}
 */
export async function decryptDocument({
  encryptedDoc,
  keyAgreementKey
}: {
  encryptedDoc: IEncryptedDocument
  keyAgreementKey: KeyAgreementKey
}): Promise<DocumentPayload> {
  const documentCipher = new EdvDocumentCipher({ cipher: new Cipher() })
  const { content, meta, stream } = await documentCipher.decrypt({
    encryptedDoc,
    keyAgreementKey
  })
  return stream === undefined ? { content, meta } : { content, meta, stream }
}
