/**
 * EDV Document envelope (Layer 2, Phase 1): wrap a Layer 1 JWE in the
 * `{ id, sequence, indexed, jwe }` document the EDV / WAS data model stores, and
 * unwrap it on read. The user's object becomes the document's `content`; an
 * optional `meta` rides alongside it inside the same JWE, so both are encrypted
 * and only `id`, `sequence`, and `indexed` stay cleartext.
 *
 * This phase always emits `indexed: []` (HMAC-blinded indexing is Layer 2,
 * Phase 3) and never produces a chunked `stream` (Phase 2), but it preserves an
 * existing `indexed` array and reports a `stream` descriptor on read.
 *
 * The envelope is byte-faithful to `@interop/edv-client`'s `EdvClientCore`
 * without taking that dependency: `generateDocumentId` reproduces its
 * identity-multihash + base58btc id via the `bnid` library already in use (an
 * 18-byte `0x00 0x10` + 16 random bytes payload, multibase `z` prefix), and the
 * `{ content, meta }` payload mirrors its `_encrypt` / `_decrypt` helpers.
 */
import { generateId } from '@digitalcredentials/bnid'
import type {
  IEDVDocument,
  IEncryptedDocument
} from '@interop/data-integrity-core'

/** Filename convention for a serialized EDV Document. */
export const EDV_DOCUMENT_FILE_SUFFIX = '.edvdoc.json'

/** The decrypted payload an EDV Document's JWE protects. */
export type DocumentPayload = Pick<IEDVDocument, 'content' | 'meta' | 'stream'>

/**
 * Generate a fresh EDV Document id: a 128-bit random value wrapped as an
 * identity multihash and base58btc-multibase encoded (the `z…` form). Byte-for-
 * byte identical to `EdvClientCore.generateId()`.
 *
 * @returns {Promise<string>}
 */
export async function generateDocumentId(): Promise<string> {
  return generateId({
    bitLength: 128,
    encoding: 'base58',
    multibase: true,
    multihash: true
  })
}

/**
 * True when a parsed value is an encrypted EDV Document envelope (it carries a
 * string `id` and an object `jwe`), as opposed to a bare Layer 1 JWE.
 *
 * @param value {unknown}
 * @returns {boolean}
 */
export function isEncryptedDocument(
  value: unknown
): value is IEncryptedDocument {
  if (value === null || typeof value !== 'object') {
    return false
  }
  const candidate = value as Record<string, unknown>
  return (
    typeof candidate.id === 'string' &&
    typeof candidate.jwe === 'object' &&
    candidate.jwe !== null
  )
}

/**
 * Build the cleartext payload to encrypt into a document's JWE: the user's
 * object as `content`, with `meta` included only when provided. Matches the
 * `{ content, meta }` object `EdvClientCore._encrypt` serializes.
 *
 * @param options {object}
 * @param options.content {Record<string, unknown>}
 * @param [options.meta] {Record<string, unknown>}
 * @returns {DocumentPayload}
 */
export function buildDocumentPayload({
  content,
  meta
}: {
  content: Record<string, unknown>
  meta?: Record<string, unknown>
}): DocumentPayload {
  return meta === undefined ? { content } : { content, meta }
}
