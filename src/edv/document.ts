/**
 * Shared EDV Document types and the envelope detector for the `edv` command.
 *
 * The `{ id, sequence, indexed, jwe }` envelope -- the document the EDV / WAS
 * data model stores -- is assembled and unwrapped by `@interop/edv-client`'s
 * `EdvClientCore` (see `./core.ts`); Phases 1-2's hand-rolled assembly was
 * retired in Phase 3 in favor of that reference implementation. This module
 * keeps only what the command layer needs alongside it: the decrypted payload
 * shape and the `isEncryptedDocument` discriminator that tells an EDV Document
 * envelope apart from a bare Layer 1 JWE on read.
 */
import type {
  IEDVDocument,
  IEncryptedDocument
} from '@interop/data-integrity-core'

/** Filename convention for a serialized EDV Document. */
export const EDV_DOCUMENT_FILE_SUFFIX = '.edvdoc.json'

/** The decrypted payload an EDV Document's JWE protects. */
export type DocumentPayload = Pick<IEDVDocument, 'content' | 'meta' | 'stream'>

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
