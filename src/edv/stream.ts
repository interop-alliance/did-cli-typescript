/**
 * Chunked-stream support for EDV Documents (Layer 2, Phase 2): encrypt a large
 * input as a sequence of fixed-size encrypted chunks instead of a single JWE,
 * and decrypt the chunks back into the original bytes. A streamed document
 * carries a cleartext `stream: { sequence, chunks }` descriptor; the bytes
 * themselves live in separate chunk JWEs, each `{ sequence, index, offset, jwe }`
 * (`IEDVChunk`), mirroring how an EDV / WAS server stores stream resources apart
 * from the document.
 *
 * On disk the document and its chunks are a **bundle directory** (convention
 * `*.edvdoc/`): `document.json` (the `{ id, sequence, indexed, stream, jwe }`
 * envelope) and `chunks/<index>.jwe.json` (one file per chunk). This keeps the
 * chunks as distinct resources, faithful to the server model.
 *
 * The cipher driving mirrors `@interop/edv-client`'s `_updateStream` /
 * `EdvDocument.getStream` without taking that dependency: it pumps the input
 * through `cipher.createEncryptStream`, stamps the document `sequence` onto each
 * emitted chunk, and feeds chunks back (in `index` order) through
 * `cipher.createDecryptStream`.
 */
import { mkdir, readFile, readdir, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import type { Cipher } from '@interop/minimal-cipher'
import type {
  IEDVChunk,
  IEncryptedDocument,
  IJWE,
  IKeyResolver,
  IRecipientTemplate
} from '@interop/data-integrity-core'
import { isEncryptedDocument } from './document.js'
import type { KeyAgreementKey } from './recipients.js'

/** The envelope file within a bundle directory. */
const BUNDLE_DOCUMENT_FILE = 'document.json'
/** The subdirectory holding the chunk JWE files within a bundle directory. */
const BUNDLE_CHUNKS_DIR = 'chunks'

/**
 * Drain a TransformStream: write each input value, then read every output
 * value. Reads run concurrently with the single write so a large input cannot
 * deadlock against the stream's internal backpressure.
 *
 * @param options {object}
 * @param options.stream {TransformStream}
 * @param options.inputs {unknown[]}   Values to write to the writable side.
 * @returns {Promise<T[]>}   The values emitted on the readable side.
 */
async function pump<T>({
  stream,
  inputs
}: {
  stream: TransformStream
  inputs: unknown[]
}): Promise<T[]> {
  const writer = stream.writable.getWriter()
  const reader = stream.readable.getReader()
  const outputs: T[] = []
  const reading = (async () => {
    for (;;) {
      const { value, done } = await reader.read()
      if (done) {
        break
      }
      outputs.push(value as T)
    }
  })()
  for (const input of inputs) {
    await writer.write(input)
  }
  await writer.close()
  await reading
  return outputs
}

/**
 * Concatenate Uint8Array parts into a single buffer.
 *
 * @param parts {Uint8Array[]}
 * @returns {Uint8Array}
 */
function concatBytes(parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.byteLength, 0)
  const result = new Uint8Array(total)
  let offset = 0
  for (const part of parts) {
    result.set(part, offset)
    offset += part.byteLength
  }
  return result
}

/**
 * Encrypt `data` as a stream of chunks for the given recipients, stamping the
 * document `sequence` onto each chunk (as `EdvClientCore._updateStream` does).
 *
 * @param options {object}
 * @param options.cipher {Cipher}
 * @param options.data {Uint8Array}
 * @param options.recipients {IRecipientTemplate[]}
 * @param options.keyResolver {IKeyResolver}
 * @param [options.chunkSize] {number}   Bytes per chunk (cipher default 1 MiB).
 * @param options.sequence {number}   The owning document's sequence.
 * @returns {Promise<IEDVChunk[]>}
 */
export async function encryptToChunks({
  cipher,
  data,
  recipients,
  keyResolver,
  chunkSize,
  sequence
}: {
  cipher: Cipher
  data: Uint8Array
  recipients: IRecipientTemplate[]
  keyResolver: IKeyResolver
  chunkSize?: number
  sequence: number
}): Promise<IEDVChunk[]> {
  const stream = await cipher.createEncryptStream({
    recipients,
    keyResolver,
    chunkSize
  })
  const emitted = await pump<{ index: number; offset: number; jwe: IJWE }>({
    stream,
    inputs: [data]
  })
  return emitted.map(chunk => ({
    sequence,
    index: chunk.index,
    offset: chunk.offset,
    jwe: chunk.jwe
  }))
}

/**
 * Decrypt a document's chunks (in `index` order) back into the original bytes.
 * A wrong key surfaces as a thrown `DataError` from the decrypt transformer.
 *
 * @param options {object}
 * @param options.cipher {Cipher}
 * @param options.chunks {IEDVChunk[]}
 * @param options.keyAgreementKey {KeyAgreementKey}
 * @returns {Promise<Uint8Array>}
 */
export async function decryptChunks({
  cipher,
  chunks,
  keyAgreementKey
}: {
  cipher: Cipher
  chunks: IEDVChunk[]
  keyAgreementKey: KeyAgreementKey
}): Promise<Uint8Array> {
  const ordered = [...chunks].sort(
    (first, second) => first.index - second.index
  )
  const stream = await cipher.createDecryptStream({ keyAgreementKey })
  const parts = await pump<Uint8Array>({
    stream,
    inputs: ordered.map(chunk => ({ jwe: chunk.jwe }))
  })
  return concatBytes(parts)
}

/**
 * Write a streamed EDV Document as a bundle directory: `document.json` plus
 * `chunks/<index>.jwe.json` for each chunk.
 *
 * @param options {object}
 * @param options.dir {string}   The bundle directory path.
 * @param options.document {IEncryptedDocument}
 * @param options.chunks {IEDVChunk[]}
 * @returns {Promise<void>}
 */
export async function writeDocumentBundle({
  dir,
  document,
  chunks
}: {
  dir: string
  document: IEncryptedDocument
  chunks: IEDVChunk[]
}): Promise<void> {
  const chunksDir = join(dir, BUNDLE_CHUNKS_DIR)
  await mkdir(chunksDir, { recursive: true })
  await writeFile(
    join(dir, BUNDLE_DOCUMENT_FILE),
    `${JSON.stringify(document, null, 2)}\n`,
    'utf8'
  )
  for (const chunk of chunks) {
    await writeFile(
      join(chunksDir, `${chunk.index}.jwe.json`),
      `${JSON.stringify(chunk, null, 2)}\n`,
      'utf8'
    )
  }
}

/**
 * Read a bundle directory back into its document envelope and chunks (sorted by
 * `index`).
 *
 * @param options {object}
 * @param options.dir {string}   The bundle directory path.
 * @returns {Promise<{document: IEncryptedDocument, chunks: IEDVChunk[]}>}
 */
export async function readDocumentBundle({ dir }: { dir: string }): Promise<{
  document: IEncryptedDocument
  chunks: IEDVChunk[]
}> {
  let document: unknown
  try {
    document = JSON.parse(
      await readFile(join(dir, BUNDLE_DOCUMENT_FILE), 'utf8')
    )
  } catch (err) {
    throw new Error(
      `Could not read ${BUNDLE_DOCUMENT_FILE} in bundle "${dir}": ${(err as Error).message}`,
      { cause: err }
    )
  }
  if (!isEncryptedDocument(document)) {
    throw new Error(`Bundle "${dir}" does not contain an EDV Document.`)
  }

  const chunksDir = join(dir, BUNDLE_CHUNKS_DIR)
  const names = (await readdir(chunksDir).catch(() => [])).filter(name =>
    name.endsWith('.jwe.json')
  )
  const chunks: IEDVChunk[] = []
  for (const name of names) {
    chunks.push(JSON.parse(await readFile(join(chunksDir, name), 'utf8')))
  }
  chunks.sort((first, second) => first.index - second.index)
  return { document, chunks }
}
