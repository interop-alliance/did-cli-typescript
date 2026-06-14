/**
 * `edv` command -- encrypt to and decrypt from X25519 recipients using the
 * EDV / minimal-cipher serialization.
 *
 * Public-key (key-agreement) encryption only: recipients are one or more X25519
 * public keys, given as a raw `publicKeyMultibase`, a wallet key
 * fingerprint/handle, a DID / DID URL, or a key-document JSON file. Three output
 * shapes:
 *  - default -- a single raw JWE (the `jwe` field of an EDV Document), to stdout
 *    or an `-o` file (convention `*.jwe.json`); Layer 1.
 *  - `--document` -- a full EDV Document envelope `{ id, sequence, indexed, jwe }`
 *    (convention `*.edvdoc.json`), encrypting the input as the document
 *    `content`; Layer 2, Phase 1.
 *  - `--stream` -- a bundle directory (convention `*.edvdoc/`) whose
 *    `document.json` carries a `stream: { sequence, chunks }` descriptor and
 *    whose `chunks/<index>.jwe.json` hold the input encrypted as fixed-size
 *    chunks; Layer 2, Phase 2.
 * HMAC-blinded indexing is Layer 2, Phase 3.
 *
 * Data goes to stdout, diagnostics to stderr. Exit codes: 0 success, 1
 * decryption failure (wrong key / not a recipient), 2 input error (no
 * recipient, unresolvable recipient/key, malformed input).
 */
import { stat } from 'node:fs/promises'
import { Command, InvalidArgumentError } from 'commander'
import { Cipher } from '@interop/minimal-cipher'
import type { IEncryptedDocument, IJWE } from '@interop/data-integrity-core'
import { readInputBytes, writeBytesOutput, writeJsonOutput } from '../was/io.js'
import { runAndExit } from './was/shared.js'
import {
  autoSelectKeyAgreementKey,
  loadKeyAgreementKey,
  resolveRecipient,
  resolveRecipientFile,
  type KeyAgreementKey
} from '../edv/recipients.js'
import {
  buildDocumentPayload,
  generateDocumentId,
  isEncryptedDocument,
  type DocumentPayload
} from '../edv/document.js'
import {
  decryptChunks,
  encryptToChunks,
  readDocumentBundle,
  writeDocumentBundle
} from '../edv/stream.js'

/**
 * Collect a repeatable option value into an array (commander reducer).
 *
 * @param value {string}
 * @param previous {string[]}
 * @returns {string[]}
 */
function collect(value: string, previous: string[]): string[] {
  return previous.concat(value)
}

/**
 * Parse and validate the `--chunk-size` option (a positive integer of bytes).
 *
 * @param value {string}
 * @returns {number}
 */
function parseChunkSize(value: string): number {
  const bytes = Number(value)
  if (!Number.isInteger(bytes) || bytes <= 0) {
    throw new InvalidArgumentError('--chunk-size must be a positive integer.')
  }
  return bytes
}

/**
 * Decode bytes as UTF-8 JSON. Returns `undefined` (rather than throwing) when
 * the input is not valid JSON, so callers can emit a context-specific message.
 *
 * @param bytes {Uint8Array}
 * @returns {unknown}
 */
function parseJson(bytes: Uint8Array): unknown {
  try {
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes))
  } catch {
    return undefined
  }
}

/**
 * Recover the recipient reference to re-resolve a prior recipient from its
 * `kid`. An X25519 `did:key` kid (`did:key:z6LS…#z6LS…`) embeds the public key
 * multibase as its fragment -- resolve that directly, since the DID resolver
 * does not resolve a `did:key` whose base is an X25519 (`z6LS`) key. Any other
 * kid (e.g. a `did:web` URL) is left for `resolveRecipient`'s DID path.
 *
 * @param kid {string}
 * @returns {string}
 */
function recipientRefFromKid(kid: string): string {
  const fragment = kid.includes('#') ? kid.slice(kid.indexOf('#') + 1) : ''
  if (kid.startsWith('did:key:') && fragment.startsWith('z6LS')) {
    return fragment
  }
  return kid
}

/**
 * Merge the recipients of an existing document into the freshly resolved keys
 * for an `--update`, re-resolving each prior recipient from its `kid` and
 * skipping any already covered. This mirrors `EdvClientCore._encrypt`'s
 * recipient-union behavior, so an update can add a recipient without
 * re-specifying the existing ones.
 *
 * @param options {object}
 * @param options.keys {KeyAgreementKey[]}   Keys resolved from `--recipient(s)`.
 * @param options.existing {IEncryptedDocument}   The document being updated.
 * @returns {Promise<KeyAgreementKey[]>}
 */
async function mergeUpdateRecipients({
  keys,
  existing
}: {
  keys: KeyAgreementKey[]
  existing: IEncryptedDocument
}): Promise<KeyAgreementKey[]> {
  const seen = new Set(keys.map(key => key.id))
  const merged = [...keys]
  for (const recipient of existing.jwe.recipients ?? []) {
    const kid = recipient?.header?.kid
    if (!kid || seen.has(kid)) {
      continue
    }
    merged.push(await resolveRecipient({ ref: recipientRefFromKid(kid) }))
    seen.add(kid)
  }
  return merged
}

/**
 * True when a path exists and is a directory (an EDV Document bundle).
 *
 * @param path {string}
 * @returns {Promise<boolean>}
 */
async function isDirectory(path: string): Promise<boolean> {
  return (await stat(path).catch(() => undefined))?.isDirectory() ?? false
}

/**
 * Load an existing EDV Document to update, from either a single `.edvdoc.json`
 * file or a bundle directory (`document.json` inside it). Returns `undefined`
 * when the source is neither.
 *
 * @param options {object}
 * @param options.path {string}
 * @returns {Promise<IEncryptedDocument | undefined>}
 */
async function loadEnvelope({
  path
}: {
  path: string
}): Promise<IEncryptedDocument | undefined> {
  if (await isDirectory(path)) {
    return (await readDocumentBundle({ dir: path })).document
  }
  const parsed = parseJson(await readInputBytes({ file: path }))
  return isEncryptedDocument(parsed) ? parsed : undefined
}

/**
 * Resolve the encrypt-time envelope fields for a new or updated document: a
 * fresh id at `sequence` 0, or -- with `--update` -- the existing document's id,
 * its incremented sequence, its preserved `indexed`, and its recipients merged
 * into `keys`.
 *
 * @param options {object}
 * @param options.keys {KeyAgreementKey[]}
 * @param [options.update] {string}   Path to the document being updated.
 * @returns {Promise<{id, sequence, indexed, encryptKeys}>}
 */
async function resolveEnvelopeFields({
  keys,
  update
}: {
  keys: KeyAgreementKey[]
  update?: string
}): Promise<{
  id: string
  sequence: number
  indexed: IEncryptedDocument['indexed']
  encryptKeys: KeyAgreementKey[]
}> {
  if (update === undefined) {
    return {
      id: await generateDocumentId(),
      sequence: 0,
      indexed: [],
      encryptKeys: keys
    }
  }
  const existing = await loadEnvelope({ path: update })
  if (!existing) {
    throw new Error(`--update target "${update}" is not an EDV Document.`)
  }
  return {
    id: existing.id,
    sequence: existing.sequence + 1,
    indexed: existing.indexed ?? [],
    encryptKeys: await mergeUpdateRecipients({ keys, existing })
  }
}

/**
 * Encrypt stdin or a file to one or more X25519 recipients. By default emits a
 * raw JWE (Layer 1); `--document` wraps the JWE in an EDV Document envelope
 * `{ id, sequence, indexed, jwe }` (input encrypted as `content`); `--stream`
 * writes a bundle directory whose chunks hold the input as a chunked stream.
 *
 * @param options {object}
 * @param [options.file] {string}   Input file; stdin when omitted.
 * @param options.recipient {string[]}   Recipient refs (`--recipient`).
 * @param options.recipientFile {string[]}   Key-document files.
 * @param [options.json] {boolean}   Parse input as JSON (`encryptObject`).
 * @param [options.document] {boolean}   Emit a full EDV Document envelope.
 * @param [options.stream] {boolean}   Emit a chunked-stream bundle directory.
 * @param [options.chunkSize] {number}   Bytes per chunk for `--stream`.
 * @param [options.meta] {string}   JSON `meta` object for the document.
 * @param [options.update] {string}   Existing document (file or bundle) to
 *   update: reuse its `id`, increment `sequence`, and merge its recipients.
 * @param [options.out] {string}   Output file/bundle; stdout when omitted.
 * @returns {Promise<number>}
 */
export async function runEncrypt({
  file,
  recipient,
  recipientFile,
  json,
  document,
  stream,
  chunkSize,
  meta,
  update,
  out
}: {
  file?: string
  recipient: string[]
  recipientFile: string[]
  json?: boolean
  document?: boolean
  stream?: boolean
  chunkSize?: number
  meta?: string
  update?: string
  out?: string
}): Promise<number> {
  const envelopeMode = Boolean(document) || Boolean(stream)
  if (!envelopeMode && (meta !== undefined || update !== undefined)) {
    console.error('--meta and --update require --document or --stream.')
    return 2
  }

  const keys: KeyAgreementKey[] = []
  try {
    for (const ref of recipient) {
      keys.push(await resolveRecipient({ ref }))
    }
    for (const path of recipientFile) {
      keys.push(await resolveRecipientFile({ path }))
    }
  } catch (err) {
    console.error((err as Error).message)
    return 2
  }
  if (keys.length === 0) {
    console.error('At least one --recipient or --recipient-file is required.')
    return 2
  }

  const bytes = await readInputBytes({ file })
  const cipher = new Cipher()

  if (stream) {
    return runEncryptStream({
      bytes,
      keys,
      meta,
      update,
      chunkSize,
      out,
      cipher
    })
  }
  if (document) {
    return runEncryptDocument({ bytes, keys, meta, update, out, cipher })
  }

  const { recipients, keyResolver } = cipher.createRecipients({ keys })
  let jwe
  if (json) {
    const obj = parseJson(bytes)
    if (obj === null || typeof obj !== 'object') {
      console.error('--json was given but the input is not valid JSON.')
      return 2
    }
    jwe = await cipher.encryptObject({ obj, recipients, keyResolver })
  } else {
    jwe = await cipher.encrypt({ data: bytes, recipients, keyResolver })
  }

  await writeJsonOutput({ value: jwe, output: out })
  return 0
}

/**
 * Parse a JSON-object command option, throwing a clear error when the value is
 * not valid JSON or not an object.
 *
 * @param options {object}
 * @param options.value {string}
 * @param options.label {string}   The option name, for the error message.
 * @returns {Record<string, unknown>}
 */
function parseJsonObjectOption({
  value,
  label
}: {
  value: string
  label: string
}): Record<string, unknown> {
  let parsed: unknown
  try {
    parsed = JSON.parse(value)
  } catch {
    throw new Error(`${label} is not valid JSON.`)
  }
  if (parsed === null || typeof parsed !== 'object') {
    throw new Error(`${label} must be a JSON object.`)
  }
  return parsed as Record<string, unknown>
}

/**
 * The `--document` branch of `runEncrypt`: parse the input as the document's
 * `content`, attach optional `--meta`, mint or carry over the envelope id and
 * sequence, encrypt `{ content, meta }`, and emit the envelope.
 *
 * @param options {object}
 * @param options.bytes {Uint8Array}
 * @param options.keys {KeyAgreementKey[]}
 * @param [options.meta] {string}
 * @param [options.update] {string}
 * @param [options.out] {string}
 * @param options.cipher {Cipher}
 * @returns {Promise<number>}
 */
async function runEncryptDocument({
  bytes,
  keys,
  meta,
  update,
  out,
  cipher
}: {
  bytes: Uint8Array
  keys: KeyAgreementKey[]
  meta?: string
  update?: string
  out?: string
  cipher: Cipher
}): Promise<number> {
  const content = parseJson(bytes)
  if (content === null || typeof content !== 'object') {
    console.error('--document requires the input to be a JSON object.')
    return 2
  }

  let metaObject: Record<string, unknown> | undefined
  let fields
  try {
    metaObject =
      meta !== undefined
        ? parseJsonObjectOption({ value: meta, label: '--meta' })
        : undefined
    fields = await resolveEnvelopeFields({ keys, update })
  } catch (err) {
    console.error((err as Error).message)
    return 2
  }

  const { recipients, keyResolver } = cipher.createRecipients({
    keys: fields.encryptKeys
  })
  const payload = buildDocumentPayload({
    content: content as Record<string, unknown>,
    meta: metaObject
  })
  const jwe = await cipher.encryptObject({
    obj: payload,
    recipients,
    keyResolver
  })

  const envelope: IEncryptedDocument = {
    id: fields.id,
    sequence: fields.sequence,
    indexed: fields.indexed,
    jwe
  }
  await writeJsonOutput({ value: envelope, output: out })
  return 0
}

/**
 * The `--stream` branch of `runEncrypt`: encrypt the input as a chunked stream
 * and write a bundle directory whose `document.json` carries a
 * `stream: { sequence, chunks }` descriptor (its `content` is `{}`; the bytes
 * live in the chunk JWEs). Requires `-o/--out` (the bundle directory).
 *
 * @param options {object}
 * @param options.bytes {Uint8Array}
 * @param options.keys {KeyAgreementKey[]}
 * @param [options.meta] {string}
 * @param [options.update] {string}
 * @param [options.chunkSize] {number}
 * @param [options.out] {string}
 * @param options.cipher {Cipher}
 * @returns {Promise<number>}
 */
async function runEncryptStream({
  bytes,
  keys,
  meta,
  update,
  chunkSize,
  out,
  cipher
}: {
  bytes: Uint8Array
  keys: KeyAgreementKey[]
  meta?: string
  update?: string
  chunkSize?: number
  out?: string
  cipher: Cipher
}): Promise<number> {
  if (!out) {
    console.error('--stream requires -o/--out (the bundle directory to write).')
    return 2
  }

  let metaObject: Record<string, unknown> | undefined
  let fields
  try {
    metaObject =
      meta !== undefined
        ? parseJsonObjectOption({ value: meta, label: '--meta' })
        : undefined
    fields = await resolveEnvelopeFields({ keys, update })
  } catch (err) {
    console.error((err as Error).message)
    return 2
  }

  // The stream's encrypt transformer mutates its recipients array (it injects an
  // ephemeral key), so build a separate recipients set for the document jwe.
  const forChunks = cipher.createRecipients({ keys: fields.encryptKeys })
  const chunks = await encryptToChunks({
    cipher,
    data: bytes,
    recipients: forChunks.recipients,
    keyResolver: forChunks.keyResolver,
    chunkSize,
    sequence: fields.sequence
  })
  const stream = { sequence: fields.sequence, chunks: chunks.length }

  const payload: DocumentPayload = { content: {}, stream }
  if (metaObject) {
    payload.meta = metaObject
  }
  const forDocument = cipher.createRecipients({ keys: fields.encryptKeys })
  const jwe = await cipher.encryptObject({
    obj: payload,
    recipients: forDocument.recipients,
    keyResolver: forDocument.keyResolver
  })

  const envelope: IEncryptedDocument = {
    id: fields.id,
    sequence: fields.sequence,
    indexed: fields.indexed,
    stream,
    jwe
  }
  await writeDocumentBundle({ dir: out, document: envelope, chunks })
  console.error(
    `Wrote bundle ${out} (${chunks.length} chunk${chunks.length === 1 ? '' : 's'})`
  )
  return 0
}

/**
 * Decrypt a JWE or EDV Document from stdin or a file with a stored X25519 key.
 * An EDV Document envelope (`{ id, jwe, … }`) is detected automatically and its
 * `content` is emitted; `--document` forces that expectation (erroring on a bare
 * JWE), and a bare JWE is decrypted directly.
 *
 * @param options {object}
 * @param [options.file] {string}   Input `.jwe.json`/`.edvdoc.json` file; stdin
 *   when omitted.
 * @param [options.key] {string}   Secret-key ref; auto-selected when omitted.
 * @param [options.json] {boolean}   Parse plaintext as JSON (`decryptObject`).
 * @param [options.document] {boolean}   Require an EDV Document envelope.
 * @param [options.out] {string}   Output plaintext file; stdout when omitted.
 * @returns {Promise<number>}
 */
export async function runDecrypt({
  file,
  key,
  json,
  document,
  out
}: {
  file?: string
  key?: string
  json?: boolean
  document?: boolean
  out?: string
}): Promise<number> {
  // A bundle directory is a streamed EDV Document; reassemble its chunks.
  if (file && (await isDirectory(file))) {
    return runDecryptBundle({ dir: file, key, out })
  }

  const bytes = await readInputBytes({ file })
  const parsed = parseJson(bytes)
  if (parsed === null || typeof parsed !== 'object') {
    console.error('The input is not a valid JWE or EDV Document.')
    return 2
  }

  const envelope = isEncryptedDocument(parsed) ? parsed : undefined
  if (document && !envelope) {
    console.error('--document was given but the input is not an EDV Document.')
    return 2
  }
  // A document's payload (`{ content, meta }`) is always an object, so decrypt
  // it with object semantics regardless of `--json`; a bare JWE honors `--json`.
  const jwe = (envelope ? envelope.jwe : parsed) as IJWE
  const asObject = Boolean(envelope) || Boolean(json)

  let keyAgreementKey
  try {
    keyAgreementKey = await selectKeyAgreementKey({ key, jwe })
  } catch (err) {
    console.error((err as Error).message)
    return 2
  }

  const cipher = new Cipher()
  // A mismatched key throws ("no matching recipient"); a matched key whose
  // unwrap/decrypt fails returns null. Both are decryption failures, not
  // crashes, so report either as a clean non-zero exit.
  let result: object | Uint8Array | null
  try {
    result = asObject
      ? await cipher.decryptObject({ jwe, keyAgreementKey })
      : await cipher.decrypt({ jwe, keyAgreementKey })
  } catch {
    result = null
  }
  if (result === null) {
    console.error(
      'Decryption failed: the key does not match any recipient of this JWE.'
    )
    return 1
  }

  if (envelope) {
    const payload = result as DocumentPayload
    reportDocumentSidecars({ payload })
    await writeJsonOutput({ value: payload.content, output: out })
  } else if (asObject) {
    await writeJsonOutput({ value: result, output: out })
  } else {
    await writeBytesOutput({ bytes: result as Uint8Array, output: out })
  }
  return 0
}

/**
 * Load the decryption key: the `-k/--key` ref when given, otherwise the stored
 * key whose id matches a recipient of `jwe`.
 *
 * @param options {object}
 * @param [options.key] {string}
 * @param options.jwe {IJWE}
 * @returns {Promise<KeyAgreementKey>}
 */
async function selectKeyAgreementKey({
  key,
  jwe
}: {
  key?: string
  jwe: IJWE
}): Promise<KeyAgreementKey> {
  return key
    ? loadKeyAgreementKey({ ref: key })
    : autoSelectKeyAgreementKey({ jwe })
}

/**
 * Report a decrypted document's `meta` / `stream` on stderr (diagnostics that
 * accompany the `content` written to stdout).
 *
 * @param options {object}
 * @param options.payload {DocumentPayload}
 * @returns {void}
 */
function reportDocumentSidecars({
  payload
}: {
  payload: DocumentPayload
}): void {
  if (payload.meta !== undefined) {
    console.error(`meta: ${JSON.stringify(payload.meta)}`)
  }
  if (payload.stream !== undefined) {
    console.error(`stream: ${JSON.stringify(payload.stream)}`)
  }
}

/**
 * Decrypt a streamed EDV Document bundle directory: decrypt the document jwe for
 * its `content`/`meta`/`stream` (reported on stderr), then reassemble the chunk
 * JWEs into the original bytes, written to `-o`/stdout.
 *
 * @param options {object}
 * @param options.dir {string}   The bundle directory.
 * @param [options.key] {string}
 * @param [options.out] {string}
 * @returns {Promise<number>}
 */
async function runDecryptBundle({
  dir,
  key,
  out
}: {
  dir: string
  key?: string
  out?: string
}): Promise<number> {
  let document
  let chunks
  try {
    ;({ document, chunks } = await readDocumentBundle({ dir }))
  } catch (err) {
    console.error((err as Error).message)
    return 2
  }

  let keyAgreementKey
  try {
    keyAgreementKey = await selectKeyAgreementKey({ key, jwe: document.jwe })
  } catch (err) {
    console.error((err as Error).message)
    return 2
  }

  const cipher = new Cipher()
  let bytes: Uint8Array
  try {
    const payload = (await cipher.decryptObject({
      jwe: document.jwe,
      keyAgreementKey
    })) as DocumentPayload | null
    if (payload === null) {
      throw new Error('document jwe did not decrypt')
    }
    reportDocumentSidecars({ payload })
    bytes = await decryptChunks({ cipher, chunks, keyAgreementKey })
  } catch {
    console.error(
      'Decryption failed: the key does not match any recipient of this bundle.'
    )
    return 1
  }

  await writeBytesOutput({ bytes, output: out })
  return 0
}

export function makeEdvCommand(): Command {
  const edv = new Command('edv').description(
    'Encrypt and decrypt objects and files to X25519 recipients (raw JWE)'
  )

  edv
    .command('encrypt [file]')
    .description('Encrypt stdin or a file to one or more X25519 recipients')
    .option(
      '-r, --recipient <ref>',
      'an X25519 recipient: a publicKeyMultibase, a wallet key ' +
        'fingerprint/handle, or a DID / DID URL (repeatable)',
      collect,
      []
    )
    .option(
      '--recipient-file <path>',
      'a key-document JSON file holding an X25519 public key (repeatable)',
      collect,
      []
    )
    .option('--json', 'parse the input as JSON and encrypt it as an object')
    .option(
      '-d, --document',
      'emit a full EDV Document envelope { id, sequence, indexed, jwe }, ' +
        'encrypting the input as the document content'
    )
    .option(
      '-s, --stream',
      'emit a chunked-stream bundle directory (requires -o); the input is ' +
        'encrypted as fixed-size chunks'
    )
    .option(
      '--chunk-size <bytes>',
      'bytes per chunk for --stream (default 1 MiB)',
      parseChunkSize
    )
    .option(
      '--meta <json>',
      'a JSON meta object to store in the document (requires --document/--stream)'
    )
    .option(
      '--update <path>',
      'an existing EDV Document (file or bundle) to update: reuse its id, ' +
        'increment its sequence, and merge its recipients'
    )
    .option(
      '-o, --out <path>',
      'write the JWE/EDV Document to a file, or the --stream bundle to a ' +
        'directory (default: stdout)'
    )
    .action(
      async (
        file: string | undefined,
        options: {
          recipient: string[]
          recipientFile: string[]
          json?: boolean
          document?: boolean
          stream?: boolean
          chunkSize?: number
          meta?: string
          update?: string
          out?: string
        }
      ) => runAndExit(runEncrypt({ file, ...options }))
    )

  edv
    .command('decrypt [file]')
    .description(
      'Decrypt a JWE or EDV Document from stdin or a file with a stored ' +
        'X25519 key'
    )
    .option(
      '-k, --key <ref>',
      'the X25519 secret key to decrypt with (fingerprint or handle); ' +
        'auto-selected from the wallet when omitted'
    )
    .option(
      '--json',
      'parse the decrypted plaintext as JSON and pretty-print it'
    )
    .option(
      '-d, --document',
      'require an EDV Document envelope and emit its decrypted content'
    )
    .option(
      '-o, --out <file>',
      'write the plaintext to a file (default: stdout)'
    )
    .action(
      async (
        file: string | undefined,
        options: {
          key?: string
          json?: boolean
          document?: boolean
          out?: string
        }
      ) => runAndExit(runDecrypt({ file, ...options }))
    )

  return edv
}
