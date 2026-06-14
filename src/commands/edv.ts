/**
 * `edv` command -- encrypt to and decrypt from X25519 recipients using the
 * EDV / minimal-cipher serialization.
 *
 * Layer 1: the encrypt output is a single raw JWE (the `jwe` field of an EDV
 * Document), printed as JSON to stdout or written to an `-o` file (convention:
 * `*.jwe.json`); decrypt reverses it. Public-key (key-agreement) encryption
 * only: recipients are one or more X25519 public keys, given as a raw
 * `publicKeyMultibase`, a wallet key fingerprint/handle, a DID / DID URL, or a
 * key-document JSON file. The full EDV Document envelope, chunked streams, and
 * HMAC-blinded indexing are Layer 2.
 *
 * Data goes to stdout, diagnostics to stderr. Exit codes: 0 success, 1
 * decryption failure (wrong key / not a recipient), 2 input error (no
 * recipient, unresolvable recipient/key, malformed input).
 */
import { Command } from 'commander'
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
 * Encrypt stdin or a file to one or more X25519 recipients. By default emits a
 * raw JWE (Layer 1); with `--document` it wraps the JWE in an EDV Document
 * envelope `{ id, sequence, indexed, jwe }`, encrypting the input as the
 * document's `content`.
 *
 * @param options {object}
 * @param [options.file] {string}   Input file; stdin when omitted.
 * @param options.recipient {string[]}   Recipient refs (`--recipient`).
 * @param options.recipientFile {string[]}   Key-document files.
 * @param [options.json] {boolean}   Parse input as JSON (`encryptObject`).
 * @param [options.document] {boolean}   Emit a full EDV Document envelope.
 * @param [options.meta] {string}   JSON `meta` object for the document.
 * @param [options.update] {string}   Existing `.edvdoc.json` to update: reuse
 *   its `id`, increment `sequence`, and merge its recipients.
 * @param [options.out] {string}   Output file; stdout when omitted.
 * @returns {Promise<number>}
 */
export async function runEncrypt({
  file,
  recipient,
  recipientFile,
  json,
  document,
  meta,
  update,
  out
}: {
  file?: string
  recipient: string[]
  recipientFile: string[]
  json?: boolean
  document?: boolean
  meta?: string
  update?: string
  out?: string
}): Promise<number> {
  if (!document && (meta !== undefined || update !== undefined)) {
    console.error('--meta and --update require --document.')
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
  if (meta !== undefined) {
    let parsedMeta: unknown
    try {
      parsedMeta = JSON.parse(meta)
    } catch {
      console.error('--meta is not valid JSON.')
      return 2
    }
    if (parsedMeta === null || typeof parsedMeta !== 'object') {
      console.error('--meta must be a JSON object.')
      return 2
    }
    metaObject = parsedMeta as Record<string, unknown>
  }

  let id: string
  let sequence: number
  let indexed: IEncryptedDocument['indexed']
  let encryptKeys = keys
  if (update !== undefined) {
    const parsed = parseJson(await readInputBytes({ file: update }))
    if (!isEncryptedDocument(parsed)) {
      console.error(`--update target "${update}" is not an EDV Document.`)
      return 2
    }
    id = parsed.id
    sequence = parsed.sequence + 1
    indexed = parsed.indexed ?? []
    try {
      encryptKeys = await mergeUpdateRecipients({ keys, existing: parsed })
    } catch (err) {
      console.error((err as Error).message)
      return 2
    }
  } else {
    id = await generateDocumentId()
    sequence = 0
    indexed = []
  }

  const { recipients, keyResolver } = cipher.createRecipients({
    keys: encryptKeys
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

  const envelope: IEncryptedDocument = { id, sequence, indexed, jwe }
  await writeJsonOutput({ value: envelope, output: out })
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
    keyAgreementKey = key
      ? await loadKeyAgreementKey({ ref: key })
      : await autoSelectKeyAgreementKey({ jwe })
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
    if (payload.meta !== undefined) {
      console.error(`meta: ${JSON.stringify(payload.meta)}`)
    }
    if (payload.stream !== undefined) {
      console.error(`stream: ${JSON.stringify(payload.stream)}`)
    }
    await writeJsonOutput({ value: payload.content, output: out })
  } else if (asObject) {
    await writeJsonOutput({ value: result, output: out })
  } else {
    await writeBytesOutput({ bytes: result as Uint8Array, output: out })
  }
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
      '--meta <json>',
      'a JSON meta object to store in the document (requires --document)'
    )
    .option(
      '--update <file>',
      'an existing EDV Document to update: reuse its id, increment its ' +
        'sequence, and merge its recipients (requires --document)'
    )
    .option(
      '-o, --out <file>',
      'write the JWE or EDV Document to a file (default: stdout)'
    )
    .action(
      async (
        file: string | undefined,
        options: {
          recipient: string[]
          recipientFile: string[]
          json?: boolean
          document?: boolean
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
