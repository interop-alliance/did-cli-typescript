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
import { readInputBytes, writeBytesOutput, writeJsonOutput } from '../was/io.js'
import { runAndExit } from './was/shared.js'
import {
  autoSelectKeyAgreementKey,
  loadKeyAgreementKey,
  resolveRecipient,
  resolveRecipientFile,
  type KeyAgreementKey
} from '../edv/recipients.js'

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
 * Encrypt stdin or a file to one or more X25519 recipients and emit a raw JWE.
 *
 * @param options {object}
 * @param [options.file] {string}   Input file; stdin when omitted.
 * @param options.recipient {string[]}   Recipient refs (`--recipient`).
 * @param options.recipientFile {string[]}   Key-document files.
 * @param [options.json] {boolean}   Parse input as JSON (`encryptObject`).
 * @param [options.out] {string}   Output JWE file; stdout when omitted.
 * @returns {Promise<number>}
 */
export async function runEncrypt({
  file,
  recipient,
  recipientFile,
  json,
  out
}: {
  file?: string
  recipient: string[]
  recipientFile: string[]
  json?: boolean
  out?: string
}): Promise<number> {
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
  const { recipients, keyResolver } = cipher.createRecipients({ keys })

  let jwe
  if (json) {
    let obj: object
    try {
      obj = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes))
    } catch {
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
 * Decrypt a JWE from stdin or a file with a stored X25519 key.
 *
 * @param options {object}
 * @param [options.file] {string}   Input `.jwe.json` file; stdin when omitted.
 * @param [options.key] {string}   Secret-key ref; auto-selected when omitted.
 * @param [options.json] {boolean}   Parse plaintext as JSON (`decryptObject`).
 * @param [options.out] {string}   Output plaintext file; stdout when omitted.
 * @returns {Promise<number>}
 */
export async function runDecrypt({
  file,
  key,
  json,
  out
}: {
  file?: string
  key?: string
  json?: boolean
  out?: string
}): Promise<number> {
  const bytes = await readInputBytes({ file })
  let jwe
  try {
    jwe = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes))
  } catch {
    console.error('The input is not a valid JWE JSON document.')
    return 2
  }

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
    result = json
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

  if (json) {
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
    .option('-o, --out <file>', 'write the JWE to a file (default: stdout)')
    .action(
      async (
        file: string | undefined,
        options: {
          recipient: string[]
          recipientFile: string[]
          json?: boolean
          out?: string
        }
      ) => runAndExit(runEncrypt({ file, ...options }))
    )

  edv
    .command('decrypt [file]')
    .description('Decrypt a JWE from stdin or a file with a stored X25519 key')
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
      '-o, --out <file>',
      'write the plaintext to a file (default: stdout)'
    )
    .action(
      async (
        file: string | undefined,
        options: { key?: string; json?: boolean; out?: string }
      ) => runAndExit(runDecrypt({ file, ...options }))
    )

  return edv
}
