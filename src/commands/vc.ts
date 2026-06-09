/**
 * `vc` command -- Verifiable Credential operations.
 *
 * Phase 1 implements `vc verify`, which reads a VC as JSON from stdin or a
 * file argument and runs full verification (cryptographic signature,
 * expiration, revocation/status, and issuer registry recognition) via the
 * verify adapter over @interop/verifier-core. By default it prints the full
 * verifier-core result; `--summary` prints a compact flattened object.
 *
 * Exit codes: 0 when verified, 1 when not verified, 2 on a read/parse error or
 * a malformed credential the verifier could not structurally parse.
 */
import { readFile } from 'node:fs/promises'
import { Command } from 'commander'
import { issueCredential } from '../vc/issue.js'
import { loadKnownRegistries } from '../vc/registries.js'
import {
  findParseFailure,
  toSummary,
  verifyCredentialFully
} from '../vc/verify.js'

/**
 * Reads all of stdin to a string. Used when no file argument is given.
 *
 * @returns {Promise<string>}
 */
async function readStdin(): Promise<string> {
  const chunks: Buffer[] = []
  for await (const chunk of process.stdin) {
    chunks.push(chunk as Buffer)
  }
  return Buffer.concat(chunks).toString('utf8')
}

/**
 * Reads and parses the credential JSON from a file (when given) or stdin.
 * Logs to stderr and returns undefined on a read or parse error.
 *
 * @param file {string | undefined}   Path to read, or undefined for stdin.
 * @returns {Promise<object | undefined>}
 */
async function readCredentialJson(
  file: string | undefined
): Promise<object | undefined> {
  try {
    const raw = file ? await readFile(file, 'utf8') : await readStdin()
    return JSON.parse(raw) as object
  } catch (err) {
    console.error(
      `Could not read credential: ${err instanceof Error ? err.message : String(err)}`
    )
    return
  }
}

/**
 * Reads, verifies, and prints a credential, returning the process exit code:
 * `0` when verified, `1` when not verified, and `2` on a read/parse error or a
 * structurally malformed credential. Kept separate from the command action so
 * the exit-code logic is directly testable without stubbing `process.exit`.
 *
 * @param file {string | undefined}   Path to read, or undefined for stdin.
 * @param options {object}
 * @param [options.summary] {boolean}   Print the compact summary instead of the
 *   full verifier-core result.
 * @returns {Promise<number>}   The process exit code.
 */
export async function runVerify(
  file: string | undefined,
  options: { summary?: boolean }
): Promise<number> {
  const credential = await readCredentialJson(file)
  if (credential === undefined) {
    return 2
  }

  const registries = await loadKnownRegistries()
  const result = await verifyCredentialFully({ credential, registries })

  const output = options.summary ? toSummary(result) : result
  console.log(JSON.stringify(output, null, 2))

  if (findParseFailure(result)) {
    return 2
  }
  return result.verified ? 0 : 1
}

/**
 * Reads, issues (signs), and prints a credential, returning the process exit
 * code: `0` when issued, `1` on an issuance error (an unauthorized key, a
 * missing DID or key file, an unknown suite, an issuer that does not match the
 * signing DID, or a signing failure), and `2` on a read/parse error. Kept
 * separate from the command action so the exit-code logic is directly testable
 * without stubbing `process.exit`.
 *
 * @param file {string | undefined}   Path to read, or undefined for stdin.
 * @param options {object}
 * @param options.did {string}   The id of the stored DID to issue (sign) with.
 * @param [options.key] {string}   The verification method id to use.
 * @param [options.suite] {string}   The signature suite to use.
 * @returns {Promise<number>}   The process exit code.
 */
export async function runIssue(
  file: string | undefined,
  options: { did: string; key?: string; suite?: string }
): Promise<number> {
  const credential = await readCredentialJson(file)
  if (credential === undefined) {
    return 2
  }

  try {
    const signed = await issueCredential({
      credential,
      did: options.did,
      keyId: options.key,
      suite: options.suite
    })
    console.log(JSON.stringify(signed, null, 2))
    return 0
  } catch (err) {
    console.error(
      `Could not issue credential: ${err instanceof Error ? err.message : String(err)}`
    )
    return 1
  }
}

export function makeVcCommand(): Command {
  const vc = new Command('vc').description('Manage Verifiable Credentials')

  vc.command('verify [file]')
    .description('Verify a Verifiable Credential (JSON from a file or stdin)')
    .option('--summary', 'print a compact summary instead of the full result')
    .action(
      async (file: string | undefined, options: { summary?: boolean }) => {
        const code = await runVerify(file, options)
        if (code !== 0) {
          process.exit(code)
        }
      }
    )

  vc.command('issue [file]')
    .description(
      'Issue (sign) an unsigned Verifiable Credential (JSON from a file or stdin)'
    )
    .requiredOption('--did <did>', 'id of the stored DID to issue (sign) with')
    .option(
      '--key <keyId>',
      'verification method id to use (default: first assertionMethod key)'
    )
    .option(
      '--suite <suite>',
      'signature suite (ed25519: eddsa-rdfc-2022 | Ed25519Signature2020; ' +
        'ecdsa: ecdsa-rdfc-2019); defaults to the signing key type'
    )
    .action(
      async (
        file: string | undefined,
        options: { did: string; key?: string; suite?: string }
      ) => {
        const code = await runIssue(file, options)
        if (code !== 0) {
          process.exit(code)
        }
      }
    )

  return vc
}
