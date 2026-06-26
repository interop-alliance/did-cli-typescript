/**
 * `vc` command -- Verifiable Credential operations.
 *
 * `vc verify` reads a VC as JSON (from a file, an http(s) URL, or stdin) and
 * runs full verification (cryptographic signature, expiration,
 * revocation/status, and issuer registry recognition) via the verify adapter
 * over @interop/verifier-core. By default it prints the full verifier-core
 * result; `--summary` prints a compact flattened object. `vc issue` signs an
 * unsigned credential with a locally stored DID. `vc import` stores an
 * existing credential in local wallet storage (`~/.config/did-cli-wallet/credentials/`)
 * along with a `.meta.json` metadata sidecar (creation timestamp plus
 * `--handle` / `--description` when given); `vc issue --save` does the same
 * for a freshly issued credential. `list` renders a metadata table of the
 * saved credentials, `show` prints one back (`--meta` for its metadata),
 * `meta` edits the metadata sidecar, and `remove` deletes a stored
 * credential.
 *
 * Exit codes: 0 on success, 1 on a verification/issuance/import error, 2 on a
 * fetch/read/parse error or a malformed credential the verifier could not
 * structurally parse.
 */
import { createHash } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { Command } from 'commander'
import { issueCredential } from '../vc/issue.js'
import { loadKnownRegistries } from '../vc/registries.js'
import {
  findParseFailure,
  toSummary,
  verifyCredentialFully
} from '../vc/verify.js'
import {
  listCollection,
  loadFromCollection,
  loadMetaFromCollection,
  removeFromCollection,
  saveMetaToCollection,
  saveToCollection,
  sanitizeStorageId,
  type ItemMetadata
} from '../storage.js'
import {
  resolveCredentialRef,
  resolveDidRef,
  type StoredCredential
} from '../meta.js'
import { renderTable } from '../table.js'

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
 * Reads and parses the credential JSON from an http(s) URL or a file (when
 * given) or stdin. Logs to stderr and returns undefined on a fetch, read, or
 * parse error.
 *
 * @param source {string | undefined}   An http(s) URL or a path to read, or
 *   undefined for stdin.
 * @returns {Promise<object | undefined>}
 */
async function readCredentialJson(
  source: string | undefined
): Promise<object | undefined> {
  try {
    let raw: string
    if (source && /^https?:\/\//.test(source)) {
      const response = await fetch(source, {
        headers: { accept: 'application/json' }
      })
      if (!response.ok) {
        throw new Error(
          `GET ${source} returned ${response.status} ${response.statusText}`
        )
      }
      raw = await response.text()
    } else {
      raw = source ? await readFile(source, 'utf8') : await readStdin()
    }
    return JSON.parse(raw) as object
  } catch (err) {
    console.error(
      `Could not read credential: ${err instanceof Error ? err.message : String(err)}`
    )
    return
  }
}

/**
 * Derives a filesystem-safe storage id for a credential: its `id` when it has
 * one (a credential's `id` property is optional), otherwise a digest of its
 * JSON content -- deterministic, so re-importing the same id-less credential
 * overwrites rather than duplicates.
 *
 * @param options {object}
 * @param options.credential {StoredCredential}
 * @returns {string}
 */
export function credentialStorageId({
  credential
}: {
  credential: StoredCredential
}): string {
  if (credential.id) {
    return sanitizeStorageId(credential.id)
  }
  const digest = createHash('sha256')
    .update(JSON.stringify(credential))
    .digest('hex')
  return `sha256-${digest.slice(0, 24)}`
}

/**
 * Returns whether a parsed JSON object structurally looks like a Verifiable
 * Credential: its `type` includes `VerifiableCredential`.
 *
 * @param value {object}
 * @returns {boolean}
 */
function isCredential(value: object): value is StoredCredential {
  const type = (value as StoredCredential).type
  const types = Array.isArray(type) ? type : [type]
  return types.includes('VerifiableCredential')
}

/**
 * Build the human-readable type label shown in list/show output: the first
 * entry of the credential's `type` that is not the generic
 * `VerifiableCredential` (e.g. `OpenBadgeCredential`), falling back to
 * `VerifiableCredential` itself.
 *
 * @param options {object}
 * @param options.credential {StoredCredential}
 * @returns {string}
 */
function credentialTypeLabel({
  credential
}: {
  credential: StoredCredential
}): string {
  const types = Array.isArray(credential.type)
    ? credential.type
    : credential.type
      ? [credential.type]
      : []
  return types.find(type => type !== 'VerifiableCredential') ?? types[0] ?? ''
}

/**
 * Extract the issuer id of a credential, accommodating both the DID-string
 * and the embedded-object (`{ id, ... }`) forms of the `issuer` property.
 *
 * @param options {object}
 * @param options.credential {StoredCredential}
 * @returns {string}
 */
function credentialIssuerId({
  credential
}: {
  credential: StoredCredential
}): string {
  const issuer = credential.issuer
  return (typeof issuer === 'string' ? issuer : issuer?.id) ?? ''
}

/**
 * Save a credential to the wallet `credentials` collection together with its
 * `.meta.json` metadata sidecar (creation timestamp plus handle and
 * description when given). When the credential is already stored, its
 * existing metadata is preserved (and updated with the given handle /
 * description) rather than reset.
 *
 * @param options {object}
 * @param options.credential {StoredCredential}
 * @param [options.handle] {string}
 * @param [options.description] {string}
 * @returns {Promise<string>}   The credential file path.
 */
async function saveCredential({
  credential,
  handle,
  description
}: {
  credential: StoredCredential
  handle?: string
  description?: string
}): Promise<string> {
  const storageId = credentialStorageId({ credential })
  const existingMeta = await loadMetaFromCollection({
    collection: 'credentials',
    storageId
  })
  const filePath = await saveToCollection('credentials', storageId, credential)
  const meta: ItemMetadata = {
    created: new Date().toISOString(),
    ...existingMeta
  }
  if (handle) {
    meta.handle = handle
  }
  if (description) {
    meta.description = description
  }
  await saveMetaToCollection({ collection: 'credentials', storageId, meta })
  return filePath
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
 * @param options.did {string}   The id or metadata handle of the stored DID to
 *   issue (sign) with.
 * @param [options.key] {string}   The verification method id to use.
 * @param [options.suite] {string}   The signature suite to use.
 * @param [options.save] {boolean}   Save the issued credential to local
 *   wallet storage.
 * @param [options.handle] {string}   Short tag stored in the metadata sidecar.
 * @param [options.description] {string}   Longer description stored in the
 *   metadata sidecar.
 * @returns {Promise<number>}   The process exit code.
 */
export async function runIssue(
  file: string | undefined,
  options: {
    did: string
    key?: string
    suite?: string
    save?: boolean
    handle?: string
    description?: string
  }
): Promise<number> {
  const credential = await readCredentialJson(file)
  if (credential === undefined) {
    return 2
  }

  let did: string | undefined
  try {
    did = await resolveDidRef({ ref: options.did })
  } catch (err) {
    console.error((err as Error).message)
    return 1
  }
  if (!did) {
    console.error(`No locally stored DID found for ${options.did}`)
    return 1
  }

  try {
    const signed = await issueCredential({
      credential,
      did,
      keyId: options.key,
      suite: options.suite
    })
    if (options.save) {
      const filePath = await saveCredential({
        credential: signed as StoredCredential,
        handle: options.handle,
        description: options.description
      })
      console.error(`Credential saved to ${filePath}`)
    }
    console.log(JSON.stringify(signed, null, 2))
    return 0
  } catch (err) {
    console.error(
      `Could not issue credential: ${err instanceof Error ? err.message : String(err)}`
    )
    return 1
  }
}

/**
 * Reads a credential and stores it in local wallet storage, returning the
 * process exit code: `0` when imported, `1` when the input is not a
 * Verifiable Credential, and `2` on a fetch/read/parse error. Kept separate
 * from the command action so the exit-code logic is directly testable without
 * stubbing `process.exit`.
 *
 * @param source {string | undefined}   An http(s) URL or a path to read, or
 *   undefined for stdin.
 * @param options {object}
 * @param [options.handle] {string}   Short tag stored in the metadata sidecar.
 * @param [options.description] {string}   Longer description stored in the
 *   metadata sidecar.
 * @returns {Promise<number>}   The process exit code.
 */
export async function runImport(
  source: string | undefined,
  options: { handle?: string; description?: string }
): Promise<number> {
  const credential = await readCredentialJson(source)
  if (credential === undefined) {
    return 2
  }
  if (!isCredential(credential)) {
    console.error(
      'Input does not look like a Verifiable Credential ' +
        "(its 'type' does not include 'VerifiableCredential')"
    )
    return 1
  }
  const filePath = await saveCredential({
    credential,
    handle: options.handle,
    description: options.description
  })
  console.error(`Credential saved to ${filePath}`)
  return 0
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
    .requiredOption(
      '--did <did>',
      'id or handle of the stored DID to issue (sign) with'
    )
    .option(
      '--key <keyId>',
      'verification method id to use (default: first assertionMethod key)'
    )
    .option(
      '--suite <suite>',
      'signature suite (ed25519: eddsa-rdfc-2022 | Ed25519Signature2020; ' +
        'ecdsa: ecdsa-rdfc-2019); defaults to the signing key type'
    )
    .option(
      '--save',
      'save the issued credential to local wallet storage (~/.config/did-cli-wallet/credentials/)'
    )
    .option(
      '--handle <handle>',
      'short tag for the saved credential (requires --save)'
    )
    .option(
      '--description <description>',
      'longer description of the saved credential (requires --save)'
    )
    .action(
      async (
        file: string | undefined,
        options: {
          did: string
          key?: string
          suite?: string
          save?: boolean
          handle?: string
          description?: string
        }
      ) => {
        if (
          (options.handle !== undefined || options.description !== undefined) &&
          !options.save
        ) {
          console.error('--handle and --description require --save')
          process.exit(1)
          return
        }
        const code = await runIssue(file, options)
        if (code !== 0) {
          process.exit(code)
        }
      }
    )

  vc.command('import [source]')
    .description(
      'Import a Verifiable Credential (JSON from a file, an http(s) URL, or ' +
        'stdin) into local wallet storage (~/.config/did-cli-wallet/credentials/)'
    )
    .option('--handle <handle>', 'short tag for the saved credential')
    .option(
      '--description <description>',
      'longer description of the saved credential'
    )
    .action(
      async (
        source: string | undefined,
        options: { handle?: string; description?: string }
      ) => {
        const code = await runImport(source, options)
        if (code !== 0) {
          process.exit(code)
        }
      }
    )

  vc.command('list')
    .description('List locally stored credentials with their metadata')
    .option(
      '--json',
      'output the list as a JSON array of objects with metadata'
    )
    .option(
      '--plain',
      'output one credential id per line, sorted (no metadata)'
    )
    .action(async (options: { json?: boolean; plain?: boolean }) => {
      const storageIds = await listCollection('credentials')
      if (options.plain) {
        const credentialIds: string[] = []
        for (const storageId of storageIds) {
          const credential = await loadFromCollection<StoredCredential>(
            'credentials',
            storageId
          )
          // An id-less credential is listed by its storage id, which is how
          // `show` / `remove` address it.
          credentialIds.push(credential.id ?? storageId)
        }
        credentialIds.sort()
        for (const credentialId of credentialIds) {
          console.log(credentialId)
        }
        return
      }

      const entries: ({
        id: string
        type: string
        issuer: string
      } & ItemMetadata)[] = []
      for (const storageId of storageIds) {
        const credential = await loadFromCollection<StoredCredential>(
          'credentials',
          storageId
        )
        const meta = await loadMetaFromCollection({
          collection: 'credentials',
          storageId
        })
        entries.push({
          id: credential.id ?? storageId,
          type: credentialTypeLabel({ credential }),
          issuer: credentialIssuerId({ credential }),
          ...meta
        })
      }

      if (options.json) {
        const output = entries.map(entry => ({
          id: entry.id,
          type: entry.type,
          issuer: entry.issuer,
          ...(entry.created && { created: entry.created }),
          ...(entry.handle && { handle: entry.handle }),
          ...(entry.description && { description: entry.description })
        }))
        console.log(JSON.stringify(output, null, 2))
        return
      }

      if (entries.length === 0) {
        return
      }
      const rows = entries.map(entry => [
        entry.handle ?? '',
        entry.type,
        entry.issuer,
        entry.created?.slice(0, 10) ?? '',
        entry.id,
        entry.description ?? ''
      ])
      console.log(
        renderTable({
          columns: [
            { header: 'HANDLE', maxWidth: 16 },
            { header: 'TYPE', maxWidth: 24 },
            { header: 'ISSUER', maxWidth: 28 },
            { header: 'CREATED' },
            { header: 'ID', maxWidth: 44 },
            { header: 'DESCRIPTION', maxWidth: 40 }
          ],
          rows
        })
      )
    })

  vc.command('show <id>')
    .aliases(['view', 'cat'])
    .description(
      'Show a locally stored credential by its credential id or metadata handle'
    )
    .option('--meta', 'show the credential metadata instead of the credential')
    .option('--json', 'with --meta, output the metadata as JSON')
    .action(async (id: string, options: { meta?: boolean; json?: boolean }) => {
      let resolved
      try {
        resolved = await resolveCredentialRef({ ref: id })
      } catch (err) {
        console.error((err as Error).message)
        process.exit(1)
        return
      }
      if (!resolved) {
        console.error(`No locally stored credential found for ${id}`)
        process.exit(1)
        return
      }

      if (options.meta) {
        const credentialId = resolved.credential.id ?? resolved.storageId
        const type = credentialTypeLabel({ credential: resolved.credential })
        const issuer = credentialIssuerId({ credential: resolved.credential })
        const validFrom =
          resolved.credential.validFrom ?? resolved.credential.issuanceDate
        const expires =
          resolved.credential.validUntil ?? resolved.credential.expirationDate
        if (options.json) {
          const output = {
            id: credentialId,
            type,
            ...(resolved.meta?.created && { created: resolved.meta.created }),
            ...(resolved.meta?.handle && { handle: resolved.meta.handle }),
            ...(resolved.meta?.description && {
              description: resolved.meta.description
            }),
            ...(issuer && { issuer }),
            ...(validFrom && { validFrom }),
            ...(expires && { expires })
          }
          console.log(JSON.stringify(output, null, 2))
          return
        }
        const rows = [
          ['ID', credentialId],
          ['Type', type],
          ['Handle', resolved.meta?.handle ?? ''],
          ['Created', resolved.meta?.created ?? ''],
          ['Description', resolved.meta?.description ?? ''],
          ['Issuer', issuer],
          ['Valid From', validFrom ?? ''],
          ['Expires', expires ?? '']
        ]
        console.log(
          renderTable({
            columns: [{ header: 'FIELD' }, { header: 'VALUE' }],
            rows
          })
        )
        return
      }

      // A stored credential holds no secret material (its proof is public),
      // so it is safe to print as-is.
      console.log(JSON.stringify(resolved.credential, null, 2))
    })

  vc.command('meta <id>')
    .description(
      'Show or edit the metadata of a locally stored credential (by ' +
        'credential id or handle); with no options, prints the current metadata'
    )
    .option('--handle <handle>', 'set the handle (an empty string clears it)')
    .option(
      '--description <description>',
      'set the description (an empty string clears it)'
    )
    .action(
      async (
        id: string,
        options: { handle?: string; description?: string }
      ) => {
        let resolved
        try {
          resolved = await resolveCredentialRef({ ref: id })
        } catch (err) {
          console.error((err as Error).message)
          process.exit(1)
          return
        }
        if (!resolved) {
          console.error(`No locally stored credential found for ${id}`)
          process.exit(1)
          return
        }

        const hasEdits =
          options.handle !== undefined || options.description !== undefined
        if (!hasEdits) {
          console.log(JSON.stringify(resolved.meta ?? {}, null, 2))
          return
        }

        const meta: ItemMetadata = { ...(resolved.meta ?? {}) }
        if (options.handle !== undefined) {
          if (options.handle === '') {
            delete meta.handle
          } else {
            meta.handle = options.handle
          }
        }
        if (options.description !== undefined) {
          if (options.description === '') {
            delete meta.description
          } else {
            meta.description = options.description
          }
        }
        const filePath = await saveMetaToCollection({
          collection: 'credentials',
          storageId: resolved.storageId,
          meta
        })
        console.error(`Metadata saved to ${filePath}`)
        console.log(JSON.stringify(meta, null, 2))
      }
    )

  vc.command('remove <id>')
    .aliases(['delete', 'rm'])
    .description(
      'Remove a locally stored credential and its metadata sidecar (by ' +
        'credential id or handle)'
    )
    .action(async (id: string) => {
      let resolved
      try {
        resolved = await resolveCredentialRef({ ref: id })
      } catch (err) {
        console.error((err as Error).message)
        process.exit(1)
        return
      }
      if (!resolved) {
        console.error(`No locally stored credential found for ${id}`)
        process.exit(1)
        return
      }
      const removed = await removeFromCollection({
        collection: 'credentials',
        storageId: resolved.storageId
      })
      for (const filePath of removed) {
        console.error(`Removed ${filePath}`)
      }
    })

  return vc
}
