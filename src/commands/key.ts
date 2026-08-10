/**
 * `key` command -- create and manage cryptographic keys in local wallet storage.
 *
 * `key create` generates a key pair of the requested `--type` (ed25519, ecdsa,
 * x25519, or hmac) and prints the exported key object to stdout; `--save` writes
 * it to local wallet storage (`~/.config/did-cli-wallet/keys/`) along with a
 * `.meta.json` metadata sidecar (creation timestamp plus `--handle` /
 * `--description` when given), and `--with-seed` includes the secret key seed in
 * the output. `list` renders a metadata table of the saved keys (with the DIDs
 * each key participates in, re-derived from the stored DID documents), `show`
 * prints one key's public object back (`--meta` for its metadata), `meta` edits
 * the metadata sidecar, and `remove` deletes a stored key; `export` remains a
 * stub. Keys are referenced by their `publicKeyMultibase` fingerprint or by a
 * metadata handle. Data goes to stdout, diagnostics and errors to stderr.
 */
import { createHash, randomBytes } from 'node:crypto'
import { Command } from 'commander'
import { IdEncoder } from '@digitalcredentials/bnid'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'
import * as EcdsaMultikey from '@interop/ecdsa-multikey'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import { SHA256HMACKey } from '@interop/data-integrity-core'
import {
  saveMetaToCollection,
  saveToCollection,
  type KeyMetadata
} from '../storage.js'
import {
  mapFingerprintsToDids,
  parseKeyStorageId,
  resolveKeyRef
} from '../meta.js'
import { renderTable, truncateMiddle } from '../table.js'
import {
  isEcdsaPublicKeyMultibase,
  normalizeEcdsaCurve,
  SUPPORTED_ECDSA_CURVES,
  warnIfNotVcIssuanceCapable
} from '../keys/ecdsa.js'
import { deriveSeed } from '../keys/seed.js'
import { runAndExit } from './was/shared.js'
import {
  applyMetaEdits,
  requireSaveForMetaFlags,
  resolveRefOrReport,
  runListCollection,
  runRemoveCollection,
  writeCreateMeta
} from './collection-command.js'

/** The wallet collection name for stored keys. */
const COLLECTION = 'keys'

/**
 * The Multikey header for an AES-256 symmetric key (`0xa2 0x01`, the multicodec
 * varint for `aes-256`), prefixed before the 32 raw key bytes in a KEK's
 * `secretKeyMultibase`.
 */
const AES_256_MULTIKEY_HEADER = Buffer.from([0xa2, 0x01])

/**
 * Build the human-readable key type label shown in list/show output, e.g.
 * `ed25519` or `ecdsa-p256`, from a parsed key storage ID.
 *
 * @param options {object}
 * @param [options.type] {string}
 * @param [options.curve] {string}
 * @returns {string}
 */
function keyTypeLabel({
  type,
  curve
}: {
  type?: string
  curve?: string
}): string {
  if (!type) {
    return ''
  }
  return curve ? `${type}-${curve}` : type
}

/**
 * Render the DIDS cell of the key list table: the first associated DID
 * (middle-truncated), with a `(+N)` suffix when the key appears in more.
 *
 * @param options {object}
 * @param options.dids {string[]}
 * @returns {string}
 */
function didsCell({ dids }: { dids: string[] }): string {
  if (dids.length === 0) {
    return ''
  }
  const first = truncateMiddle({ value: dids[0], maxWidth: 38 })
  return dids.length > 1 ? `${first} (+${dids.length - 1})` : first
}

/**
 * Generates a key pair of the requested type, optionally saving it to the
 * wallet, and prints the key (or the seed-wrapped form) to stdout.
 *
 * @param options {object}
 * @param options.type {string}   Key type: ed25519, ecdsa, x25519, hmac, or
 *   aes256.
 * @param options.curve {string}   ECDSA curve, for --type ecdsa.
 * @param [options.save] {boolean}   Save the key to wallet storage.
 * @param [options.handle] {string}   Short tag stored in the metadata sidecar.
 * @param [options.description] {string}   Longer description for the sidecar.
 * @param [options.withSeed] {boolean}   Include/derive the secret key seed
 *   (ed25519 only).
 * @returns {Promise<number>}   The process exit code.
 */
export async function runCreate(options: {
  type: string
  curve: string
  save?: boolean
  handle?: string
  description?: string
  withSeed?: boolean
}): Promise<number> {
  if (!requireSaveForMetaFlags(options)) {
    return 1
  }
  switch (options.type) {
    case 'ed25519': {
      const { secretKeySeed, seedBytes } = await deriveSeed({
        withSeed: options.withSeed
      })
      const keyPair = await Ed25519VerificationKey.generate({
        seed: seedBytes
      })
      const exported = await keyPair.export({
        publicKey: true,
        secretKey: true
      })
      if (options.save) {
        const now = new Date()
        const date = now.toISOString().slice(0, 10)
        const rawId = exported.id ?? keyPair.publicKeyMultibase
        const storageId = `${date}-${options.type}-${rawId}`.replaceAll(
          ':',
          '_'
        )
        const filePath = await saveToCollection({
          collection: 'keys',
          storageId,
          data: exported
        })
        await writeCreateMeta({
          collection: COLLECTION,
          storageId,
          created: now.toISOString(),
          handle: options.handle,
          description: options.description
        })
        console.error(`Key saved to ${filePath}`)
      }
      const output = options.withSeed
        ? { secretKeySeed, keyPair: exported }
        : exported
      console.log(JSON.stringify(output, null, 2))
      return 0
    }
    case 'ecdsa': {
      if (options.withSeed) {
        console.error(
          '--with-seed is not supported for ecdsa keys; ECDSA key ' +
            'generation is non-deterministic and cannot be derived ' +
            'from a seed.'
        )
        return 1
      }
      const curve = normalizeEcdsaCurve({ curve: options.curve })
      if (!curve) {
        console.error(
          `Unknown ecdsa curve: ${options.curve}. ` +
            `Supported: ${SUPPORTED_ECDSA_CURVES}`
        )
        return 1
      }
      warnIfNotVcIssuanceCapable({ curve })
      const keyPair = await EcdsaMultikey.generate({ curve })
      const exported = await keyPair.export({
        publicKey: true,
        secretKey: true
      })
      if (options.save) {
        const now = new Date()
        const date = now.toISOString().slice(0, 10)
        const rawId = exported.id ?? exported.publicKeyMultibase
        const curveLabel = curve.replace('-', '').toLowerCase()
        const storageId = `${date}-ecdsa-${curveLabel}-${rawId}`.replaceAll(
          ':',
          '_'
        )
        const filePath = await saveToCollection({
          collection: 'keys',
          storageId,
          data: exported
        })
        await writeCreateMeta({
          collection: COLLECTION,
          storageId,
          created: now.toISOString(),
          handle: options.handle,
          description: options.description
        })
        console.error(`Key saved to ${filePath}`)
      }
      console.log(JSON.stringify(exported, null, 2))
      return 0
    }
    case 'x25519': {
      if (options.withSeed) {
        console.error(
          '--with-seed is not supported for x25519 keys; X25519 key ' +
            'generation is non-deterministic and cannot be derived ' +
            'from a seed.'
        )
        return 1
      }
      const keyPair = await X25519KeyAgreementKey2020.generate()
      const exported = await keyPair.export({
        publicKey: true,
        privateKey: true
      })
      if (options.save) {
        const now = new Date()
        const date = now.toISOString().slice(0, 10)
        const rawId = exported.id ?? exported.publicKeyMultibase
        const storageId = `${date}-x25519-${rawId}`.replaceAll(':', '_')
        const filePath = await saveToCollection({
          collection: 'keys',
          storageId,
          data: exported
        })
        await writeCreateMeta({
          collection: COLLECTION,
          storageId,
          created: now.toISOString(),
          handle: options.handle,
          description: options.description
        })
        console.error(`Key saved to ${filePath}`)
      }
      console.log(JSON.stringify(exported, null, 2))
      return 0
    }
    case 'hmac': {
      if (options.withSeed) {
        console.error(
          '--with-seed is not supported for hmac keys; HMAC key ' +
            'generation is non-deterministic and cannot be derived ' +
            'from a seed.'
        )
        return 1
      }
      const hmac = await SHA256HMACKey.generate()
      const exported = await hmac.export({ secretKey: true })
      if (options.save) {
        const now = new Date()
        const date = now.toISOString().slice(0, 10)
        const storageId = `${date}-hmac-${exported.id}`.replaceAll(':', '_')
        const filePath = await saveToCollection({
          collection: 'keys',
          storageId,
          data: exported
        })
        await writeCreateMeta({
          collection: COLLECTION,
          storageId,
          created: now.toISOString(),
          handle: options.handle,
          description: options.description
        })
        console.error(`Key saved to ${filePath}`)
      }
      console.log(JSON.stringify(exported, null, 2))
      return 0
    }
    case 'aes256': {
      if (options.withSeed) {
        console.error(
          '--with-seed is not supported for aes256 keys; an AES-256 KEK is ' +
            'always generated from fresh random bytes, never derived from a ' +
            'seed.'
        )
        return 1
      }
      // 32 random key bytes prefixed with the AES-256 Multikey header, encoded
      // as base58btc multibase -- a symmetric Multikey `secretKeyMultibase`.
      const keyBytes = randomBytes(32)
      const secretKeyMultibase = new IdEncoder({
        encoding: 'base58',
        multibase: true
      }).encode(Buffer.concat([AES_256_MULTIKEY_HEADER, keyBytes]))
      // The id is derived from the RAW 32 key bytes (header excluded), matching
      // the KEK id a Wallet Attached Storage server derives from the same value.
      const id = `urn:kek:sha256:${createHash('sha256')
        .update(keyBytes)
        .digest('hex')}`
      const exported = { id, type: 'Multikey', secretKeyMultibase }
      if (options.save) {
        const now = new Date()
        const date = now.toISOString().slice(0, 10)
        const storageId = `${date}-aes256-${id}`.replaceAll(':', '_')
        const filePath = await saveToCollection({
          collection: 'keys',
          storageId,
          data: exported
        })
        await writeCreateMeta({
          collection: COLLECTION,
          storageId,
          created: now.toISOString(),
          handle: options.handle,
          description: options.description
        })
        console.error(`Key saved to ${filePath}`)
      }
      console.log(JSON.stringify(exported, null, 2))
      return 0
    }
    default:
      console.error(
        `Unknown key type: ${options.type}. ` +
          'Supported: ed25519, ecdsa, x25519, hmac, aes256'
      )
      return 1
  }
}

/**
 * Lists locally stored keys with their metadata: one fingerprint per line with
 * `--plain`, a JSON array with `--json`, otherwise a column-aligned table.
 *
 * @param options {object}
 * @param [options.json] {boolean}   Output a JSON array of objects.
 * @param [options.plain] {boolean}   Output one fingerprint per line, sorted.
 * @returns {Promise<number>}   The process exit code.
 */
export async function runList(options: {
  json?: boolean
  plain?: boolean
}): Promise<number> {
  // The key-to-DID associations (one pass over all stored DID documents) are
  // only needed for the table/JSON output, so derive them lazily and once.
  let fingerprintDidsCache: Map<string, string[]> | undefined
  const fingerprintDids = async (): Promise<Map<string, string[]>> =>
    (fingerprintDidsCache ??= await mapFingerprintsToDids())

  return runListCollection<
    { id?: string; publicKeyMultibase?: string },
    {
      fingerprint: string
      storageId: string
      type?: string
      curve?: string
      created?: string
      handle?: string
      description?: string
      dids: string[]
    }
  >({
    collection: COLLECTION,
    plain: options.plain,
    json: options.json,
    plainId: key => key.publicKeyMultibase,
    // Storage IDs carry a YYYY-MM-DD prefix, so the listing order is
    // chronological.
    toEntry: async ({ storageId, item, meta }) => {
      // Asymmetric keys are identified by their publicKeyMultibase
      // fingerprint; an HMAC key has no public half, so fall back to its id.
      const fingerprint = item.publicKeyMultibase ?? item.id
      if (!fingerprint) {
        return undefined
      }
      const parsed = parseKeyStorageId({ storageId })
      return {
        fingerprint,
        storageId,
        type: parsed.type,
        curve: parsed.curve,
        created: meta?.created ?? parsed.date,
        handle: meta?.handle,
        description: meta?.description,
        dids: (await fingerprintDids()).get(fingerprint) ?? []
      }
    },
    toJson: entry => ({
      fingerprint: entry.fingerprint,
      storageId: entry.storageId,
      ...(entry.type && { type: entry.type }),
      ...(entry.curve && { curve: entry.curve }),
      ...(entry.created && { created: entry.created }),
      ...(entry.handle && { handle: entry.handle }),
      ...(entry.description && { description: entry.description }),
      dids: entry.dids
    }),
    columns: [
      { header: 'HANDLE', maxWidth: 16 },
      { header: 'TYPE' },
      { header: 'CREATED' },
      { header: 'FINGERPRINT', maxWidth: 28 },
      { header: 'DIDS' },
      { header: 'DESCRIPTION', maxWidth: 40 }
    ],
    toRow: entry => [
      entry.handle ?? '',
      keyTypeLabel({ type: entry.type, curve: entry.curve }),
      entry.created?.slice(0, 10) ?? '',
      entry.fingerprint,
      didsCell({ dids: entry.dids }),
      entry.description ?? ''
    ]
  })
}

/**
 * Shows a locally stored key (its public key object, or its metadata with
 * `--meta`), resolved by fingerprint or handle.
 *
 * @param options {object}
 * @param options.id {string}   The publicKeyMultibase fingerprint or handle.
 * @param [options.meta] {boolean}   Show the metadata instead of the key.
 * @param [options.json] {boolean}   With --meta, output the metadata as JSON.
 * @returns {Promise<number>}   The process exit code.
 */
export async function runShow(options: {
  id: string
  meta?: boolean
  json?: boolean
}): Promise<number> {
  const { id } = options
  const resolved = await resolveRefOrReport({
    resolve: ref => resolveKeyRef({ ref }),
    ref: id,
    noun: 'key'
  })
  if (!resolved) {
    return 1
  }
  // An HMAC key has no public fingerprint, so fall back to its id.
  const fingerprint = resolved.key.publicKeyMultibase ?? resolved.key.id
  if (!fingerprint) {
    console.error(`No locally stored key found for ${id}`)
    return 1
  }
  const storedKey = resolved.key

  if (options.meta) {
    const parsed = parseKeyStorageId({ storageId: resolved.storageId })
    const created = resolved.meta?.created ?? parsed.date
    // The displayed DIDs are always derived from the stored DID documents,
    // never the cached meta.dids, so they cannot be stale.
    const dids = (await mapFingerprintsToDids()).get(fingerprint) ?? []
    if (options.json) {
      const output = {
        fingerprint,
        storageId: resolved.storageId,
        ...(parsed.type && { type: parsed.type }),
        ...(parsed.curve && { curve: parsed.curve }),
        ...(created && { created }),
        ...(resolved.meta?.handle && { handle: resolved.meta.handle }),
        ...(resolved.meta?.description && {
          description: resolved.meta.description
        }),
        dids
      }
      console.log(JSON.stringify(output, null, 2))
      return 0
    }
    const rows = [
      ['Fingerprint', fingerprint],
      ['Type', parsed.type ?? ''],
      ...(parsed.curve ? [['Curve', parsed.curve]] : []),
      ['Created', created ?? ''],
      ['Handle', resolved.meta?.handle ?? ''],
      ['Description', resolved.meta?.description ?? ''],
      ['DIDs', dids.join(', ')]
    ]
    console.log(
      renderTable({
        columns: [{ header: 'FIELD' }, { header: 'VALUE' }],
        rows
      })
    )
    return 0
  }

  // Re-import the stored key pair and re-export the public half only, so the
  // secret key material never leaves storage in the displayed output.
  let publicKey
  if ((storedKey as { type?: string }).type === 'Sha256HmacKey2019') {
    // A symmetric HMAC key has no public half; show only its safe fields,
    // never the secret material.
    publicKey = { id: storedKey.id, type: 'Sha256HmacKey2019' }
  } else if (
    (storedKey as { type?: string }).type === 'Multikey' &&
    (storedKey as { secretKeyMultibase?: string }).secretKeyMultibase &&
    !storedKey.publicKeyMultibase
  ) {
    // A symmetric AES-256 KEK (a Multikey with a secretKeyMultibase and no
    // public half); show only its safe fields, never the secret material.
    publicKey = { id: storedKey.id, type: 'Multikey' }
  } else if (
    (storedKey as { type?: string }).type === 'X25519KeyAgreementKey2020'
  ) {
    publicKey = await (
      await X25519KeyAgreementKey2020.from(storedKey)
    ).export({ publicKey: true })
  } else if (
    isEcdsaPublicKeyMultibase({
      publicKeyMultibase: storedKey.publicKeyMultibase
    })
  ) {
    publicKey = await (
      await EcdsaMultikey.from(storedKey)
    ).export({
      publicKey: true,
      secretKey: false
    })
  } else {
    publicKey = await (
      await Ed25519VerificationKey.from(storedKey)
    ).export({
      publicKey: true,
      secretKey: false
    })
  }
  console.log(JSON.stringify(publicKey, null, 2))
  return 0
}

/**
 * Shows or edits the metadata of a locally stored key (by fingerprint or
 * handle). With no edits, prints the current metadata; otherwise applies the
 * handle/description changes and saves the sidecar.
 *
 * @param options {object}
 * @param options.id {string}   The publicKeyMultibase fingerprint or handle.
 * @param [options.handle] {string}   Set the handle (empty string clears it).
 * @param [options.description] {string}   Set the description (empty clears it).
 * @returns {Promise<number>}   The process exit code.
 */
export async function runMeta(options: {
  id: string
  handle?: string
  description?: string
}): Promise<number> {
  const { id } = options
  const resolved = await resolveRefOrReport({
    resolve: ref => resolveKeyRef({ ref }),
    ref: id,
    noun: 'key'
  })
  if (!resolved) {
    return 1
  }
  if (!resolved.key.publicKeyMultibase) {
    console.error(`No locally stored key found for ${id}`)
    return 1
  }
  const fingerprint = resolved.key.publicKeyMultibase
  const dids = (await mapFingerprintsToDids()).get(fingerprint) ?? []

  const hasEdits =
    options.handle !== undefined || options.description !== undefined
  if (!hasEdits) {
    const output: KeyMetadata = { ...(resolved.meta ?? {}) }
    // Show the derived associations, not the cached ones.
    if (dids.length > 0) {
      output.dids = dids
    } else {
      delete output.dids
    }
    console.log(JSON.stringify(output, null, 2))
    return 0
  }

  const meta: KeyMetadata = { ...(resolved.meta ?? {}) }
  if (!meta.created) {
    // Backfill a date-only created from the storage ID's date prefix.
    const { date } = parseKeyStorageId({ storageId: resolved.storageId })
    if (date) {
      meta.created = date
    }
  }
  applyMetaEdits(meta, {
    handle: options.handle,
    description: options.description
  })
  // Every write also refreshes the cached key-to-DID associations.
  if (dids.length > 0) {
    meta.dids = dids
  } else {
    delete meta.dids
  }
  const filePath = await saveMetaToCollection({
    collection: COLLECTION,
    storageId: resolved.storageId,
    meta
  })
  console.error(`Metadata saved to ${filePath}`)
  console.log(JSON.stringify(meta, null, 2))
  return 0
}

/**
 * Removes a locally stored key and its metadata sidecar, resolved by
 * publicKeyMultibase fingerprint or handle.
 *
 * @param options {object}
 * @param options.id {string}   The publicKeyMultibase fingerprint or handle.
 * @returns {Promise<number>}   The process exit code.
 */
export async function runRemove(options: { id: string }): Promise<number> {
  return runRemoveCollection({
    collection: COLLECTION,
    noun: 'key',
    resolve: ref => resolveKeyRef({ ref }),
    ref: options.id
  })
}

/**
 * Exports a key by ID in the requested format.
 *
 * @param options {object}
 * @param options.keyId {string}   The key to export.
 * @param options.format {string}   Export format (jwk|multibase).
 * @returns {Promise<number>}   The process exit code.
 */
export async function runExport(options: {
  keyId: string
  format: string
}): Promise<number> {
  console.error(`Exporting key ${options.keyId} (format: ${options.format})`)
  // TODO: implement
  return 0
}

export function makeKeyCommand(): Command {
  const key = new Command('key').description('Manage cryptographic keys')

  key
    .command('create')
    .description('Create a new key')
    .option(
      '-t, --type <type>',
      'key type (supported: ed25519, ecdsa, x25519, hmac, aes256)',
      'ed25519'
    )
    .option(
      '--curve <curve>',
      `ECDSA curve for --type ecdsa (supported: ${SUPPORTED_ECDSA_CURVES})`,
      'p256'
    )
    .option(
      '--save',
      'save the key to local wallet storage (~/.config/did-cli-wallet/keys/)'
    )
    .option(
      '--handle <handle>',
      'short tag for the saved key (requires --save)'
    )
    .option(
      '--description <description>',
      'longer description of the saved key (requires --save)'
    )
    .option(
      '--with-seed',
      'include the secret key seed in output (generated if SECRET_KEY_SEED is not set)'
    )
    .action(
      (options: {
        type: string
        curve: string
        save?: boolean
        handle?: string
        description?: string
        withSeed?: boolean
      }) => runAndExit(runCreate(options))
    )

  key
    .command('list')
    .description('List locally stored keys with their metadata')
    .option(
      '--json',
      'output the list as a JSON array of objects with metadata'
    )
    .option('--plain', 'output one fingerprint per line, sorted (no metadata)')
    .action((options: { json?: boolean; plain?: boolean }) =>
      runAndExit(runList(options))
    )

  key
    .command('show <id>')
    .aliases(['view', 'cat'])
    .description(
      'Show a locally stored key (public key object only) by its ' +
        'publicKeyMultibase fingerprint or handle'
    )
    .option('--meta', 'show the key metadata instead of the public key object')
    .option('--json', 'with --meta, output the metadata as JSON')
    .action((id: string, options: { meta?: boolean; json?: boolean }) =>
      runAndExit(runShow({ id, ...options }))
    )

  key
    .command('meta <id>')
    .description(
      'Show or edit the metadata of a locally stored key (by fingerprint or ' +
        'handle); with no options, prints the current metadata'
    )
    .option('--handle <handle>', 'set the handle (an empty string clears it)')
    .option(
      '--description <description>',
      'set the description (an empty string clears it)'
    )
    .action((id: string, options: { handle?: string; description?: string }) =>
      runAndExit(runMeta({ id, ...options }))
    )

  key
    .command('remove <id>')
    .aliases(['delete', 'rm'])
    .description(
      'Remove a locally stored key and its metadata sidecar (by ' +
        'publicKeyMultibase fingerprint or handle)'
    )
    .action((id: string) => runAndExit(runRemove({ id })))

  key
    .command('export <id>')
    .description('Export a key by ID')
    .option('-f, --format <format>', 'export format (jwk|multibase)', 'jwk')
    .action((keyId: string, options: { format: string }) =>
      runAndExit(runExport({ keyId, ...options }))
    )

  return key
}
