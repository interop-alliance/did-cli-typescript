import { Command } from 'commander'
import {
  decodeSecretKeySeed,
  generateSecretKeySeed
} from '@digitalcredentials/bnid'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'
import * as EcdsaMultikey from '@interop/ecdsa-multikey'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import { SHA256HMACKey } from '@interop/data-integrity-core'
import {
  listCollection,
  loadFromCollection,
  loadMetaFromCollection,
  removeFromCollection,
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
import { runAndExit } from './was/shared.js'

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
 * Write the metadata sidecar of a freshly saved key: the creation timestamp,
 * plus the handle and description when given.
 *
 * @param options {object}
 * @param options.storageId {string}
 * @param options.created {string}
 * @param [options.handle] {string}
 * @param [options.description] {string}
 * @returns {Promise<void>}
 */
async function writeCreateMeta({
  storageId,
  created,
  handle,
  description
}: {
  storageId: string
  created: string
  handle?: string
  description?: string
}): Promise<void> {
  const meta: KeyMetadata = { created }
  if (handle) {
    meta.handle = handle
  }
  if (description) {
    meta.description = description
  }
  await saveMetaToCollection({ collection: 'keys', storageId, meta })
}

/**
 * Generates a key pair of the requested type, optionally saving it to the
 * wallet, and prints the key (or the seed-wrapped form) to stdout.
 *
 * @param options {object}
 * @param options.type {string}   Key type: ed25519, ecdsa, x25519, or hmac.
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
  if (
    (options.handle !== undefined || options.description !== undefined) &&
    !options.save
  ) {
    console.error('--handle and --description require --save')
    return 1
  }
  switch (options.type) {
    case 'ed25519': {
      const envSeed = process.env.SECRET_KEY_SEED
      const secretKeySeed = options.withSeed
        ? (envSeed ?? (await generateSecretKeySeed()))
        : envSeed
      const seedBytes = secretKeySeed
        ? decodeSecretKeySeed({ secretKeySeed })
        : undefined
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
        const filePath = await saveToCollection('keys', storageId, exported)
        await writeCreateMeta({
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
        const filePath = await saveToCollection('keys', storageId, exported)
        await writeCreateMeta({
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
        const filePath = await saveToCollection('keys', storageId, exported)
        await writeCreateMeta({
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
        const filePath = await saveToCollection('keys', storageId, exported)
        await writeCreateMeta({
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
          'Supported: ed25519, ecdsa, x25519, hmac'
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
  const storageIds = await listCollection('keys')
  if (options.plain) {
    const keyIds: string[] = []
    for (const storageId of storageIds) {
      const key = await loadFromCollection<{ publicKeyMultibase?: string }>(
        'keys',
        storageId
      )
      if (key.publicKeyMultibase) {
        keyIds.push(key.publicKeyMultibase)
      }
    }
    keyIds.sort()
    for (const keyId of keyIds) {
      console.log(keyId)
    }
    return 0
  }

  const fingerprintDids = await mapFingerprintsToDids()
  const entries: {
    fingerprint: string
    storageId: string
    type?: string
    curve?: string
    created?: string
    handle?: string
    description?: string
    dids: string[]
  }[] = []
  // Storage IDs carry a YYYY-MM-DD prefix, so this order is chronological.
  for (const storageId of storageIds) {
    const key = await loadFromCollection<{
      id?: string
      publicKeyMultibase?: string
    }>('keys', storageId)
    // Asymmetric keys are identified by their publicKeyMultibase
    // fingerprint; an HMAC key has no public half, so fall back to its id.
    const fingerprint = key.publicKeyMultibase ?? key.id
    if (!fingerprint) {
      continue
    }
    const meta = await loadMetaFromCollection({
      collection: 'keys',
      storageId
    })
    const parsed = parseKeyStorageId({ storageId })
    entries.push({
      fingerprint,
      storageId,
      type: parsed.type,
      curve: parsed.curve,
      created: meta?.created ?? parsed.date,
      handle: meta?.handle,
      description: meta?.description,
      dids: fingerprintDids.get(fingerprint) ?? []
    })
  }

  if (options.json) {
    const output = entries.map(entry => ({
      fingerprint: entry.fingerprint,
      storageId: entry.storageId,
      ...(entry.type && { type: entry.type }),
      ...(entry.curve && { curve: entry.curve }),
      ...(entry.created && { created: entry.created }),
      ...(entry.handle && { handle: entry.handle }),
      ...(entry.description && { description: entry.description }),
      dids: entry.dids
    }))
    console.log(JSON.stringify(output, null, 2))
    return 0
  }

  if (entries.length === 0) {
    return 0
  }
  const rows = entries.map(entry => [
    entry.handle ?? '',
    keyTypeLabel({ type: entry.type, curve: entry.curve }),
    entry.created?.slice(0, 10) ?? '',
    entry.fingerprint,
    didsCell({ dids: entry.dids }),
    entry.description ?? ''
  ])
  console.log(
    renderTable({
      columns: [
        { header: 'HANDLE', maxWidth: 16 },
        { header: 'TYPE' },
        { header: 'CREATED' },
        { header: 'FINGERPRINT', maxWidth: 28 },
        { header: 'DIDS' },
        { header: 'DESCRIPTION', maxWidth: 40 }
      ],
      rows
    })
  )
  return 0
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
  let resolved
  try {
    resolved = await resolveKeyRef({ ref: id })
  } catch (err) {
    console.error((err as Error).message)
    return 1
  }
  // An HMAC key has no public fingerprint, so fall back to its id.
  const fingerprint = resolved?.key.publicKeyMultibase ?? resolved?.key.id
  if (!resolved || !fingerprint) {
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
  let resolved
  try {
    resolved = await resolveKeyRef({ ref: id })
  } catch (err) {
    console.error((err as Error).message)
    return 1
  }
  if (!resolved?.key.publicKeyMultibase) {
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
  // Every write also refreshes the cached key-to-DID associations.
  if (dids.length > 0) {
    meta.dids = dids
  } else {
    delete meta.dids
  }
  const filePath = await saveMetaToCollection({
    collection: 'keys',
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
  const { id } = options
  let resolved
  try {
    resolved = await resolveKeyRef({ ref: id })
  } catch (err) {
    console.error((err as Error).message)
    return 1
  }
  if (!resolved) {
    console.error(`No locally stored key found for ${id}`)
    return 1
  }
  const removed = await removeFromCollection({
    collection: 'keys',
    storageId: resolved.storageId
  })
  for (const filePath of removed) {
    console.error(`Removed ${filePath}`)
  }
  return 0
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
      'key type (supported: ed25519, ecdsa, x25519, hmac)',
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
