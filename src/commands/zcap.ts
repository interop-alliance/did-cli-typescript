/**
 * `zcap` command -- Authorization Capability (zcap) operations.
 *
 * `zcap create` builds an unsigned root capability for an invocation target.
 * `zcap delegate` signs a delegated capability: a first-level delegation from
 * the root capability for a `--url`, or a further (attenuated) delegation of an
 * existing `--capability`. Both print `{ rootCapability|delegatedCapability,
 * encoded }` to stdout (the `encoded` field is the multibase base58btc form);
 * diagnostics and errors go to stderr. `--save` writes the capability to local
 * wallet storage (`~/.config/did-cli-wallet/zcaps/`) along with a `.meta.json` metadata
 * sidecar (creation timestamp plus `--handle` / `--description` when given).
 * `list` renders a metadata table of the saved zcaps, `show` prints one back
 * (`--meta` for its metadata), `meta` edits the metadata sidecar, and `remove`
 * deletes a stored zcap; `revoke` remains a stub.
 *
 * The delegation signing key is sourced from a stored DID (`--did`) or, as a
 * fallback, the `ZCAP_CONTROLLER_KEY_SEED` env var together with `--controller`.
 *
 * Exit codes: 0 on success, 1 on a creation/delegation or input error.
 */
import { readFile } from 'node:fs/promises'
import { Command } from 'commander'
import type { IZcap } from '@interop/data-integrity-core/zcap'
import { createCapability } from '../zcap/create.js'
import { delegateCapability } from '../zcap/delegate.js'
import { decodeCapability } from '../zcap/encoding.js'
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
import { resolveZcapRef, type StoredZcap } from '../meta.js'
import { renderTable } from '../table.js'

/**
 * Derives a filesystem-safe storage id from a capability id (the `urn:...`
 * value). Exported for reuse by `was grant --save`, which stores into the
 * same zcap collection.
 *
 * @param capabilityId {string}
 * @returns {string}
 */
export function storageIdFor(capabilityId: string): string {
  return sanitizeStorageId(capabilityId)
}

/**
 * Build the human-readable type label shown in list/show output: `delegated`
 * when the capability descends from a parent, `root` otherwise.
 *
 * @param options {object}
 * @param options.zcap {StoredZcap}
 * @returns {string}
 */
function zcapTypeLabel({ zcap }: { zcap: StoredZcap }): string {
  return zcap.parentCapability ? 'delegated' : 'root'
}

/**
 * Write the metadata sidecar of a freshly saved zcap: the creation timestamp,
 * plus the handle and description when given. Exported for reuse by
 * `was grant --save`.
 *
 * @param options {object}
 * @param options.storageId {string}
 * @param options.created {string}
 * @param [options.handle] {string}
 * @param [options.description] {string}
 * @returns {Promise<void>}
 */
export async function writeCreateMeta({
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
  const meta: ItemMetadata = { created }
  if (handle) {
    meta.handle = handle
  }
  if (description) {
    meta.description = description
  }
  await saveMetaToCollection({ collection: 'zcaps', storageId, meta })
}

/**
 * Resolves a `--capability` option value to a parent capability object. A value
 * beginning with `z` is treated as a multibase-encoded capability string;
 * otherwise it is treated as a path to a JSON file containing the capability.
 *
 * @param value {string}
 * @returns {Promise<IZcap>}
 */
async function resolveCapabilityInput(value: string): Promise<IZcap> {
  if (value.startsWith('z')) {
    return decodeCapability(value)
  }
  return JSON.parse(await readFile(value, 'utf8')) as IZcap
}

/**
 * Creates a root capability and prints it (with its encoding) to stdout.
 *
 * @param options {object}
 * @param options.controller {string}   The root controller DID.
 * @param options.url {string}   The invocation target.
 * @param [options.save] {boolean}   Save the capability to local storage.
 * @param [options.handle] {string}   Short tag stored in the metadata sidecar.
 * @param [options.description] {string}   Longer description stored in the
 *   metadata sidecar.
 * @returns {Promise<number>}   The process exit code.
 */
export async function runCreate(options: {
  controller: string
  url: string
  save?: boolean
  handle?: string
  description?: string
}): Promise<number> {
  try {
    const result = createCapability({
      controller: options.controller,
      url: options.url
    })
    if (options.save) {
      const storageId = storageIdFor(result.rootCapability.id)
      const filePath = await saveToCollection(
        'zcaps',
        storageId,
        result.rootCapability
      )
      await writeCreateMeta({
        storageId,
        created: new Date().toISOString(),
        handle: options.handle,
        description: options.description
      })
      console.error(`Capability saved to ${filePath}`)
    }
    console.log(JSON.stringify(result, null, 2))
    return 0
  } catch (err) {
    console.error(
      `Could not create capability: ${err instanceof Error ? err.message : String(err)}`
    )
    return 1
  }
}

/**
 * Signs a delegated capability and prints it (with its encoding) to stdout.
 *
 * @param options {object}
 * @param options.delegatee {string}   The DID to delegate to.
 * @param [options.did] {string}   The stored DID to sign with.
 * @param [options.controller] {string}   The expected controller DID, when
 *   signing via `ZCAP_CONTROLLER_KEY_SEED`.
 * @param [options.url] {string}   The invocation target for a first-level
 *   delegation.
 * @param [options.capability] {string}   A parent capability (multibase string
 *   or a path to a JSON file) to delegate.
 * @param [options.invocationTarget] {string}   An attenuated invocation target.
 * @param [options.allow] {string[]}   Allowed actions.
 * @param [options.ttl] {string}   Time-to-live for expiration.
 * @param [options.expires] {string}   Explicit ISO 8601 expiration.
 * @param [options.save] {boolean}   Save the capability to local storage.
 * @param [options.handle] {string}   Short tag stored in the metadata sidecar.
 * @param [options.description] {string}   Longer description stored in the
 *   metadata sidecar.
 * @returns {Promise<number>}   The process exit code.
 */
export async function runDelegate(options: {
  delegatee: string
  did?: string
  controller?: string
  url?: string
  capability?: string
  invocationTarget?: string
  allow?: string[]
  ttl?: string
  expires?: string
  save?: boolean
  handle?: string
  description?: string
}): Promise<number> {
  try {
    const capability = options.capability
      ? await resolveCapabilityInput(options.capability)
      : undefined
    const result = await delegateCapability({
      did: options.did,
      controller: options.controller,
      delegatee: options.delegatee,
      url: options.url,
      capability,
      invocationTarget: options.invocationTarget,
      allow: options.allow,
      ttl: options.ttl,
      expires: options.expires
    })
    if (options.save) {
      const storageId = storageIdFor(result.delegatedCapability.id)
      const filePath = await saveToCollection(
        'zcaps',
        storageId,
        result.delegatedCapability
      )
      await writeCreateMeta({
        storageId,
        created: new Date().toISOString(),
        handle: options.handle,
        description: options.description
      })
      console.error(`Capability saved to ${filePath}`)
    }
    console.log(JSON.stringify(result, null, 2))
    return 0
  } catch (err) {
    console.error(
      `Could not delegate capability: ${err instanceof Error ? err.message : String(err)}`
    )
    return 1
  }
}

export function makeZcapCommand(): Command {
  const zcap = new Command('zcap').description(
    'Manage authorization capabilities'
  )

  zcap
    .command('create')
    .description('Create a new (root) zcap')
    .requiredOption('--controller <did>', 'the DID of the zcap controller')
    .requiredOption(
      '--url <url>',
      'the URL the capability targets (the invocationTarget)'
    )
    .option(
      '--save',
      'save the zcap to local wallet storage (~/.config/did-cli-wallet/zcaps/)'
    )
    .option(
      '--handle <handle>',
      'short tag for the saved zcap (requires --save)'
    )
    .option(
      '--description <description>',
      'longer description of the saved zcap (requires --save)'
    )
    .action(
      async (options: {
        controller: string
        url: string
        save?: boolean
        handle?: string
        description?: string
      }) => {
        if (
          (options.handle !== undefined || options.description !== undefined) &&
          !options.save
        ) {
          console.error('--handle and --description require --save')
          process.exit(1)
          return
        }
        const code = await runCreate(options)
        if (code !== 0) {
          process.exit(code)
        }
      }
    )

  zcap
    .command('delegate')
    .description('Delegate a zcap')
    .requiredOption(
      '--delegatee <did>',
      'the DID to delegate to (the delegated capability controller)'
    )
    .option(
      '--did <did>',
      'id of the stored DID to sign with (preferred over ZCAP_CONTROLLER_KEY_SEED)'
    )
    .option(
      '--controller <did>',
      'expected controller DID, required when signing via ZCAP_CONTROLLER_KEY_SEED'
    )
    .option(
      '--url <url>',
      'invocation target for a first-level delegation from the root capability'
    )
    .option(
      '--capability <value>',
      'parent capability to delegate: a multibase (z...) string or a JSON file path'
    )
    .option(
      '--invocation-target <url>',
      "attenuated invocation target (narrows the parent capability's target)"
    )
    .option(
      '--allow <action...>',
      'allowed action(s), e.g. read write (default: inherit the parent)'
    )
    .option('--ttl <duration>', 'time to live, e.g. 1y, 30d, 24h', '1y')
    .option('--expires <iso>', 'explicit ISO 8601 expiration (overrides --ttl)')
    .option(
      '--save',
      'save the zcap to local wallet storage (~/.config/did-cli-wallet/zcaps/)'
    )
    .option(
      '--handle <handle>',
      'short tag for the saved zcap (requires --save)'
    )
    .option(
      '--description <description>',
      'longer description of the saved zcap (requires --save)'
    )
    .action(
      async (options: {
        delegatee: string
        did?: string
        controller?: string
        url?: string
        capability?: string
        invocationTarget?: string
        allow?: string[]
        ttl?: string
        expires?: string
        save?: boolean
        handle?: string
        description?: string
      }) => {
        if (
          (options.handle !== undefined || options.description !== undefined) &&
          !options.save
        ) {
          console.error('--handle and --description require --save')
          process.exit(1)
          return
        }
        const code = await runDelegate(options)
        if (code !== 0) {
          process.exit(code)
        }
      }
    )

  zcap
    .command('list')
    .description('List locally stored zcaps with their metadata')
    .option(
      '--json',
      'output the list as a JSON array of objects with metadata'
    )
    .option(
      '--plain',
      'output one capability id per line, sorted (no metadata)'
    )
    .action(async (options: { json?: boolean; plain?: boolean }) => {
      const storageIds = await listCollection('zcaps')
      if (options.plain) {
        const zcapIds: string[] = []
        for (const storageId of storageIds) {
          const zcap = await loadFromCollection<StoredZcap>('zcaps', storageId)
          if (zcap.id) {
            zcapIds.push(zcap.id)
          }
        }
        zcapIds.sort()
        for (const zcapId of zcapIds) {
          console.log(zcapId)
        }
        return
      }

      const entries: ({ id: string; type: string } & ItemMetadata)[] = []
      for (const storageId of storageIds) {
        const zcap = await loadFromCollection<StoredZcap>('zcaps', storageId)
        if (!zcap.id) {
          continue
        }
        const meta = await loadMetaFromCollection({
          collection: 'zcaps',
          storageId
        })
        entries.push({ id: zcap.id, type: zcapTypeLabel({ zcap }), ...meta })
      }

      if (options.json) {
        const output = entries.map(entry => ({
          id: entry.id,
          type: entry.type,
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
        entry.created?.slice(0, 10) ?? '',
        entry.id,
        entry.description ?? ''
      ])
      console.log(
        renderTable({
          columns: [
            { header: 'HANDLE', maxWidth: 16 },
            { header: 'TYPE' },
            { header: 'CREATED' },
            { header: 'ID', maxWidth: 44 },
            { header: 'DESCRIPTION', maxWidth: 40 }
          ],
          rows
        })
      )
    })

  zcap
    .command('show <id>')
    .aliases(['view', 'cat'])
    .description(
      'Show a locally stored zcap by its capability id or metadata handle'
    )
    .option('--meta', 'show the zcap metadata instead of the capability')
    .option('--json', 'with --meta, output the metadata as JSON')
    .action(async (id: string, options: { meta?: boolean; json?: boolean }) => {
      let resolved
      try {
        resolved = await resolveZcapRef({ ref: id })
      } catch (err) {
        console.error((err as Error).message)
        process.exit(1)
        return
      }
      if (!resolved) {
        console.error(`No locally stored zcap found for ${id}`)
        process.exit(1)
        return
      }

      if (options.meta) {
        const zcapId = resolved.zcap.id ?? ''
        const type = zcapTypeLabel({ zcap: resolved.zcap })
        if (options.json) {
          const output = {
            id: zcapId,
            type,
            ...(resolved.meta?.created && { created: resolved.meta.created }),
            ...(resolved.meta?.handle && { handle: resolved.meta.handle }),
            ...(resolved.meta?.description && {
              description: resolved.meta.description
            }),
            ...(resolved.zcap.controller && {
              controller: resolved.zcap.controller
            }),
            ...(resolved.zcap.invocationTarget && {
              invocationTarget: resolved.zcap.invocationTarget
            }),
            ...(resolved.zcap.expires && { expires: resolved.zcap.expires })
          }
          console.log(JSON.stringify(output, null, 2))
          return
        }
        const rows = [
          ['ID', zcapId],
          ['Type', type],
          ['Handle', resolved.meta?.handle ?? ''],
          ['Created', resolved.meta?.created ?? ''],
          ['Description', resolved.meta?.description ?? ''],
          ['Controller', resolved.zcap.controller ?? ''],
          ['Target', resolved.zcap.invocationTarget ?? ''],
          ['Expires', resolved.zcap.expires ?? '']
        ]
        console.log(
          renderTable({
            columns: [{ header: 'FIELD' }, { header: 'VALUE' }],
            rows
          })
        )
        return
      }

      // A stored zcap holds no secret material (a delegated capability's proof
      // is public), so it is safe to print as-is.
      console.log(JSON.stringify(resolved.zcap, null, 2))
    })

  zcap
    .command('meta <id>')
    .description(
      'Show or edit the metadata of a locally stored zcap (by capability id ' +
        'or handle); with no options, prints the current metadata'
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
          resolved = await resolveZcapRef({ ref: id })
        } catch (err) {
          console.error((err as Error).message)
          process.exit(1)
          return
        }
        if (!resolved) {
          console.error(`No locally stored zcap found for ${id}`)
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
          collection: 'zcaps',
          storageId: resolved.storageId,
          meta
        })
        console.error(`Metadata saved to ${filePath}`)
        console.log(JSON.stringify(meta, null, 2))
      }
    )

  zcap
    .command('remove <id>')
    .aliases(['delete', 'rm'])
    .description(
      'Remove a locally stored zcap and its metadata sidecar (by capability ' +
        'id or handle)'
    )
    .action(async (id: string) => {
      let resolved
      try {
        resolved = await resolveZcapRef({ ref: id })
      } catch (err) {
        console.error((err as Error).message)
        process.exit(1)
        return
      }
      if (!resolved) {
        console.error(`No locally stored zcap found for ${id}`)
        process.exit(1)
        return
      }
      const removed = await removeFromCollection({
        collection: 'zcaps',
        storageId: resolved.storageId
      })
      for (const filePath of removed) {
        console.error(`Removed ${filePath}`)
      }
    })

  zcap
    .command('revoke <id>')
    .description('Revoke a zcap by ID')
    .action((zcapId: string) => {
      console.log(`Revoking zcap ${zcapId}...`)
      // TODO: implement
    })

  return zcap
}
