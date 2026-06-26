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
import { Command } from 'commander'
import { createCapability } from '../zcap/create.js'
import { delegateCapability } from '../zcap/delegate.js'
import { resolveCapabilityInput } from '../zcap/resolve.js'
import {
  saveToCollection,
  sanitizeStorageId,
  type ItemMetadata
} from '../storage.js'
import { resolveZcapRef, type StoredZcap } from '../meta.js'
import { renderTable } from '../table.js'
import {
  requireSaveForMetaFlags,
  resolveRefOrReport,
  runListCollection,
  runMetaCollection,
  runRemoveCollection,
  writeCreateMeta
} from './collection-command.js'

/** The wallet collection name for stored authorization capabilities. */
const COLLECTION = 'zcaps'

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
  if (!requireSaveForMetaFlags(options)) {
    return 1
  }
  try {
    const result = createCapability({
      controller: options.controller,
      url: options.url
    })
    if (options.save) {
      const storageId = storageIdFor(result.rootCapability.id)
      const filePath = await saveToCollection(
        COLLECTION,
        storageId,
        result.rootCapability
      )
      await writeCreateMeta({
        collection: COLLECTION,
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
 * @param [options.capability] {string}   A parent capability (multibase
 *   string, a path to a JSON file, or a stored zcap id/handle) to delegate.
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
  if (!requireSaveForMetaFlags(options)) {
    return 1
  }
  try {
    const capability = options.capability
      ? await resolveCapabilityInput({ ref: options.capability })
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
        COLLECTION,
        storageId,
        result.delegatedCapability
      )
      await writeCreateMeta({
        collection: COLLECTION,
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
      'parent capability to delegate: a multibase (z...) string, a JSON ' +
        'file path, or a stored zcap id/handle'
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
      await runListCollection<
        StoredZcap,
        { id: string; type: string } & ItemMetadata
      >({
        collection: COLLECTION,
        plain: options.plain,
        json: options.json,
        plainId: zcap => zcap.id,
        toEntry: ({ item, meta }) =>
          item.id
            ? { id: item.id, type: zcapTypeLabel({ zcap: item }), ...meta }
            : undefined,
        toJson: entry => ({
          id: entry.id,
          type: entry.type,
          ...(entry.created && { created: entry.created }),
          ...(entry.handle && { handle: entry.handle }),
          ...(entry.description && { description: entry.description })
        }),
        columns: [
          { header: 'HANDLE', maxWidth: 16 },
          { header: 'TYPE' },
          { header: 'CREATED' },
          { header: 'ID', maxWidth: 44 },
          { header: 'DESCRIPTION', maxWidth: 40 }
        ],
        toRow: entry => [
          entry.handle ?? '',
          entry.type,
          entry.created?.slice(0, 10) ?? '',
          entry.id,
          entry.description ?? ''
        ]
      })
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
      const resolved = await resolveRefOrReport({
        resolve: ref => resolveZcapRef({ ref }),
        ref: id,
        noun: 'zcap'
      })
      if (!resolved) {
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
        const code = await runMetaCollection({
          collection: COLLECTION,
          noun: 'zcap',
          resolve: ref => resolveZcapRef({ ref }),
          ref: id,
          handle: options.handle,
          description: options.description
        })
        if (code !== 0) {
          process.exit(code)
        }
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
      const code = await runRemoveCollection({
        collection: COLLECTION,
        noun: 'zcap',
        resolve: ref => resolveZcapRef({ ref }),
        ref: id
      })
      if (code !== 0) {
        process.exit(code)
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
