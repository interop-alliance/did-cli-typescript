/**
 * `zcap` command -- Authorization Capability (zcap) operations.
 *
 * `zcap create` builds an unsigned root capability for an invocation target.
 * `zcap delegate` signs a delegated capability: a first-level delegation from
 * the root capability for a `--url`, or a further (attenuated) delegation of an
 * existing `--capability`. Both print `{ rootCapability|delegatedCapability,
 * encoded }` to stdout (the `encoded` field is the multibase base58btc form);
 * diagnostics and errors go to stderr. `--save` writes the capability to local
 * wallet storage (`~/.wallet/zcaps/`). `list` reads back the ids of saved
 * zcaps from that storage; `revoke` remains a stub.
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
  saveToCollection
} from '../storage.js'

/**
 * Derives a filesystem-safe storage id from a capability id (the `urn:...`
 * value), replacing characters that are awkward in file names.
 *
 * @param capabilityId {string}
 * @returns {string}
 */
function storageIdFor(capabilityId: string): string {
  return capabilityId.replaceAll(':', '_').replaceAll('%', '_')
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
 * @returns {Promise<number>}   The process exit code.
 */
export async function runCreate(options: {
  controller: string
  url: string
  save?: boolean
}): Promise<number> {
  try {
    const result = createCapability({
      controller: options.controller,
      url: options.url
    })
    if (options.save) {
      const filePath = await saveToCollection(
        'zcaps',
        storageIdFor(result.rootCapability.id),
        result.rootCapability
      )
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
      const filePath = await saveToCollection(
        'zcaps',
        storageIdFor(result.delegatedCapability.id),
        result.delegatedCapability
      )
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
      'save the zcap to local wallet storage (~/.wallet/zcaps/)'
    )
    .action(
      async (options: { controller: string; url: string; save?: boolean }) => {
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
      'save the zcap to local wallet storage (~/.wallet/zcaps/)'
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
      }) => {
        const code = await runDelegate(options)
        if (code !== 0) {
          process.exit(code)
        }
      }
    )

  zcap
    .command('list')
    .description('List locally stored zcaps')
    .option('--json', 'output the list of zcap IDs as a JSON array')
    .action(async (options: { json?: boolean }) => {
      const storageIds = await listCollection('zcaps')
      const zcapIds: string[] = []
      for (const storageId of storageIds) {
        const zcap = await loadFromCollection<{ id?: string }>(
          'zcaps',
          storageId
        )
        if (zcap.id) {
          zcapIds.push(zcap.id)
        }
      }
      zcapIds.sort()
      if (options.json) {
        console.log(JSON.stringify(zcapIds, null, 2))
        return
      }
      for (const zcapId of zcapIds) {
        console.log(zcapId)
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
