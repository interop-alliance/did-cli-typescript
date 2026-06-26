/**
 * `did` command wiring. Defines the commander surface (create, add-key,
 * add-service, remove-service, get, show, list, meta, remove, and the webvh
 * subcommand) and delegates each action to a `run*` function in the `did/`
 * modules: create/add-key in `./did/create.js`, service edits in
 * `./did/service.js`, read/manage operations in `./did/manage.js`, and the
 * did:webvh update-key plumbing plus rotate-keys in `./did/webvh-update.js`.
 */
import { Command } from 'commander'
import { type ServiceEndpoint } from '@interop/did-method-webvh'
import { SUPPORTED_ECDSA_CURVES } from '../keys/ecdsa.js'
import { runAndExit } from './was/shared.js'
import {
  DEFAULT_VERIFICATION_PURPOSES,
  runAddKey,
  runCreate
} from './did/create.js'
import {
  addServiceEntry,
  buildServiceEntry,
  dispatchServiceUpdate,
  normalizeServiceId,
  removeServiceEntry
} from './did/service.js'
import { runGet, runList, runMeta, runRemove, runShow } from './did/manage.js'
import { runRotateKeys } from './did/webvh-update.js'

export { parseDidLog } from './did/webvh-update.js'

export function makeDidCommand(): Command {
  const did = new Command('did').description('Manage DIDs')

  did
    .command('create [method]')
    .description('Create a new DID (method: key, web, webvh) [default: key]')
    .option(
      '-t, --type <type>',
      'key type (supported: ed25519, ecdsa)',
      'ed25519'
    )
    .option(
      '--curve <curve>',
      `ECDSA curve for --type ecdsa (supported: ${SUPPORTED_ECDSA_CURVES})`,
      'p256'
    )
    .option(
      '--url <url>',
      'HTTPS url of the DID document (required for did:web)'
    )
    .option(
      '--prerotation',
      'arm did:webvh key pre-rotation: stage a next update key and commit ' +
        'its hash (default)'
    )
    .option('--no-prerotation', 'create the did:webvh without key pre-rotation')
    .option(
      '--portable',
      'create a portable did:webvh that can later be moved to a different ' +
        'domain (default)'
    )
    .option(
      '--no-portable',
      'create a non-portable did:webvh (pinned to its domain)'
    )
    .option(
      '--witness <did...>',
      'declare a witness did:key DID authorized to co-sign did:webvh log ' +
        'entries (repeatable; declaration only -- witness proof generation is ' +
        'out of scope)'
    )
    .option(
      '--witness-threshold <n>',
      'number of did:webvh witness approvals required ' +
        '(default: number of witnesses; requires --witness)'
    )
    .option(
      '--watcher <url...>',
      'declare a did:webvh watcher URL that monitors the DID log ' +
        '(repeatable; https:// or http://localhost)'
    )
    .option(
      '--with-seed',
      'include the secret key seed in output (generated if SECRET_KEY_SEED is not set)'
    )
    .option(
      '--save',
      'save the DID document to local storage (~/.config/did-cli-wallet/dids/)'
    )
    .option(
      '--handle <handle>',
      'short tag for the saved DID (requires --save)'
    )
    .option(
      '--description <description>',
      'longer description of the saved DID (requires --save)'
    )
    .action(
      (
        method: string = 'key',
        options: {
          type: string
          curve: string
          url?: string
          prerotation?: boolean
          portable?: boolean
          witness?: string[]
          witnessThreshold?: string
          watcher?: string[]
          withSeed?: boolean
          save?: boolean
          handle?: string
          description?: string
        }
      ) => runAndExit(runCreate({ method, ...options }))
    )

  did
    .command('add-key <did>')
    .description(
      'Add a verification key to an existing (locally stored) did:web'
    )
    .option(
      '-t, --type <type>',
      'key type (supported: ed25519, ecdsa, x25519); x25519 keys are wired ' +
        'into keyAgreement only',
      'ed25519'
    )
    .option(
      '--curve <curve>',
      `ECDSA curve for --type ecdsa (supported: ${SUPPORTED_ECDSA_CURVES})`,
      'p256'
    )
    .option(
      '--purpose <purpose...>',
      'verification relationship(s) to wire the key into ' +
        `(default: ${DEFAULT_VERIFICATION_PURPOSES.join(', ')})`
    )
    .option(
      '--with-seed',
      'include the new secret key seed in output (generated if SECRET_KEY_SEED is not set)'
    )
    .action(
      (
        did: string,
        options: {
          type: string
          curve: string
          purpose?: string[]
          withSeed?: boolean
        }
      ) => runAndExit(runAddKey({ did, ...options }))
    )

  did
    .command('add-service <did>')
    .description(
      'Add a service entry to a locally stored did:web or did:webvh DID. The ' +
        'DID may be given as a metadata handle. For did:webvh this appends a ' +
        'log entry; if pre-rotation is armed the update key is advanced as ' +
        'part of the change.'
    )
    .requiredOption(
      '--id <id>',
      'service id; a bare fragment (e.g. "files") is expanded to <did>#files'
    )
    .requiredOption(
      '--type <type...>',
      'service type(s), e.g. LinkedDomains (repeat for multiple)'
    )
    .option(
      '--endpoint <endpoint...>',
      'serviceEndpoint value(s); a single value stays a string, several ' +
        'become an array (mutually exclusive with --endpoint-json)'
    )
    .option(
      '--endpoint-json <json>',
      'serviceEndpoint as a raw JSON value (mutually exclusive with --endpoint)'
    )
    .option(
      '--keep-old-key',
      'did:webvh pre-rotation only: retain the retired update key secret in ' +
        'the sidecar (default: drop it)'
    )
    .option('-y, --yes', 'skip the did:webvh confirmation prompt')
    .action(
      async (
        did: string,
        options: {
          id: string
          type: string[]
          endpoint?: string[]
          endpointJson?: string
          keepOldKey?: boolean
          yes?: boolean
        }
      ) => {
        const transform = (
          current: ServiceEndpoint[],
          resolvedDid: string
        ): ServiceEndpoint[] => {
          const entry = buildServiceEntry({
            did: resolvedDid,
            id: options.id,
            type: options.type,
            endpoint: options.endpoint,
            endpointJson: options.endpointJson
          })
          return addServiceEntry({ current, entry, did: resolvedDid })
        }
        return runAndExit(
          dispatchServiceUpdate({
            ref: did,
            transform,
            yes: options.yes,
            keepOldKey: options.keepOldKey
          })
        )
      }
    )

  did
    .command('remove-service <did>')
    .description(
      'Remove a service entry (by id) from a locally stored did:web or ' +
        'did:webvh DID. The DID may be given as a metadata handle. For ' +
        'did:webvh this appends a log entry; if pre-rotation is armed the ' +
        'update key is advanced as part of the change.'
    )
    .requiredOption(
      '--id <id>',
      'id of the service to remove; a bare fragment (e.g. "files") is ' +
        'expanded to <did>#files'
    )
    .option(
      '--keep-old-key',
      'did:webvh pre-rotation only: retain the retired update key secret in ' +
        'the sidecar (default: drop it)'
    )
    .option('-y, --yes', 'skip the did:webvh confirmation prompt')
    .action(
      async (
        did: string,
        options: { id: string; keepOldKey?: boolean; yes?: boolean }
      ) => {
        const transform = (
          current: ServiceEndpoint[],
          resolvedDid: string
        ): ServiceEndpoint[] =>
          removeServiceEntry({
            current,
            id: normalizeServiceId({ did: resolvedDid, id: options.id }),
            did: resolvedDid
          })
        return runAndExit(
          dispatchServiceUpdate({
            ref: did,
            transform,
            yes: options.yes,
            keepOldKey: options.keepOldKey
          })
        )
      }
    )

  did
    .command('get <did>')
    .aliases(['resolve'])
    .description(
      'Resolve a DID to its DID document, or a DID URL (a did#fragment key ' +
        'id) to its verification method, via the security document loader'
    )
    .action((didOrKeyId: string) => runAndExit(runGet({ didOrKeyId })))

  did
    .command('show <did>')
    .aliases(['view', 'cat'])
    .description(
      'Show a locally stored DID document (no secret key material) by DID ' +
        'or handle. For did:webvh the document is resolved from its history ' +
        'log -- the source of truth -- rather than the stored snapshot.'
    )
    .option('--meta', 'show the DID metadata instead of the DID document')
    .option('--json', 'with --meta, output the metadata as JSON')
    .action((didRef: string, options: { meta?: boolean; json?: boolean }) =>
      runAndExit(runShow({ didRef, ...options }))
    )

  did
    .command('list')
    .description('List locally stored DIDs with their metadata')
    .option(
      '--json',
      'output the list as a JSON array of objects with metadata'
    )
    .option('--plain', 'output one DID per line, sorted (no metadata)')
    .action((options: { json?: boolean; plain?: boolean }) =>
      runAndExit(runList(options))
    )

  did
    .command('meta <did>')
    .description(
      'Show or edit the metadata of a locally stored DID (by DID or handle); ' +
        'with no options, prints the current metadata'
    )
    .option('--handle <handle>', 'set the handle (an empty string clears it)')
    .option(
      '--description <description>',
      'set the description (an empty string clears it)'
    )
    .action(
      (didRef: string, options: { handle?: string; description?: string }) =>
        runAndExit(runMeta({ didRef, ...options }))
    )

  did
    .command('remove <did>')
    .aliases(['delete', 'rm'])
    .description(
      'Remove a locally stored DID document, its keys file, and its ' +
        'metadata sidecar (by DID or handle)'
    )
    .action((didRef: string) => runAndExit(runRemove({ didRef })))

  const webvh = new Command('webvh').description(
    'Manage did:webvh DIDs: rotate update (authorization) keys'
  )

  webvh
    .command('rotate-keys <did>')
    .description(
      'Rotate the update (authorization) key of a locally stored did:webvh ' +
        'DID. By default advances key pre-rotation -- reveals the staged next ' +
        'key and stages a fresh one -- and never touches the document ' +
        'verification methods.'
    )
    .option(
      '--update-key <multibase...>',
      'rotate to specific update key(s) by publicKeyMultibase instead of ' +
        'generating a fresh one (ordinary mode only; rejected while ' +
        'pre-rotation is armed, where the next keys are fixed by the prior ' +
        'commitment)'
    )
    .option(
      '--enable-prerotation',
      'for a DID without pre-rotation, turn it on by staging a next key this ' +
        'rotation (alone: stage only, leaving the active key unchanged)'
    )
    .option(
      '--stop-prerotation',
      'do not stage a next key; pre-rotation turns off after this rotation'
    )
    .option(
      '--keep-old-key',
      'retain the retired update key secret in the sidecar (default: drop it)'
    )
    .option('-y, --yes', 'skip the confirmation prompt')
    .action(
      (
        didRef: string,
        options: {
          updateKey?: string[]
          enablePrerotation?: boolean
          stopPrerotation?: boolean
          keepOldKey?: boolean
          yes?: boolean
        }
      ) => runAndExit(runRotateKeys({ didRef, ...options }))
    )

  did.addCommand(webvh)

  return did
}
