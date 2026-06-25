import { createInterface } from 'node:readline/promises'
import { stdin, stdout } from 'node:process'
import { Command } from 'commander'
import {
  decodeSecretKeySeed,
  generateSecretKeySeed
} from '@digitalcredentials/bnid'
import { driver } from '@interop/did-method-key'
import * as didWeb from '@interop/did-web-resolver'
import {
  createDID,
  resolveDIDFromLog,
  updateDID,
  type DIDLog,
  type ServiceEndpoint
} from '@interop/did-method-webvh'
import {
  createDefaultDidResolver,
  securityLoader
} from '@interop/security-document-loader'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'
import * as EcdsaMultikey from '@interop/ecdsa-multikey'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import {
  listDids,
  loadDidDocument,
  loadDidKeys,
  loadDidLog,
  loadDidMeta,
  loadDidUpdateKeys,
  removeDidFiles,
  saveDidLog,
  saveDidMeta,
  saveDidUpdateKeys,
  saveToDids,
  type ItemMetadata,
  type WebvhUpdateKey,
  type WebvhUpdateKeys
} from '../storage.js'
import {
  recordKeyDidAssociation,
  removeKeyDidAssociation,
  resolveDidRef
} from '../meta.js'
import { renderTable } from '../table.js'
import {
  normalizeEcdsaCurve,
  SUPPORTED_ECDSA_CURVES,
  warnIfNotVcIssuanceCapable
} from '../keys/ecdsa.js'
import { makeWebvhSigner } from '../keys/webvh-signer.js'
import { makeWebvhDriver, webvhLogVerifier } from '../keys/webvh-driver.js'
import {
  exportUpdateKey,
  generateStagedKey,
  loadUpdateKey
} from '../keys/webvh-update.js'

/**
 * Save the artifacts of a newly created DID: the DID document, its keys file,
 * a metadata sidecar (creation timestamp plus the handle and description when
 * given), and the key-to-DID association cache of any matching wallet keys.
 *
 * @param options {object}
 * @param options.method {string}
 * @param options.didDocument {object}
 * @param options.exportedKeys {object}
 * @param options.fingerprints {(string | undefined)[]}
 * @param [options.handle] {string}
 * @param [options.description] {string}
 * @returns {Promise<void>}
 */
async function saveDidArtifacts({
  method,
  didDocument,
  exportedKeys,
  fingerprints,
  handle,
  description
}: {
  method: string
  didDocument: object
  exportedKeys: object
  fingerprints: (string | undefined)[]
  handle?: string
  description?: string
}): Promise<void> {
  const did = (didDocument as { id: string }).id
  const docPath = await saveToDids({ method, did, data: didDocument })
  await saveToDids({ method, did, suffix: 'keys', data: exportedKeys })
  const meta: ItemMetadata = { created: new Date().toISOString() }
  if (handle) {
    meta.handle = handle
  }
  if (description) {
    meta.description = description
  }
  await saveDidMeta({ did, meta })
  for (const fingerprint of fingerprints) {
    if (fingerprint) {
      await recordKeyDidAssociation({ publicKeyMultibase: fingerprint, did })
    }
  }
  console.error(`DID saved to ${docPath}`)
}

/**
 * Parse a raw did:webvh history log (newline-delimited JSON) into the entry
 * array the library's resolver/updater expect, ignoring blank lines.
 *
 * @param logText {string}
 * @returns {DIDLog}
 */
export function parseDidLog(logText: string): DIDLog {
  return logText
    .split('\n')
    .filter(line => line.trim().length > 0)
    .map(line => JSON.parse(line)) as DIDLog
}

/**
 * Ask the user to confirm a hard-to-undo action. Returns true immediately when
 * `--yes` was passed or when stdin is not an interactive TTY (so scripts and
 * tests are not blocked); otherwise prompts and requires an explicit `y`.
 *
 * @param options {object}
 * @param options.message {string}
 * @param options.yes {boolean} the value of the `--yes` flag.
 * @returns {Promise<boolean>}
 */
async function confirmAction({
  message,
  yes
}: {
  message: string
  yes?: boolean
}): Promise<boolean> {
  if (yes || !stdin.isTTY) {
    return true
  }
  const rl = createInterface({ input: stdin, output: stdout })
  try {
    const answer = await rl.question(`${message} [y/N] `)
    return answer.trim().toLowerCase() === 'y'
  } finally {
    rl.close()
  }
}

/**
 * Load and resolve a locally stored did:webvh history log in preparation for an
 * update, asserting it is updatable. The log is the source of truth for a
 * stored did:webvh, so its absence is what "not locally stored" means.
 *
 * @param options {object}
 * @param options.targetDid {string} the resolved did:webvh DID.
 * @param options.action {string} verb used in error messages (e.g.
 *   `rotate keys`, `update services`).
 * @returns {Promise<{ log, doc, meta }>}
 * @throws {Error} with a user-facing message if the log is missing, fails to
 *   resolve, or the DID is deactivated.
 */
async function resolveWebvhForUpdate({
  targetDid,
  action
}: {
  targetDid: string
  action: string
}): Promise<{
  log: DIDLog
  doc: Awaited<ReturnType<typeof resolveDIDFromLog>>['doc']
  meta: Awaited<ReturnType<typeof resolveDIDFromLog>>['meta']
}> {
  let logText: string
  try {
    logText = await loadDidLog(targetDid)
  } catch {
    throw new Error(`No locally stored did:webvh found for ${targetDid}`)
  }
  const log = parseDidLog(logText)
  let resolved: Awaited<ReturnType<typeof resolveDIDFromLog>>
  try {
    resolved = await resolveDIDFromLog(log, { verifier: webvhLogVerifier })
  } catch (err) {
    throw new Error(
      `Could not resolve the DID log: ${(err as Error).message}`,
      {
        cause: err
      }
    )
  }
  if (resolved.meta.deactivated) {
    throw new Error(`Cannot ${action}: the DID is deactivated.`)
  }
  return { log, doc: resolved.doc, meta: resolved.meta }
}

/**
 * Load a did:webvh DID's update-keys sidecar, treating an absent file as
 * `undefined` (no stored secrets) rather than an error.
 *
 * @param did {string}
 * @returns {Promise<WebvhUpdateKeys | undefined>}
 */
async function loadStoredUpdateKeys(
  did: string
): Promise<WebvhUpdateKeys | undefined> {
  try {
    return await loadDidUpdateKeys(did)
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== 'ENOENT') {
      throw err
    }
    return undefined
  }
}

/**
 * Pre-rotation reveal: validate and load the staged (pre-committed) update key
 * that must sign this entry, returning the signer key pair plus the records
 * that make it the new active key and retire the current one.
 *
 * @param options {object}
 * @param options.stored {WebvhUpdateKeys | undefined} the update-keys sidecar.
 * @param options.meta {Awaited<ReturnType<typeof resolveDIDFromLog>>['meta']}
 * @param options.targetDid {string}
 * @param options.action {string} verb used in error messages.
 * @returns {Promise<{ signerKeyPair, newActive, retiredActive }>}
 * @throws {Error} if the staged secret is missing or has diverged from the
 *   log's committed nextKeyHashes.
 */
async function revealStagedSigner({
  stored,
  meta,
  targetDid,
  action
}: {
  stored: WebvhUpdateKeys | undefined
  meta: Awaited<ReturnType<typeof resolveDIDFromLog>>['meta']
  targetDid: string
  action: string
}): Promise<{
  signerKeyPair: Ed25519VerificationKey
  newActive: WebvhUpdateKey
  retiredActive: WebvhUpdateKey
}> {
  if (!stored?.staged) {
    throw new Error(
      `Cannot ${action}: the pre-committed next-key secret was not found. ` +
        'While pre-rotation is armed the staged key must sign this entry; ' +
        `check for a backup of the ${targetDid}.update-keys.json sidecar.`
    )
  }
  if (!meta.nextKeyHashes.includes(stored.staged.nextKeyHash)) {
    throw new Error(
      `Cannot ${action}: the staged key's hash is not among the log's ` +
        'committed nextKeyHashes. The local update-keys record has diverged ' +
        'from the published log (an update may have happened elsewhere); ' +
        're-resolve before retrying.'
    )
  }
  return {
    signerKeyPair: await loadUpdateKey(stored.staged),
    newActive: {
      publicKeyMultibase: stored.staged.publicKeyMultibase,
      secretKeyMultibase: stored.staged.secretKeyMultibase
    },
    retiredActive: stored.active
  }
}

/**
 * Ordinary (non-pre-rotation) signer: the current active update key signs.
 * Returns the signer key pair and the active record it was loaded from.
 *
 * @param options {object}
 * @param options.stored {WebvhUpdateKeys | undefined} the update-keys sidecar.
 * @param options.meta {Awaited<ReturnType<typeof resolveDIDFromLog>>['meta']}
 * @param options.targetDid {string}
 * @param options.action {string} verb used in error messages.
 * @returns {Promise<{ signerKeyPair, activeRecord }>}
 * @throws {Error} if the active secret is missing or no longer matches the
 *   log's updateKeys.
 */
async function loadActiveSigner({
  stored,
  meta,
  targetDid,
  action
}: {
  stored: WebvhUpdateKeys | undefined
  meta: Awaited<ReturnType<typeof resolveDIDFromLog>>['meta']
  targetDid: string
  action: string
}): Promise<{
  signerKeyPair: Ed25519VerificationKey
  activeRecord: WebvhUpdateKey
}> {
  const activeRecord =
    stored?.active.secretKeyMultibase &&
    meta.updateKeys.includes(stored.active.publicKeyMultibase)
      ? stored.active
      : undefined
  if (!activeRecord) {
    throw new Error(
      `Cannot ${action}: the current active update-key secret was not found ` +
        `in ${targetDid}.update-keys.json.`
    )
  }
  return { signerKeyPair: await loadUpdateKey(activeRecord), activeRecord }
}

/**
 * Build the entry signer for a did:webvh update from an update key pair.
 *
 * @param keyPair {Ed25519VerificationKey} mutated: its `id` is set in place.
 * @returns the signer to pass to `updateDID`.
 */
function makeWebvhEntrySigner(keyPair: Ed25519VerificationKey) {
  const signer = makeWebvhSigner({ keyPair })
  // `keyPair.signer()` requires an id to be set before signing.
  keyPair.id = signer.getVerificationMethodId()
  return signer
}

/**
 * Write the update-keys sidecar: the active key, the staged next key (or
 * none), and any retired secrets. At creation there is no prior sidecar; after
 * an advance/rotation the superseded active key is appended to `retired` only
 * when `keepOldKey` asks to preserve it.
 *
 * @param options {object}
 * @param options.did {string}
 * @param options.newActive {WebvhUpdateKey}
 * @param [options.newStaged] {WebvhUpdateKey & { nextKeyHash: string }}
 * @param [options.retiredActive] {WebvhUpdateKey} the superseded active key.
 * @param [options.stored] {WebvhUpdateKeys} the prior sidecar, if any.
 * @param [options.keepOldKey] {boolean} retain the retired secret.
 * @returns {Promise<string>} the saved sidecar path.
 */
async function persistUpdateKeysSidecar({
  did,
  newActive,
  newStaged,
  retiredActive,
  stored,
  keepOldKey
}: {
  did: string
  newActive: WebvhUpdateKey
  newStaged?: WebvhUpdateKey & { nextKeyHash: string }
  retiredActive?: WebvhUpdateKey
  stored?: WebvhUpdateKeys
  keepOldKey?: boolean
}): Promise<string> {
  const updated: WebvhUpdateKeys = { active: newActive }
  if (newStaged) {
    updated.staged = newStaged
  }
  const retiredList = stored?.retired ? [...stored.retired] : []
  // retiredActive is undefined on the stage-only path, so this also skips that
  // case without a separate guard.
  if (keepOldKey && retiredActive?.secretKeyMultibase) {
    retiredList.push(retiredActive)
  }
  if (retiredList.length > 0) {
    updated.retired = retiredList
  }
  return saveDidUpdateKeys({ did, updateKeys: updated })
}

/**
 * Expand a service id to a full DID URL. A bare fragment (`files`) or a
 * leading-`#` fragment (`#files`) is resolved against the DID; a value that is
 * already a full DID URL, or any absolute URI carrying a fragment, is returned
 * unchanged.
 *
 * @param options {object}
 * @param options.did {string}
 * @param options.id {string}
 * @returns {string}
 */
function normalizeServiceId({ did, id }: { did: string; id: string }): string {
  if (id.startsWith('#')) {
    return `${did}${id}`
  }
  if (id.startsWith('did:') || id.includes('#')) {
    return id
  }
  return `${did}#${id}`
}

/**
 * Build a service-endpoint entry from add-service options. Exactly one of
 * `endpoint` (one or more endpoint values -- a single value stays a string,
 * several become an array) or `endpointJson` (a raw JSON value) supplies the
 * serviceEndpoint; a single `type` likewise stays a string.
 *
 * @param options {object}
 * @param options.did {string}
 * @param options.id {string}
 * @param options.type {string[]}
 * @param [options.endpoint] {string[]}
 * @param [options.endpointJson] {string}
 * @returns {ServiceEndpoint}
 */
function buildServiceEntry({
  did,
  id,
  type,
  endpoint,
  endpointJson
}: {
  did: string
  id: string
  type: string[]
  endpoint?: string[]
  endpointJson?: string
}): ServiceEndpoint {
  const hasEndpoint = Boolean(endpoint?.length)
  const hasEndpointJson = Boolean(endpointJson)
  // True when both are supplied or neither is -- i.e. not exactly one.
  if (hasEndpoint === hasEndpointJson) {
    throw new Error('Provide exactly one of --endpoint or --endpoint-json.')
  }
  let serviceEndpoint: ServiceEndpoint['serviceEndpoint']
  if (endpointJson) {
    try {
      serviceEndpoint = JSON.parse(endpointJson)
    } catch {
      throw new Error('--endpoint-json must be valid JSON.')
    }
  } else {
    serviceEndpoint = endpoint!.length === 1 ? endpoint![0] : endpoint
  }
  return {
    id: normalizeServiceId({ did, id }),
    type: type.length === 1 ? type[0] : type,
    serviceEndpoint
  }
}

/**
 * Whether a stored service entry has the given (already-normalized, absolute)
 * id. Service ids in a DID document may be relative (`#files`) or absolute, so
 * the stored id is normalized against the DID before comparing.
 *
 * @param options {object}
 * @param options.service {ServiceEndpoint}
 * @param options.id {string} the normalized id to match.
 * @param options.did {string}
 * @returns {boolean}
 */
function serviceHasId({
  service,
  id,
  did
}: {
  service: ServiceEndpoint
  id: string
  did: string
}): boolean {
  return (
    service.id !== undefined &&
    normalizeServiceId({ did, id: service.id }) === id
  )
}

/**
 * Append a service entry to the current array, rejecting a duplicate id.
 *
 * @param options {object}
 * @param options.current {ServiceEndpoint[]}
 * @param options.entry {ServiceEndpoint} its `id` is already normalized.
 * @param options.did {string}
 * @returns {ServiceEndpoint[]}
 */
function addServiceEntry({
  current,
  entry,
  did
}: {
  current: ServiceEndpoint[]
  entry: ServiceEndpoint
  did: string
}): ServiceEndpoint[] {
  if (current.some(service => serviceHasId({ service, id: entry.id!, did }))) {
    throw new Error(`A service with id "${entry.id}" already exists.`)
  }
  return [...current, entry]
}

/**
 * Remove the service entry with the given (normalized) id, rejecting a missing
 * id.
 *
 * @param options {object}
 * @param options.current {ServiceEndpoint[]}
 * @param options.id {string} the normalized id to remove.
 * @param options.did {string}
 * @returns {ServiceEndpoint[]}
 */
function removeServiceEntry({
  current,
  id,
  did
}: {
  current: ServiceEndpoint[]
  id: string
  did: string
}): ServiceEndpoint[] {
  const next = current.filter(service => !serviceHasId({ service, id, did }))
  if (next.length === current.length) {
    throw new Error(`No service with id "${id}" found on the DID document.`)
  }
  return next
}

/**
 * Apply a service-array transform to a locally stored did:web document and
 * re-save it. did:web has no history log, so this is a direct document edit;
 * the `service` property is dropped entirely when the array empties out.
 *
 * @param options {object}
 * @param options.did {string}
 * @param options.transform {(current: ServiceEndpoint[], did: string) => ServiceEndpoint[]}
 * @returns {Promise<number>} the process exit code
 */
async function runWebServiceUpdate({
  did,
  transform
}: {
  did: string
  transform: (current: ServiceEndpoint[], did: string) => ServiceEndpoint[]
}): Promise<number> {
  let didDocument: Record<string, unknown>
  try {
    didDocument = await loadDidDocument(did)
  } catch {
    console.error(`No locally stored did:web found for ${did}`)
    return 1
  }
  const current = Array.isArray(didDocument.service)
    ? (didDocument.service as ServiceEndpoint[])
    : []
  let next: ServiceEndpoint[]
  try {
    next = transform(current, did)
  } catch (err) {
    console.error((err as Error).message)
    return 1
  }
  if (next.length > 0) {
    didDocument.service = next
  } else {
    delete didDocument.service
  }
  const docPath = await saveToDids({ method: 'web', did, data: didDocument })
  console.error(`DID saved to ${docPath}`)
  console.log(JSON.stringify({ id: didDocument.id, didDocument }, null, 2))
  return 0
}

/**
 * Apply a service-array transform to a locally stored did:webvh DID by
 * appending a sparse log entry that overlays only the `service` array. Update
 * keys and document verification methods are carried forward unchanged -- with
 * one exception: a pre-rotation-armed DID cannot author a key-neutral update
 * (the library requires the staged key to sign), so the update-key ratchet is
 * advanced as part of the change -- the staged key is revealed to sign and a
 * fresh next key is staged.
 *
 * @param options {object}
 * @param options.targetDid {string} the resolved did:webvh DID.
 * @param options.transform {(current: ServiceEndpoint[], did: string) => ServiceEndpoint[]}
 * @param [options.yes] {boolean} skip the confirmation prompt.
 * @param [options.keepOldKey] {boolean} retain the retired update key secret
 *   (pre-rotation path only; default is to drop it).
 * @returns {Promise<number>} the process exit code
 */
async function runWebvhServiceUpdate({
  targetDid,
  transform,
  yes,
  keepOldKey
}: {
  targetDid: string
  transform: (current: ServiceEndpoint[], did: string) => ServiceEndpoint[]
  yes?: boolean
  keepOldKey?: boolean
}): Promise<number> {
  let log: DIDLog
  let doc: Awaited<ReturnType<typeof resolveDIDFromLog>>['doc']
  let meta: Awaited<ReturnType<typeof resolveDIDFromLog>>['meta']
  try {
    ;({ log, doc, meta } = await resolveWebvhForUpdate({
      targetDid,
      action: 'update services'
    }))
  } catch (err) {
    console.error((err as Error).message)
    return 1
  }

  // Compute the new service array from the current resolved document.
  const current = Array.isArray(doc?.service) ? doc.service : []
  let services: ServiceEndpoint[]
  try {
    services = transform(current, targetDid)
  } catch (err) {
    console.error((err as Error).message)
    return 1
  }

  const stored = await loadStoredUpdateKeys(targetDid)

  // Choose the signer and key parameters. A sparse update normally omits
  // updateKeys/nextKeyHashes so the keys carry forward untouched; a
  // pre-rotation DID instead must reveal its staged key (which signs) and stage
  // a fresh one in the same entry.
  let signerKeyPair: Ed25519VerificationKey
  let updateKeys: string[] | undefined
  let nextKeyHashes: string[] | undefined
  let newActive: WebvhUpdateKey | undefined
  let newStaged: (WebvhUpdateKey & { nextKeyHash: string }) | undefined
  let retiredActive: WebvhUpdateKey | undefined
  try {
    if (meta.prerotation) {
      ;({ signerKeyPair, newActive, retiredActive } = await revealStagedSigner({
        stored,
        meta,
        targetDid,
        action: 'update services'
      }))
      newStaged = await generateStagedKey()
      updateKeys = [newActive.publicKeyMultibase]
      nextKeyHashes = [newStaged.nextKeyHash]
    } else {
      ;({ signerKeyPair } = await loadActiveSigner({
        stored,
        meta,
        targetDid,
        action: 'update services'
      }))
    }
  } catch (err) {
    console.error((err as Error).message)
    return 1
  }

  const confirmed = await confirmAction({
    message:
      `Update the services of ${targetDid}? This appends a new log entry ` +
      'and is hard to undo.',
    yes
  })
  if (!confirmed) {
    console.error('Aborted.')
    return 0
  }

  const signer = makeWebvhEntrySigner(signerKeyPair)

  let result: Awaited<ReturnType<typeof updateDID>>
  try {
    result = await updateDID({
      log,
      signer,
      verifier: webvhLogVerifier,
      services,
      ...(updateKeys ? { updateKeys } : {}),
      ...(nextKeyHashes ? { nextKeyHashes } : {})
    })
  } catch (err) {
    console.error(`Service update failed: ${(err as Error).message}`)
    return 1
  }

  const logPath = await saveDidLog({ did: result.did, log: result.log })
  const docPath = await saveToDids({
    method: 'webvh',
    did: result.did,
    data: result.doc
  })

  // Persist the advanced ratchet only on the pre-rotation path; an ordinary
  // service update leaves the update-keys sidecar untouched.
  if (meta.prerotation && newActive) {
    const updateKeysPath = await persistUpdateKeysSidecar({
      did: result.did,
      newActive,
      newStaged,
      retiredActive,
      stored,
      keepOldKey
    })
    console.error(`Update keys saved to ${updateKeysPath}`)
    console.error(
      'Pre-rotation: the update key was advanced as part of this change.'
    )
  }

  console.error(`DID document saved to ${docPath}`)
  console.error(`DID history log saved to ${logPath}`)
  console.log(
    JSON.stringify({ id: result.did, didDocument: result.doc }, null, 2)
  )
  return 0
}

/**
 * Resolve a DID reference, then route a service-array transform to the right
 * per-method runner and return its exit code. did:web is a direct document
 * edit; did:webvh appends a log entry.
 *
 * @param options {object}
 * @param options.ref {string} a DID or a local metadata handle.
 * @param options.transform {(current: ServiceEndpoint[], did: string) => ServiceEndpoint[]}
 * @param [options.yes] {boolean} skip the did:webvh confirmation prompt.
 * @param [options.keepOldKey] {boolean} did:webvh pre-rotation path only.
 * @returns {Promise<number>} the process exit code
 */
async function dispatchServiceUpdate({
  ref,
  transform,
  yes,
  keepOldKey
}: {
  ref: string
  transform: (current: ServiceEndpoint[], did: string) => ServiceEndpoint[]
  yes?: boolean
  keepOldKey?: boolean
}): Promise<number> {
  let resolved: string | undefined
  try {
    resolved = await resolveDidRef({ ref })
  } catch (err) {
    console.error((err as Error).message)
    return 1
  }
  const did = resolved ?? ref
  if (did.startsWith('did:web:')) {
    return runWebServiceUpdate({ did, transform })
  }
  if (did.startsWith('did:webvh:')) {
    return runWebvhServiceUpdate({ targetDid: did, transform, yes, keepOldKey })
  }
  console.error(
    'add-service/remove-service are only supported for did:web and ' +
      'did:webvh DIDs'
  )
  return 1
}

/**
 * Document loader for DID / DID-URL resolution. A bare DID resolves to its DID
 * document; a `did#fragment` URL is dereferenced straight to its
 * verification-method node. Works for did:key (offline), did:web, and did:webvh
 * (both fetched). Built once and reused. (Per project convention, DID/JSON-LD
 * resolution goes through `@interop/security-document-loader`, never a
 * hand-rolled loader.) The loader's default resolver only knows did:key and
 * did:web, so the did:webvh driver is registered onto a copy of the defaults
 * and injected -- keeping the did:webvh dependency out of the shared loader.
 */
const didResolver = createDefaultDidResolver()
// `CachedResolver.use` types its argument as the full generation-capable
// `DidMethodDriver`, but only reads `.method` (and later calls `.get`) for
// resolution; the webvh driver implements just that resolution subset.
didResolver.use(
  makeWebvhDriver() as unknown as Parameters<typeof didResolver.use>[0]
)
const documentLoader = securityLoader({ didResolver }).build()

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
      async (
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
      ) => {
        if (
          (options.handle !== undefined || options.description !== undefined) &&
          !options.save
        ) {
          console.error('--handle and --description require --save')
          process.exit(1)
          return
        }
        switch (method) {
          case 'key': {
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

                const didDriver = driver()
                didDriver.use({ keyPairClass: Ed25519VerificationKey })
                const { didDocument } = await didDriver.fromKeyPair({
                  verificationKeyPair: keyPair
                })

                if (options.save) {
                  const exported = await keyPair.export({
                    publicKey: true,
                    secretKey: true
                  })
                  await saveDidArtifacts({
                    method: 'key',
                    didDocument,
                    exportedKeys: exported,
                    fingerprints: [
                      (exported as { publicKeyMultibase?: string })
                        .publicKeyMultibase
                    ],
                    handle: options.handle,
                    description: options.description
                  })
                }

                const output: Record<string, unknown> = { id: didDocument.id }
                if (options.withSeed) {
                  output.secretKeySeed = secretKeySeed
                }
                output.didDocument = didDocument
                console.log(JSON.stringify(output, null, 2))
                break
              }
              case 'ecdsa': {
                if (options.withSeed) {
                  console.error(
                    '--with-seed is not supported for ecdsa keys; ECDSA key ' +
                      'generation is non-deterministic and cannot be derived ' +
                      'from a seed.'
                  )
                  process.exit(1)
                  return
                }
                const curve = normalizeEcdsaCurve({ curve: options.curve })
                if (!curve) {
                  console.error(
                    `Unknown ecdsa curve: ${options.curve}. ` +
                      `Supported: ${SUPPORTED_ECDSA_CURVES}`
                  )
                  process.exit(1)
                  return
                }
                warnIfNotVcIssuanceCapable({ curve })
                const keyPair = await EcdsaMultikey.generate({ curve })

                const didDriver = driver()
                const { didDocument } = await didDriver.fromKeyPair({
                  verificationKeyPair: keyPair
                })

                if (options.save) {
                  const exported = await keyPair.export({
                    publicKey: true,
                    secretKey: true
                  })
                  await saveDidArtifacts({
                    method: 'key',
                    didDocument,
                    exportedKeys: exported,
                    fingerprints: [
                      (exported as { publicKeyMultibase?: string })
                        .publicKeyMultibase
                    ],
                    handle: options.handle,
                    description: options.description
                  })
                }

                const output: Record<string, unknown> = { id: didDocument.id }
                output.didDocument = didDocument
                console.log(JSON.stringify(output, null, 2))
                break
              }
              default:
                console.error(
                  `Unknown key type: ${options.type}. Supported: ed25519, ecdsa`
                )
                process.exit(1)
            }
            break
          }
          case 'web': {
            switch (options.type) {
              case 'ed25519': {
                if (!options.url) {
                  console.error(
                    'did:web requires --url (e.g. --url https://example.com)'
                  )
                  process.exit(1)
                  return
                }
                const envSeed = process.env.SECRET_KEY_SEED
                const secretKeySeed = options.withSeed
                  ? (envSeed ?? (await generateSecretKeySeed()))
                  : envSeed
                const seedBytes = secretKeySeed
                  ? decodeSecretKeySeed({ secretKeySeed })
                  : undefined

                const didWebDriver = didWeb.driver()
                didWebDriver.use({ keyPairClass: Ed25519VerificationKey })
                const { didDocument, keyPairs } = await didWebDriver.generate({
                  url: options.url,
                  seed: seedBytes
                })

                if (options.save) {
                  const exported: Record<string, unknown> = {}
                  const fingerprints: (string | undefined)[] = []
                  for (const [methodId, keyPair] of keyPairs) {
                    const exportedKey = (await keyPair.export({
                      publicKey: true,
                      secretKey: true
                    })) as { publicKeyMultibase?: string }
                    exported[methodId] = exportedKey
                    fingerprints.push(exportedKey.publicKeyMultibase)
                  }
                  await saveDidArtifacts({
                    method: 'web',
                    didDocument,
                    exportedKeys: exported,
                    fingerprints,
                    handle: options.handle,
                    description: options.description
                  })
                }

                const output: Record<string, unknown> = { id: didDocument.id }
                if (options.withSeed) {
                  output.secretKeySeed = secretKeySeed
                }
                output.didDocument = didDocument
                console.log(JSON.stringify(output, null, 2))
                break
              }
              case 'ecdsa': {
                if (!options.url) {
                  console.error(
                    'did:web requires --url (e.g. --url https://example.com)'
                  )
                  process.exit(1)
                  return
                }
                if (options.withSeed) {
                  console.error(
                    '--with-seed is not supported for ecdsa keys; ECDSA key ' +
                      'generation is non-deterministic and cannot be derived ' +
                      'from a seed.'
                  )
                  process.exit(1)
                  return
                }
                const curve = normalizeEcdsaCurve({ curve: options.curve })
                if (!curve) {
                  console.error(
                    `Unknown ecdsa curve: ${options.curve}. ` +
                      `Supported: ${SUPPORTED_ECDSA_CURVES}`
                  )
                  process.exit(1)
                  return
                }
                warnIfNotVcIssuanceCapable({ curve })
                const keyPair = await EcdsaMultikey.generate({ curve })

                const didWebDriver = didWeb.driver()
                const { didDocument, keyPairs } = await didWebDriver.generate({
                  url: options.url,
                  verificationKeyPair: keyPair
                })

                if (options.save) {
                  const exported: Record<string, unknown> = {}
                  const fingerprints: (string | undefined)[] = []
                  for (const [methodId, savedKey] of keyPairs) {
                    const exportedKey = (await savedKey.export({
                      publicKey: true,
                      secretKey: true
                    })) as { publicKeyMultibase?: string }
                    exported[methodId] = exportedKey
                    fingerprints.push(exportedKey.publicKeyMultibase)
                  }
                  await saveDidArtifacts({
                    method: 'web',
                    didDocument,
                    exportedKeys: exported,
                    fingerprints,
                    handle: options.handle,
                    description: options.description
                  })
                }

                const output: Record<string, unknown> = { id: didDocument.id }
                output.didDocument = didDocument
                console.log(JSON.stringify(output, null, 2))
                break
              }
              default:
                console.error(
                  `Unknown key type: ${options.type}. ` +
                    `Supported: ed25519, ecdsa`
                )
                process.exit(1)
            }
            break
          }
          case 'webvh': {
            if (!options.url) {
              console.error(
                'did:webvh requires --url (e.g. --url https://example.com)'
              )
              process.exit(1)
              return
            }
            // The webvh library hardcodes the `eddsa-jcs-2022` cryptosuite, so
            // only Ed25519 update keys are supported for now.
            if (options.type !== 'ed25519') {
              console.error(
                `did:webvh only supports --type ed25519 (got ${options.type}); ` +
                  'the eddsa-jcs-2022 cryptosuite requires an Ed25519 key.'
              )
              process.exit(1)
              return
            }
            // Pre-rotation is the default; --no-prerotation opts out. With no
            // flag, commander leaves `prerotation` undefined, which is on.
            const prerotation = options.prerotation !== false
            // Portability is the default; --no-portable opts out (same shape).
            const portable = options.portable !== false

            // Witness declarations (declaration only -- generating the witness
            // proofs / did-witness.json sidecar is out of scope for now).
            const witnessDids = options.witness ?? []
            if (
              options.witnessThreshold !== undefined &&
              witnessDids.length === 0
            ) {
              console.error(
                '--witness-threshold requires at least one --witness'
              )
              process.exit(1)
              return
            }
            for (const witnessDid of witnessDids) {
              if (!witnessDid.startsWith('did:key:')) {
                console.error(
                  `Invalid witness "${witnessDid}": witnesses must be ` +
                    'did:key DIDs'
                )
                process.exit(1)
                return
              }
            }
            let witness:
              | { threshold: number; witnesses: { id: string }[] }
              | undefined
            if (witnessDids.length > 0) {
              let threshold = witnessDids.length
              if (options.witnessThreshold !== undefined) {
                threshold = Number.parseInt(options.witnessThreshold, 10)
                if (
                  !Number.isInteger(threshold) ||
                  threshold < 1 ||
                  threshold > witnessDids.length
                ) {
                  console.error(
                    '--witness-threshold must be an integer between 1 and the ' +
                      `number of witnesses (${witnessDids.length})`
                  )
                  process.exit(1)
                  return
                }
              }
              witness = {
                threshold,
                witnesses: witnessDids.map(id => ({ id }))
              }
            }

            // Watcher URLs: https:// (or http://localhost for local testing).
            const watchers = options.watcher ?? []
            for (const watcher of watchers) {
              let watcherUrl: URL
              try {
                watcherUrl = new URL(watcher)
              } catch {
                console.error(`Invalid watcher URL: ${watcher}`)
                process.exit(1)
                return
              }
              const isLocalhost =
                watcherUrl.protocol === 'http:' &&
                (watcherUrl.hostname === 'localhost' ||
                  watcherUrl.hostname === '127.0.0.1')
              if (watcherUrl.protocol !== 'https:' && !isLocalhost) {
                console.error(
                  `Invalid watcher URL "${watcher}": must be https:// ` +
                    '(or http://localhost)'
                )
                process.exit(1)
                return
              }
            }

            const envSeed = process.env.SECRET_KEY_SEED
            const secretKeySeed = options.withSeed
              ? (envSeed ?? (await generateSecretKeySeed()))
              : envSeed
            const seedBytes = secretKeySeed
              ? decodeSecretKeySeed({ secretKeySeed })
              : undefined

            // Update key A: the active authorization key. It is what the DID
            // identifier (SCID) derives from, so it is the seed-derived one.
            const updateKey = await Ed25519VerificationKey.generate({
              seed: seedBytes
            })
            const signer = makeWebvhEntrySigner(updateKey)

            // Document verification key V, decoupled from the update keys so
            // that rotating the update key never disturbs the document.
            const docKey = await Ed25519VerificationKey.generate()

            // Staged next update key B: when pre-rotation is on, commit its
            // hash now so the next update must reveal it.
            const stagedKey = prerotation
              ? await generateStagedKey()
              : undefined

            const result = await createDID({
              address: options.url,
              signer,
              verifier: signer,
              // A portable DID (the default) can later be moved to a different
              // domain; --no-portable pins it to its origin.
              portable,
              updateKeys: [updateKey.publicKeyMultibase],
              ...(stagedKey ? { nextKeyHashes: [stagedKey.nextKeyHash] } : {}),
              ...(witness ? { witness } : {}),
              ...(watchers.length > 0 ? { watchers } : {}),
              verificationMethods: [
                {
                  type: 'Multikey',
                  publicKeyMultibase: docKey.publicKeyMultibase,
                  // Wire the document key into the same relationships as did:web
                  // (everything but keyAgreement, which needs an X25519 key).
                  purpose: [
                    'authentication',
                    'assertionMethod',
                    'capabilityDelegation',
                    'capabilityInvocation'
                  ]
                }
              ]
            })

            if (options.save) {
              // Persist the document key V keyed by its document verification
              // method id (so it can be selected for signing), and set its id
              // to match.
              const docVmId = (
                result.doc as {
                  verificationMethod?: { id: string }[]
                }
              ).verificationMethod?.[0]?.id
              if (!docVmId) {
                console.error(
                  'Created did:webvh document is missing a verification method id'
                )
                process.exit(1)
                return
              }
              docKey.id = docVmId
              const exportedDoc = (await docKey.export({
                publicKey: true,
                secretKey: true
              })) as { publicKeyMultibase?: string }
              await saveDidArtifacts({
                method: 'webvh',
                didDocument: result.doc as { id: string },
                exportedKeys: { [docVmId]: exportedDoc },
                fingerprints: [exportedDoc.publicKeyMultibase],
                handle: options.handle,
                description: options.description
              })

              // Persist the update keys (active A, and staged B when armed) in
              // a sidecar distinct from the document's keys file.
              const updateKeysPath = await persistUpdateKeysSidecar({
                did: result.did,
                newActive: await exportUpdateKey(updateKey),
                newStaged: stagedKey
              })
              const logPath = await saveDidLog({
                did: result.did,
                log: result.log
              })
              console.error(`DID history log saved to ${logPath}`)
              console.error(`Update keys saved to ${updateKeysPath}`)
            }

            const output: Record<string, unknown> = { id: result.did }
            if (options.withSeed) {
              output.secretKeySeed = secretKeySeed
            }
            output.didDocument = result.doc
            console.log(JSON.stringify(output, null, 2))
            break
          }
          default:
            console.error(
              `Unknown method: ${method}. Supported: key, web, webvh`
            )
            process.exit(1)
        }
      }
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
        '(default: authentication, assertionMethod, capabilityDelegation, capabilityInvocation)'
    )
    .option(
      '--with-seed',
      'include the new secret key seed in output (generated if SECRET_KEY_SEED is not set)'
    )
    .action(
      async (
        did: string,
        options: {
          type: string
          curve: string
          purpose?: string[]
          withSeed?: boolean
        }
      ) => {
        if (!did.startsWith('did:web:')) {
          console.error('add-key is only supported for did:web DIDs')
          process.exit(1)
        }
        if (
          options.type !== 'ed25519' &&
          options.type !== 'ecdsa' &&
          options.type !== 'x25519'
        ) {
          console.error(
            `Unknown key type: ${options.type}. ` +
              'Supported: ed25519, ecdsa, x25519'
          )
          process.exit(1)
        }
        // x25519 keys are key agreement keys; they can only be wired into the
        // keyAgreement verification relationship.
        let purposes = options.purpose
        if (options.type === 'x25519') {
          if (
            purposes &&
            purposes.some(purpose => purpose !== 'keyAgreement')
          ) {
            console.error(
              'x25519 keys can only be added to the keyAgreement ' +
                'verification relationship'
            )
            process.exit(1)
            return
          }
          purposes = ['keyAgreement']
        }

        let didDocument: Record<string, unknown>
        let exportedKeys: Record<string, unknown>
        try {
          didDocument = await loadDidDocument(did)
          exportedKeys = await loadDidKeys(did)
        } catch {
          console.error(`No locally stored did:web found for ${did}`)
          process.exit(1)
        }

        // ed25519 keys are derived from a seed; ecdsa and x25519 keys are
        // generated non-deterministically and have no seed.
        let secretKeySeed: string | undefined
        let keyPair: any
        const didWebDriver = didWeb.driver()
        if (options.type === 'ed25519') {
          const envSeed = process.env.SECRET_KEY_SEED
          secretKeySeed = options.withSeed
            ? (envSeed ?? (await generateSecretKeySeed()))
            : envSeed
          const seedBytes = secretKeySeed
            ? decodeSecretKeySeed({ secretKeySeed })
            : undefined
          keyPair = await Ed25519VerificationKey.generate({ seed: seedBytes })
          didWebDriver.use({ keyPairClass: Ed25519VerificationKey })
        } else if (options.type === 'ecdsa') {
          if (options.withSeed) {
            console.error(
              '--with-seed is not supported for ecdsa keys; ECDSA key ' +
                'generation is non-deterministic and cannot be derived ' +
                'from a seed.'
            )
            process.exit(1)
            return
          }
          const curve = normalizeEcdsaCurve({ curve: options.curve })
          if (!curve) {
            console.error(
              `Unknown ecdsa curve: ${options.curve}. ` +
                `Supported: ${SUPPORTED_ECDSA_CURVES}`
            )
            process.exit(1)
            return
          }
          warnIfNotVcIssuanceCapable({ curve })
          keyPair = await EcdsaMultikey.generate({ curve })
        } else {
          if (options.withSeed) {
            console.error(
              '--with-seed is not supported for x25519 keys; X25519 key ' +
                'generation is non-deterministic and cannot be derived ' +
                'from a seed.'
            )
            process.exit(1)
            return
          }
          keyPair = await X25519KeyAgreementKey2020.generate()
        }

        const keyPairs = new Map<string, any>()
        try {
          await didWebDriver.addVerificationMethod({
            didDocument,
            keyPairs,
            keyPair,
            purposes
          })
        } catch (err) {
          console.error((err as Error).message)
          process.exit(1)
        }

        // Merge the new key into the stored keys file (keyed by VM id). X25519
        // keys export their private half as `privateKeyMultibase`, the other
        // suites as `secretKeyMultibase`.
        const addedFingerprints: (string | undefined)[] = []
        for (const [methodId, addedKey] of keyPairs) {
          const exportedKey = (await addedKey.export(
            options.type === 'x25519'
              ? { publicKey: true, privateKey: true }
              : { publicKey: true, secretKey: true }
          )) as { publicKeyMultibase?: string }
          exportedKeys[methodId] = exportedKey
          addedFingerprints.push(exportedKey.publicKeyMultibase)
        }
        const docPath = await saveToDids({
          method: 'web',
          did,
          data: didDocument
        })
        await saveToDids({
          method: 'web',
          did,
          suffix: 'keys',
          data: exportedKeys
        })
        // Update the key-to-DID cache of any matching wallet keys; the DID's
        // own metadata sidecar is left untouched.
        for (const fingerprint of addedFingerprints) {
          if (fingerprint) {
            await recordKeyDidAssociation({
              publicKeyMultibase: fingerprint,
              did
            })
          }
        }
        console.error(`DID saved to ${docPath}`)

        const output: Record<string, unknown> = { id: didDocument.id }
        if (options.withSeed) {
          output.secretKeySeed = secretKeySeed
        }
        output.didDocument = didDocument
        console.log(JSON.stringify(output, null, 2))
      }
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
        const code = await dispatchServiceUpdate({
          ref: did,
          transform,
          yes: options.yes,
          keepOldKey: options.keepOldKey
        })
        if (code !== 0) {
          process.exit(code)
        }
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
        const code = await dispatchServiceUpdate({
          ref: did,
          transform,
          yes: options.yes,
          keepOldKey: options.keepOldKey
        })
        if (code !== 0) {
          process.exit(code)
        }
      }
    )

  did
    .command('get <did>')
    .aliases(['resolve'])
    .description(
      'Resolve a DID to its DID document, or a DID URL (a did#fragment key ' +
        'id) to its verification method, via the security document loader'
    )
    .action(async (didOrKeyId: string) => {
      let document: Record<string, unknown>
      try {
        ;({ document } = (await documentLoader(didOrKeyId)) as {
          document: Record<string, unknown>
        })
      } catch (err) {
        console.error(
          `Could not resolve "${didOrKeyId}": ${(err as Error).message}`
        )
        process.exit(1)
        return
      }
      console.log(JSON.stringify(document, null, 2))
    })

  did
    .command('show <did>')
    .aliases(['view', 'cat'])
    .description(
      'Show a locally stored DID document (no secret key material) by DID ' +
        'or handle'
    )
    .option('--meta', 'show the DID metadata instead of the DID document')
    .option('--json', 'with --meta, output the metadata as JSON')
    .action(
      async (didRef: string, options: { meta?: boolean; json?: boolean }) => {
        let did: string | undefined
        try {
          did = await resolveDidRef({ ref: didRef })
        } catch (err) {
          console.error((err as Error).message)
          process.exit(1)
          return
        }
        let didDocument: Record<string, unknown>
        try {
          didDocument = await loadDidDocument(did ?? didRef)
        } catch {
          console.error(`No locally stored DID found for ${didRef}`)
          process.exit(1)
          return
        }

        if (options.meta) {
          const docDid = didDocument.id as string
          const meta = await loadDidMeta({ did: docDid })
          const keyCount = Array.isArray(didDocument.verificationMethod)
            ? didDocument.verificationMethod.length
            : 0
          if (options.json) {
            const output = {
              did: docDid,
              method: docDid.split(':')[1],
              ...(meta?.created && { created: meta.created }),
              ...(meta?.handle && { handle: meta.handle }),
              ...(meta?.description && { description: meta.description }),
              keys: keyCount
            }
            console.log(JSON.stringify(output, null, 2))
            return
          }
          const rows = [
            ['DID', docDid],
            ['Method', docDid.split(':')[1]],
            ['Handle', meta?.handle ?? ''],
            ['Created', meta?.created ?? ''],
            ['Description', meta?.description ?? ''],
            ['Keys', String(keyCount)]
          ]
          console.log(
            renderTable({
              columns: [{ header: 'FIELD' }, { header: 'VALUE' }],
              rows
            })
          )
          return
        }

        // The stored DID document holds no secret material -- signing keys live in
        // the separate `<did>.keys.json` file -- so it is safe to print as-is.
        console.log(JSON.stringify(didDocument, null, 2))
      }
    )

  did
    .command('list')
    .description('List locally stored DIDs with their metadata')
    .option(
      '--json',
      'output the list as a JSON array of objects with metadata'
    )
    .option('--plain', 'output one DID per line, sorted (no metadata)')
    .action(async (options: { json?: boolean; plain?: boolean }) => {
      const dids = await listDids()
      if (options.plain) {
        for (const did of dids) {
          console.log(did)
        }
        return
      }

      const entries: ({ did: string; method: string } & ItemMetadata)[] = []
      for (const did of dids) {
        const meta = await loadDidMeta({ did })
        entries.push({ did, method: did.split(':')[1], ...meta })
      }

      if (options.json) {
        const output = entries.map(entry => ({
          did: entry.did,
          method: entry.method,
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
        entry.method,
        entry.created?.slice(0, 10) ?? '',
        entry.did,
        entry.description ?? ''
      ])
      console.log(
        renderTable({
          columns: [
            { header: 'HANDLE', maxWidth: 16 },
            { header: 'METHOD' },
            { header: 'CREATED' },
            { header: 'DID', maxWidth: 44 },
            { header: 'DESCRIPTION', maxWidth: 40 }
          ],
          rows
        })
      )
    })

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
      async (
        didRef: string,
        options: { handle?: string; description?: string }
      ) => {
        let did: string | undefined
        try {
          did = await resolveDidRef({ ref: didRef })
        } catch (err) {
          console.error((err as Error).message)
          process.exit(1)
          return
        }
        if (did) {
          // Refuse to create metadata for DIDs that are not saved locally.
          try {
            await loadDidDocument(did)
          } catch {
            did = undefined
          }
        }
        if (!did) {
          console.error(`No locally stored DID found for ${didRef}`)
          process.exit(1)
          return
        }

        const existing = await loadDidMeta({ did })
        const hasEdits =
          options.handle !== undefined || options.description !== undefined
        if (!hasEdits) {
          console.log(JSON.stringify(existing ?? {}, null, 2))
          return
        }

        const meta: ItemMetadata = { ...(existing ?? {}) }
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
        const filePath = await saveDidMeta({ did, meta })
        console.error(`Metadata saved to ${filePath}`)
        console.log(JSON.stringify(meta, null, 2))
      }
    )

  did
    .command('remove <did>')
    .aliases(['delete', 'rm'])
    .description(
      'Remove a locally stored DID document, its keys file, and its ' +
        'metadata sidecar (by DID or handle)'
    )
    .action(async (didRef: string) => {
      let did: string | undefined
      try {
        did = await resolveDidRef({ ref: didRef })
      } catch (err) {
        console.error((err as Error).message)
        process.exit(1)
        return
      }
      let didDocument: {
        verificationMethod?: { publicKeyMultibase?: string }[]
      }
      try {
        didDocument = await loadDidDocument(did ?? didRef)
      } catch {
        console.error(`No locally stored DID found for ${didRef}`)
        process.exit(1)
        return
      }
      const docDid = did ?? didRef
      // Scrub the cached key-to-DID associations of any matching wallet keys
      // before the DID document (the source of truth) is deleted.
      for (const method of didDocument.verificationMethod ?? []) {
        if (method.publicKeyMultibase) {
          await removeKeyDidAssociation({
            publicKeyMultibase: method.publicKeyMultibase,
            did: docDid
          })
        }
      }
      const removed = await removeDidFiles({ did: docDid })
      for (const filePath of removed) {
        console.error(`Removed ${filePath}`)
      }
    })

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
      async (
        didRef: string,
        options: {
          updateKey?: string[]
          enablePrerotation?: boolean
          stopPrerotation?: boolean
          keepOldKey?: boolean
          yes?: boolean
        }
      ) => {
        let resolved: string | undefined
        try {
          resolved = await resolveDidRef({ ref: didRef })
        } catch (err) {
          console.error((err as Error).message)
          process.exit(1)
          return
        }
        const targetDid = resolved ?? didRef
        if (!targetDid.startsWith('did:webvh:')) {
          console.error('rotate-keys is only supported for did:webvh DIDs')
          process.exit(1)
          return
        }
        // The history log is the source of truth for a stored did:webvh (the
        // current document is just its last entry's state), so a key-only
        // rotation ignores the resolved document.
        let log: DIDLog
        let meta: Awaited<ReturnType<typeof resolveDIDFromLog>>['meta']
        try {
          ;({ log, meta } = await resolveWebvhForUpdate({
            targetDid,
            action: 'rotate keys'
          }))
        } catch (err) {
          console.error((err as Error).message)
          process.exit(1)
          return
        }

        // Flag validation against the current pre-rotation state.
        if (options.enablePrerotation && options.stopPrerotation) {
          console.error(
            '--enable-prerotation and --stop-prerotation are mutually exclusive'
          )
          process.exit(1)
          return
        }
        if (meta.prerotation) {
          if (options.updateKey) {
            console.error(
              '--update-key is not allowed while pre-rotation is armed; the ' +
                'next update keys are fixed by the committed nextKeyHashes'
            )
            process.exit(1)
            return
          }
          if (options.enablePrerotation) {
            console.error('pre-rotation is already enabled for this DID')
            process.exit(1)
            return
          }
        } else if (options.stopPrerotation) {
          console.error('pre-rotation is already off for this DID')
          process.exit(1)
          return
        }

        const stored = await loadStoredUpdateKeys(targetDid)

        // Inbound: who signs this entry, and what becomes the active key.
        let signerKeyPair: Ed25519VerificationKey
        let newActive: WebvhUpdateKey
        let retiredActive: WebvhUpdateKey | undefined
        try {
          if (meta.prerotation) {
            // Pre-rotation reveal: the staged key signs its own activation.
            ;({ signerKeyPair, newActive, retiredActive } =
              await revealStagedSigner({
                stored,
                meta,
                targetDid,
                action: 'rotate keys'
              }))
          } else {
            // Ordinary rotation: the current active key signs.
            let activeRecord: WebvhUpdateKey
            ;({ signerKeyPair, activeRecord } = await loadActiveSigner({
              stored,
              meta,
              targetDid,
              action: 'rotate keys'
            }))
            if (options.enablePrerotation && !options.updateKey) {
              // Stage only: arm pre-rotation without changing the active key.
              newActive = activeRecord
            } else if (options.updateKey) {
              // Rotate to externally-held key(s); the secret is not ours to store.
              newActive = { publicKeyMultibase: options.updateKey[0] }
              retiredActive = activeRecord
            } else {
              newActive = await exportUpdateKey(
                await Ed25519VerificationKey.generate()
              )
              retiredActive = activeRecord
            }
          }
        } catch (err) {
          console.error((err as Error).message)
          process.exit(1)
          return
        }

        // Outbound: keep the ratchet armed (stage a fresh next key) or not.
        const arm = meta.prerotation
          ? !options.stopPrerotation
          : Boolean(options.enablePrerotation)
        const newStaged = arm ? await generateStagedKey() : undefined
        const nextKeyHashes = newStaged ? [newStaged.nextKeyHash] : []

        const confirmed = await confirmAction({
          message:
            `Rotate the update key of ${targetDid}? This appends a new log ` +
            'entry and is hard to undo.',
          yes: options.yes
        })
        if (!confirmed) {
          console.error('Aborted.')
          return
        }

        const signer = makeWebvhEntrySigner(signerKeyPair)

        // A sparse updateDID() carries the prior DID document state forward and
        // only overlays the fields an update actually supplies, so a key-only
        // rotation omits all document directives to leave the document
        // unchanged.
        let result: Awaited<ReturnType<typeof updateDID>>
        try {
          result = await updateDID({
            log,
            signer,
            verifier: webvhLogVerifier,
            updateKeys: [newActive.publicKeyMultibase],
            nextKeyHashes
          })
        } catch (err) {
          console.error(`Key rotation failed: ${(err as Error).message}`)
          process.exit(1)
          return
        }

        const logPath = await saveDidLog({ did: result.did, log: result.log })
        const docPath = await saveToDids({
          method: 'webvh',
          did: result.did,
          data: result.doc
        })

        const updateKeysPath = await persistUpdateKeysSidecar({
          did: result.did,
          newActive,
          newStaged,
          retiredActive,
          stored,
          keepOldKey: options.keepOldKey
        })

        console.error(`DID document saved to ${docPath}`)
        console.error(`DID history log saved to ${logPath}`)
        console.error(`Update keys saved to ${updateKeysPath}`)
        console.error(
          nextKeyHashes.length > 0
            ? 'Pre-rotation is armed: a next update key is staged.'
            : 'Pre-rotation is off after this rotation.'
        )

        console.log(
          JSON.stringify({ id: result.did, didDocument: result.doc }, null, 2)
        )
      }
    )

  did.addCommand(webvh)

  return did
}
