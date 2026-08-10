/**
 * Service-entry management for did:web and did:webvh DIDs. Builds and edits the
 * `service` array (add/remove by id, with id normalization) and routes a
 * service-array transform to the right per-method runner: did:web is a direct
 * document edit, did:webvh appends a sparse log entry (advancing the
 * pre-rotation ratchet when one is armed). The webvh log machinery is reused
 * from `./webvh-update.js`.
 */
import {
  resolveDIDFromLog,
  updateDID,
  type DIDLog,
  type ServiceEndpoint
} from '@interop/did-method-webvh'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'
import {
  loadDidDocument,
  saveToDids,
  type WebvhUpdateKey,
  type WebvhUpdateKeys
} from '../../storage.js'
import { resolveDidRef } from '../../meta.js'
import { generateStagedKey } from '../../keys/webvh-update.js'
import {
  appendWebvhEntry,
  confirmAction,
  loadActiveSigner,
  loadStoredUpdateKeys,
  makeWebvhEntrySigner,
  persistWebvhUpdate,
  resolveWebvhForUpdate,
  revealStagedSigner
} from './webvh-update.js'

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
export function normalizeServiceId({
  did,
  id
}: {
  did: string
  id: string
}): string {
  if (id.startsWith('#')) {
    return `${did}${id}`
  }
  if (id.startsWith('did:') || id.includes('#')) {
    return id
  }
  return `${did}#${id}`
}

/**
 * Build (and validate) the serviceEndpoint value from add-service options.
 * Exactly one of `endpoint` (one or more endpoint values -- a single value
 * stays a string, several become an array) or `endpointJson` (a raw JSON
 * value) must supply it. Needs no DID, so the CLI layer calls it up front to
 * reject bad arguments before any (expensive) log resolution.
 *
 * @param options {object}
 * @param [options.endpoint] {string[]}
 * @param [options.endpointJson] {string}
 * @returns {ServiceEndpoint['serviceEndpoint']}
 */
export function buildServiceEndpoint({
  endpoint,
  endpointJson
}: {
  endpoint?: string[]
  endpointJson?: string
}): ServiceEndpoint['serviceEndpoint'] {
  const hasEndpoint = Boolean(endpoint?.length)
  const hasEndpointJson = Boolean(endpointJson)
  // True when both are supplied or neither is -- i.e. not exactly one.
  if (hasEndpoint === hasEndpointJson) {
    throw new Error('Provide exactly one of --endpoint or --endpoint-json.')
  }
  if (endpointJson) {
    try {
      return JSON.parse(endpointJson)
    } catch {
      throw new Error('--endpoint-json must be valid JSON.')
    }
  }
  return endpoint!.length === 1 ? endpoint![0] : endpoint
}

/**
 * Build a service-endpoint entry from add-service options (see
 * `buildServiceEndpoint` for the serviceEndpoint rules); a single `type`
 * stays a string.
 *
 * @param options {object}
 * @param options.did {string}
 * @param options.id {string}
 * @param options.type {string[]}
 * @param [options.endpoint] {string[]}
 * @param [options.endpointJson] {string}
 * @returns {ServiceEndpoint}
 */
export function buildServiceEntry({
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
  return {
    id: normalizeServiceId({ did, id }),
    type: type.length === 1 ? type[0] : type,
    serviceEndpoint: buildServiceEndpoint({ endpoint, endpointJson })
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
export function addServiceEntry({
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
export function removeServiceEntry({
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

  let stored: WebvhUpdateKeys | undefined
  try {
    stored = await loadStoredUpdateKeys(targetDid)
  } catch (err) {
    console.error((err as Error).message)
    return 1
  }

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
    return 1
  }

  const signer = makeWebvhEntrySigner(signerKeyPair)

  let result: Awaited<ReturnType<typeof updateDID>>
  try {
    result = await appendWebvhEntry({
      log,
      meta,
      signer,
      services,
      ...(updateKeys ? { updateKeys } : {}),
      ...(nextKeyHashes ? { nextKeyHashes } : {})
    })
  } catch (err) {
    console.error(`Service update failed: ${(err as Error).message}`)
    return 1
  }

  // The advanced ratchet is persisted only on the pre-rotation path; an
  // ordinary service update leaves the update-keys sidecar untouched.
  const { logPath, docPath, updateKeysPath } = await persistWebvhUpdate({
    result,
    sidecar:
      meta.prerotation && newActive
        ? { newActive, newStaged, retiredActive, stored, keepOldKey }
        : undefined
  })
  if (updateKeysPath !== undefined) {
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
export async function dispatchServiceUpdate({
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
