/**
 * Builds a `WasClient` from a DID stored in the local wallet plus a server
 * URL, resolving both from flags, environment variables, and the local space
 * registry. The signing DID resolution order is the `--did` flag (a DID or a
 * metadata handle), then the `WAS_DID` environment variable, then the
 * `controller` recorded in the registry entry for the addressed space. The
 * server URL resolution order is the origin of a full space URL address,
 * then the `--server` flag, then `WAS_SERVER_URL`, then the `server`
 * recorded in the registry entry.
 *
 * Only locally stored `did:key` DIDs with Ed25519 keys are supported for
 * signing (the constraint of the `Ed25519Signature2020` zcap suite used by
 * `@interop/was-client`).
 */
import { WasClient } from '@interop/was-client'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'
import { createSigner } from '@interop/ed25519-signature'
import type { ISigner } from '@interop/data-integrity-core'
import {
  loadDidDocument,
  loadDidKeys,
  type ItemMetadata,
  type StoredKeyPair
} from '../storage.js'
import { resolveDidRef } from '../meta.js'
import { parseWasAddress } from './address.js'
import { resolveSpaceRef, type SpaceRecord } from './registry.js'

/**
 * The multibase prefix of an Ed25519 `publicKeyMultibase`. Both Ed25519 and
 * ECDSA keys export as `type: 'Multikey'`, so the multicodec prefix of the
 * public key is what identifies the curve.
 */
const ED25519_MULTIBASE_PREFIX = 'z6Mk'

/**
 * Constructs the `WasClient` for a resolved server URL and signer. Kept as a
 * replaceable factory so command tests can substitute a stubbed client (no
 * network) while exercising the full resolution path.
 */
type WasClientFactory = (options: {
  serverUrl: string
  signer: ISigner
}) => WasClient

function defaultWasClientFactory({
  serverUrl,
  signer
}: {
  serverUrl: string
  signer: ISigner
}): WasClient {
  return WasClient.fromSigner({ serverUrl, signer })
}

let wasClientFactory: WasClientFactory = defaultWasClientFactory

/**
 * Replaces the `WasClient` construction step (a test-only seam). Call with
 * no argument to restore the default factory.
 *
 * @param [factory] {WasClientFactory}
 * @returns {void}
 */
export function setWasClientFactory(factory?: WasClientFactory): void {
  wasClientFactory = factory ?? defaultWasClientFactory
}

/**
 * A fully resolved WAS command target: the client to talk to the server
 * with, the resolved server URL and signing DID, the addressed space /
 * collection / resource ids, and the local registry entry for the space
 * (when one exists).
 */
export interface ResolvedWasTarget {
  client: WasClient
  server: string
  did: string
  spaceId: string
  collectionId?: string
  resourceId?: string
  entry?: { storageId: string; record: SpaceRecord; meta?: ItemMetadata }
}

/**
 * Loads the WAS invocation signer from a locally stored DID. Only `did:key`
 * DIDs with Ed25519 keys are supported; anything else is rejected with a
 * clear error.
 *
 * @param options {object}
 * @param options.did {string}   A DID or the metadata handle of a stored DID.
 * @returns {Promise<{did: string, signer: ISigner}>}
 */
export async function loadWasSigner({
  did
}: {
  did: string
}): Promise<{ did: string; signer: ISigner }> {
  const resolved = await resolveDidRef({ ref: did })
  if (!resolved) {
    throw new Error(`No locally stored DID found for "${did}".`)
  }
  if (!resolved.startsWith('did:key:')) {
    throw new Error(
      `WAS signing currently supports only did:key DIDs (got ${resolved}).`
    )
  }
  try {
    await loadDidDocument(resolved)
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
      throw new Error(
        `DID ${resolved} is not in local storage; save it first with ` +
          '"di did create --save".',
        { cause: err }
      )
    }
    throw err
  }
  const keysData = await loadDidKeys<StoredKeyPair>(resolved)
  // Both Ed25519 and ECDSA keys export as `type: 'Multikey'`; the curve is
  // identified by the multicodec prefix of the public key.
  if (!keysData.publicKeyMultibase?.startsWith(ED25519_MULTIBASE_PREFIX)) {
    throw new Error(
      'WAS signing currently supports only Ed25519 keys ' +
        `(DID ${resolved} has a different key type).`
    )
  }
  const keyPair = await Ed25519VerificationKey.from(keysData)
  return { did: resolved, signer: createSigner(keyPair) }
}

/**
 * Builds a `WasClient` from an explicit server URL and signing DID,
 * falling back to the `WAS_SERVER_URL` and `WAS_DID` environment variables.
 * Used by commands that do not address an existing space (e.g.
 * `was space create`).
 *
 * @param options {object}
 * @param [options.server] {string}   The server base URL.
 * @param [options.did] {string}   A DID or stored-DID metadata handle.
 * @returns {Promise<{client: WasClient, server: string, did: string}>}
 */
export async function buildWasClient({
  server,
  did
}: {
  server?: string
  did?: string
} = {}): Promise<{ client: WasClient; server: string; did: string }> {
  const serverUrl = server ?? process.env.WAS_SERVER_URL
  if (!serverUrl) {
    throw new Error(
      'No WAS server URL: provide --server or set WAS_SERVER_URL.'
    )
  }
  const didRef = did ?? process.env.WAS_DID
  if (!didRef) {
    throw new Error('No signing DID: provide --did or set WAS_DID.')
  }
  const { did: resolvedDid, signer } = await loadWasSigner({ did: didRef })
  const client = wasClientFactory({ serverUrl, signer })
  return { client, server: serverUrl, did: resolvedDid }
}

/**
 * Resolves a WAS address into a ready-to-use command target: parses the
 * `SPACE[/COLLECTION[/RESOURCE]]` path, consults the local space registry
 * for the space reference (handle or id), resolves the server URL and
 * signing DID from the flags / environment / registry entry, and builds the
 * signed `WasClient`.
 *
 * @param options {object}
 * @param options.address {string}   The positional WAS path.
 * @param [options.server] {string}   The `--server` flag value.
 * @param [options.did] {string}   The `--did` flag value (DID or handle).
 * @returns {Promise<ResolvedWasTarget>}
 */
export async function resolveWasTarget({
  address,
  server,
  did
}: {
  address: string
  server?: string
  did?: string
}): Promise<ResolvedWasTarget> {
  const parsed = parseWasAddress(address)
  const entry = await resolveSpaceRef({ ref: parsed.spaceRef })
  const spaceId = entry?.record.id ?? parsed.spaceRef

  const serverUrl =
    parsed.server ??
    server ??
    process.env.WAS_SERVER_URL ??
    entry?.record.server
  if (!serverUrl) {
    throw new Error(
      `No WAS server URL for space "${parsed.spaceRef}": use a full space ` +
        'URL, provide --server or WAS_SERVER_URL, or register the space ' +
        'with "di was space add".'
    )
  }

  const didRef = did ?? process.env.WAS_DID ?? entry?.record.controller
  if (!didRef) {
    throw new Error(
      `No signing DID for space "${parsed.spaceRef}": provide --did or ` +
        'WAS_DID, or register the space with its controller DID.'
    )
  }
  const { did: resolvedDid, signer } = await loadWasSigner({ did: didRef })
  const client = wasClientFactory({ serverUrl, signer })

  return {
    client,
    server: serverUrl,
    did: resolvedDid,
    spaceId,
    ...(parsed.collectionId !== undefined && {
      collectionId: parsed.collectionId
    }),
    ...(parsed.resourceId !== undefined && { resourceId: parsed.resourceId }),
    ...(entry && { entry })
  }
}
