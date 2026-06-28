/**
 * Read/manage operations over locally stored DIDs: `get` (resolve via the
 * security document loader), `show` (display a stored document or its
 * metadata), `list`, `meta` (show/edit the metadata sidecar), and `remove`.
 * For did:webvh, `show` resolves the current document from its history log --
 * the source of truth -- via `./webvh-update.js`.
 */
import { type resolveDIDFromLog } from '@interop/did-method-webvh'
import {
  didStorageFiles,
  listDids,
  loadDidDocument,
  loadDidMeta,
  methodOf,
  removeDidFiles,
  saveDidMeta,
  type ItemMetadata
} from '../../storage.js'
import { removeKeyDidAssociation, resolveDidRef } from '../../meta.js'
import { renderTable } from '../../table.js'
import { documentLoader } from '../../documentLoader.js'
import { applyMetaEdits } from '../collection-command.js'
import { resolveStoredWebvh } from './webvh-update.js'

/**
 * Resolve a DID to its DID document, or a DID URL to its verification method,
 * via the security document loader, and print the result.
 *
 * @param options {object}
 * @param options.didOrKeyId {string}   The DID or DID URL to resolve.
 * @returns {Promise<number>}   The process exit code.
 */
export async function runGet(options: { didOrKeyId: string }): Promise<number> {
  const { didOrKeyId } = options
  let document: Record<string, unknown>
  try {
    ;({ document } = (await documentLoader(didOrKeyId)) as {
      document: Record<string, unknown>
    })
  } catch (err) {
    console.error(
      `Could not resolve "${didOrKeyId}": ${(err as Error).message}`
    )
    return 1
  }
  console.log(JSON.stringify(document, null, 2))
  return 0
}

/**
 * Show a locally stored DID document (no secret key material), or its metadata
 * with `--meta`, by DID or handle. For did:webvh the document is resolved from
 * its history log rather than the stored snapshot.
 *
 * @param options {object}
 * @param options.didRef {string}   The DID or metadata handle.
 * @param [options.meta] {boolean}   Show the metadata instead of the document.
 * @param [options.json] {boolean}   With --meta, output the metadata as JSON.
 * @returns {Promise<number>}   The process exit code.
 */
export async function runShow(options: {
  didRef: string
  meta?: boolean
  json?: boolean
}): Promise<number> {
  const { didRef } = options
  let did: string | undefined
  try {
    did = await resolveDidRef({ ref: didRef })
  } catch (err) {
    console.error((err as Error).message)
    return 1
  }
  const targetDid = did ?? didRef

  // For did:webvh the history log is the source of truth, so resolve the
  // current document (and its accumulated parameters) from it rather than
  // trusting the stored snapshot. A DID with no stored log falls through
  // to the stored document below.
  let webvhMeta:
    Awaited<ReturnType<typeof resolveDIDFromLog>>['meta'] | undefined
  let resolvedDoc: Record<string, unknown> | undefined
  if (targetDid.startsWith('did:webvh:')) {
    let resolved: Awaited<ReturnType<typeof resolveStoredWebvh>>
    try {
      resolved = await resolveStoredWebvh(targetDid)
    } catch (err) {
      console.error(
        `Could not resolve the DID log for ${targetDid}: ` +
          (err as Error).message
      )
      return 1
    }
    if (resolved) {
      resolvedDoc = resolved.doc as Record<string, unknown>
      webvhMeta = resolved.meta
    }
  }

  let didDocument: Record<string, unknown>
  if (resolvedDoc) {
    didDocument = resolvedDoc
  } else {
    try {
      didDocument = await loadDidDocument(targetDid)
    } catch {
      console.error(`No locally stored DID found for ${didRef}`)
      return 1
    }
  }

  if (options.meta) {
    const docDid = didDocument.id as string
    const meta = await loadDidMeta({ did: docDid })
    const keyCount = Array.isArray(didDocument.verificationMethod)
      ? didDocument.verificationMethod.length
      : 0
    // Parameters resolved from the did:webvh log (absent for other
    // methods, and for a webvh DID with no stored log).
    const witnessCount = webvhMeta?.witness?.witnesses?.length ?? 0
    const watcherCount = webvhMeta?.watchers?.length ?? 0
    if (options.json) {
      const output = {
        did: docDid,
        method: methodOf(docDid),
        ...(meta?.created && { created: meta.created }),
        ...(meta?.handle && { handle: meta.handle }),
        ...(meta?.description && { description: meta.description }),
        keys: keyCount,
        ...(webvhMeta && {
          versionId: webvhMeta.versionId,
          updated: webvhMeta.updated,
          portable: webvhMeta.portable,
          prerotation: webvhMeta.prerotation,
          deactivated: webvhMeta.deactivated,
          updateKeys: webvhMeta.updateKeys.length,
          witnesses: witnessCount,
          watchers: watcherCount
        })
      }
      console.log(JSON.stringify(output, null, 2))
      return 0
    }
    const rows = [
      ['DID', docDid],
      ['Method', methodOf(docDid)],
      ['Handle', meta?.handle ?? ''],
      ['Created', meta?.created ?? ''],
      ['Description', meta?.description ?? ''],
      ['Keys', String(keyCount)]
    ]
    if (webvhMeta) {
      rows.push(
        ['Version', webvhMeta.versionId],
        ['Updated', webvhMeta.updated],
        ['Portable', webvhMeta.portable ? 'yes' : 'no'],
        ['Prerotation', webvhMeta.prerotation ? 'yes' : 'no'],
        ['Deactivated', webvhMeta.deactivated ? 'yes' : 'no'],
        ['Update keys', String(webvhMeta.updateKeys.length)],
        ['Witnesses', String(witnessCount)],
        ['Watchers', String(watcherCount)]
      )
    }
    console.log(
      renderTable({
        columns: [{ header: 'FIELD' }, { header: 'VALUE' }],
        rows
      })
    )
    return 0
  }

  // The DID document holds no secret material -- signing keys live in the
  // separate `<did>.keys.json` file -- so it is safe to print as-is.
  console.log(JSON.stringify(didDocument, null, 2))
  return 0
}

/**
 * List locally stored DIDs with their metadata: one DID per line with
 * `--plain`, a JSON array with `--json`, otherwise a column-aligned table.
 *
 * @param options {object}
 * @param [options.json] {boolean}   Output a JSON array of objects.
 * @param [options.plain] {boolean}   Output one DID per line, sorted.
 * @returns {Promise<number>}   The process exit code.
 */
export async function runList(options: {
  json?: boolean
  plain?: boolean
}): Promise<number> {
  const dids = await listDids()
  if (options.plain) {
    for (const did of dids) {
      console.log(did)
    }
    return 0
  }

  const entries: ({ did: string; method: string } & ItemMetadata)[] = []
  for (const did of dids) {
    const meta = await loadDidMeta({ did })
    entries.push({ did, method: methodOf(did), ...meta })
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
    return 0
  }

  if (entries.length === 0) {
    return 0
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
  return 0
}

/**
 * Show or edit the metadata of a locally stored DID (by DID or handle). With no
 * edits, prints the current metadata; otherwise applies the handle/description
 * changes and saves the sidecar.
 *
 * @param options {object}
 * @param options.didRef {string}   The DID or metadata handle.
 * @param [options.handle] {string}   Set the handle (empty string clears it).
 * @param [options.description] {string}   Set the description (empty clears it).
 * @returns {Promise<number>}   The process exit code.
 */
export async function runMeta(options: {
  didRef: string
  handle?: string
  description?: string
  json?: boolean
}): Promise<number> {
  const { didRef } = options
  let did: string | undefined
  try {
    did = await resolveDidRef({ ref: didRef })
  } catch (err) {
    console.error((err as Error).message)
    return 1
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
    return 1
  }

  const existing = await loadDidMeta({ did })
  const hasEdits =
    options.handle !== undefined || options.description !== undefined
  if (!hasEdits) {
    const files = (await didStorageFiles({ did })).filter(file => file.exists)
    if (options.json) {
      // Machine-readable: fold the on-disk locations into the JSON output.
      console.log(
        JSON.stringify(
          { metadata: existing ?? {}, files: fileLocations(files) },
          null,
          2
        )
      )
      return 0
    }
    // Report where the DID's artifacts live on disk (stderr, so stdout stays
    // the pure metadata JSON). Skips files that do not exist for this DID.
    if (files.length > 0) {
      console.error('Location:')
      for (const file of files) {
        console.error(`  ${file.label}: ${file.path}`)
      }
    }
    console.log(JSON.stringify(existing ?? {}, null, 2))
    return 0
  }

  const meta: ItemMetadata = { ...(existing ?? {}) }
  applyMetaEdits(meta, {
    handle: options.handle,
    description: options.description
  })
  const filePath = await saveDidMeta({ did, meta })
  console.error(`Metadata saved to ${filePath}`)
  if (options.json) {
    const files = (await didStorageFiles({ did })).filter(file => file.exists)
    console.log(
      JSON.stringify({ metadata: meta, files: fileLocations(files) }, null, 2)
    )
  } else {
    console.log(JSON.stringify(meta, null, 2))
  }
  return 0
}

/**
 * Build the `files` map for `did meta --json`: the existing artifacts keyed by
 * a camelCase label (`update-keys` becomes `updateKeys`).
 *
 * @param files {{ label: string, path: string, exists: boolean }[]}
 * @returns {Record<string, string>}
 */
function fileLocations(
  files: { label: string; path: string; exists: boolean }[]
): Record<string, string> {
  const locations: Record<string, string> = {}
  for (const file of files) {
    const key = file.label === 'update-keys' ? 'updateKeys' : file.label
    locations[key] = file.path
  }
  return locations
}

/**
 * Remove a locally stored DID document, its keys file, and its metadata
 * sidecar (by DID or handle), scrubbing the cached key-to-DID associations.
 *
 * @param options {object}
 * @param options.didRef {string}   The DID or metadata handle.
 * @returns {Promise<number>}   The process exit code.
 */
export async function runRemove(options: { didRef: string }): Promise<number> {
  const { didRef } = options
  let did: string | undefined
  try {
    did = await resolveDidRef({ ref: didRef })
  } catch (err) {
    console.error((err as Error).message)
    return 1
  }
  let didDocument: {
    verificationMethod?: { publicKeyMultibase?: string }[]
  }
  try {
    didDocument = await loadDidDocument(did ?? didRef)
  } catch {
    console.error(`No locally stored DID found for ${didRef}`)
    return 1
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
  return 0
}
