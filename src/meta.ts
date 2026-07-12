/**
 * Metadata derivation and resolution logic layered on top of the raw storage
 * helpers: parsing key storage IDs, deriving key-to-DID associations from the
 * stored DID documents, caching those associations in key metadata sidecars,
 * and resolving user-supplied key, DID, zcap, and credential references
 * (fingerprint / DID / capability or credential id, or metadata handle).
 */

import {
  findStoredKey,
  listCollection,
  listDids,
  loadDidDocument,
  loadDidMeta,
  loadFromCollection,
  loadMetaFromCollection,
  saveMetaToCollection,
  type ItemMetadata,
  type KeyMetadata,
  type StoredKeyPair
} from './storage.js'

/**
 * Parse a key storage ID of the form `YYYY-MM-DD-<type>[-<curve>]-<rawId>`
 * into its date, key type, and (for ecdsa) curve components. Returns empty
 * fields for storage IDs that do not match the convention.
 *
 * @param options {object}
 * @param options.storageId {string}
 * @returns {{date?: string, type?: string, curve?: string}}
 */
export function parseKeyStorageId({ storageId }: { storageId: string }): {
  date?: string
  type?: string
  curve?: string
} {
  const match = storageId.match(
    /^(\d{4}-\d{2}-\d{2})-(ed25519|ecdsa|x25519|hmac|aes256)(?:-(p\d{3}))?-/
  )
  if (!match) {
    return {}
  }
  return { date: match[1], type: match[2], curve: match[3] }
}

/**
 * Derive the key-to-DID associations from the locally stored DID documents.
 *
 * Performs a single pass over all saved DIDs and returns a map from each
 * verification method's publicKeyMultibase to the sorted DIDs whose documents
 * reference it. This is the source of truth shown by `key list` / `key show`;
 * the `dids` cached in key metadata sidecars is never displayed directly.
 *
 * @returns {Promise<Map<string, string[]>>}
 */
export async function mapFingerprintsToDids(): Promise<Map<string, string[]>> {
  const fingerprintDids = new Map<string, string[]>()
  const dids = await listDids()
  for (const did of dids) {
    const didDocument = await loadDidDocument<{
      verificationMethod?: { publicKeyMultibase?: string }[]
    }>(did)
    for (const method of didDocument.verificationMethod ?? []) {
      if (!method.publicKeyMultibase) {
        continue
      }
      const entries = fingerprintDids.get(method.publicKeyMultibase) ?? []
      if (!entries.includes(did)) {
        entries.push(did)
      }
      fingerprintDids.set(method.publicKeyMultibase, entries)
    }
  }
  for (const entries of fingerprintDids.values()) {
    entries.sort()
  }
  return fingerprintDids
}

/**
 * Record in a wallet key's metadata sidecar that the key participates in a
 * DID document. No-op when no wallet key matches the fingerprint. The cached
 * `dids` list is deduplicated and sorted; the sidecar is created if needed.
 *
 * @param options {object}
 * @param options.publicKeyMultibase {string}
 * @param options.did {string}
 * @returns {Promise<void>}
 */
export async function recordKeyDidAssociation({
  publicKeyMultibase,
  did
}: {
  publicKeyMultibase: string
  did: string
}): Promise<void> {
  const found = await findStoredKey({ fingerprint: publicKeyMultibase })
  if (!found) {
    return
  }
  const meta =
    (await loadMetaFromCollection<KeyMetadata>({
      collection: 'keys',
      storageId: found.storageId
    })) ?? {}
  const dids = [...new Set([...(meta.dids ?? []), did])].sort()
  await saveMetaToCollection({
    collection: 'keys',
    storageId: found.storageId,
    meta: { ...meta, dids }
  })
}

/**
 * Remove a DID from a wallet key's cached `dids` associations, the inverse of
 * `recordKeyDidAssociation`. No-op when no wallet key matches the fingerprint
 * or the key's sidecar does not cache the DID.
 *
 * @param options {object}
 * @param options.publicKeyMultibase {string}
 * @param options.did {string}
 * @returns {Promise<void>}
 */
export async function removeKeyDidAssociation({
  publicKeyMultibase,
  did
}: {
  publicKeyMultibase: string
  did: string
}): Promise<void> {
  const found = await findStoredKey({ fingerprint: publicKeyMultibase })
  if (!found) {
    return
  }
  const meta = await loadMetaFromCollection<KeyMetadata>({
    collection: 'keys',
    storageId: found.storageId
  })
  if (!meta?.dids?.includes(did)) {
    return
  }
  const dids = meta.dids.filter(entry => entry !== did)
  const updated: KeyMetadata = { ...meta }
  if (dids.length > 0) {
    updated.dids = dids
  } else {
    delete updated.dids
  }
  await saveMetaToCollection({
    collection: 'keys',
    storageId: found.storageId,
    meta: updated
  })
}

/**
 * Resolve a metadata handle to a single storage id by scanning the `.meta.json`
 * sidecars of a set of items. This is the shared core of every `resolve*Ref`
 * helper: the direct id/fingerprint match stays in each caller, and this
 * collapses the "scan handles, collect matches, complain on ambiguity" tail.
 * Returns undefined when no handle matches; throws when more than one does
 * (handles are not unique).
 *
 * @param options {object}
 * @param options.ref {string}             The handle to match.
 * @param options.noun {string}            Plural noun for the ambiguity message (e.g. `zcaps`).
 * @param options.alternative {string}     The unambiguous identifier to suggest instead.
 * @param options.storageIds {string[]}    The storage ids to scan.
 * @param options.loadMeta {(storageId: string) => Promise<MetaType | undefined>}
 *   Loads the metadata sidecar for a storage id.
 * @returns {Promise<{storageId: string, meta: MetaType} | undefined>}
 */
export async function resolveByHandle<MetaType extends { handle?: string }>({
  ref,
  noun,
  alternative,
  storageIds,
  loadMeta
}: {
  ref: string
  noun: string
  alternative: string
  storageIds: string[]
  loadMeta: (storageId: string) => Promise<MetaType | undefined>
}): Promise<{ storageId: string; meta: MetaType } | undefined> {
  const matches: { storageId: string; meta: MetaType }[] = []
  for (const storageId of storageIds) {
    const meta = await loadMeta(storageId)
    if (meta?.handle === ref) {
      matches.push({ storageId, meta })
    }
  }
  if (matches.length === 0) {
    return undefined
  }
  if (matches.length > 1) {
    throw new Error(
      `Handle "${ref}" matches ${matches.length} ${noun}; ` +
        `use the ${alternative} instead.`
    )
  }
  return matches[0]
}

/**
 * Resolve a user-supplied DID reference -- a full DID or a metadata handle --
 * to a stored DID. Anything starting with `did:` is returned as-is; otherwise
 * the metadata sidecars of all stored DIDs are searched for a matching
 * handle. Throws when a handle matches more than one DID (handles are not
 * unique). Returns undefined when nothing matches.
 *
 * @param options {object}
 * @param options.ref {string}
 * @returns {Promise<string | undefined>}
 */
export async function resolveDidRef({
  ref
}: {
  ref: string
}): Promise<string | undefined> {
  if (ref.startsWith('did:')) {
    return ref
  }
  const match = await resolveByHandle({
    ref,
    noun: 'DIDs',
    alternative: 'full DID',
    storageIds: await listDids(),
    loadMeta: did => loadDidMeta({ did })
  })
  return match?.storageId
}

/**
 * A stored Authorization Capability (zcap), as loaded from wallet storage.
 * Only the fields the CLI inspects are typed; the loaded object retains
 * whatever else the stored JSON carries (e.g. `@context`, `proof`).
 */
export interface StoredZcap {
  id?: string
  controller?: string
  invocationTarget?: string
  parentCapability?: string
  expires?: string
}

/**
 * Resolve a user-supplied zcap reference -- a capability id (the `urn:...`
 * value shown by `zcap list`) or a metadata handle -- to a stored zcap.
 * Capability id matches take precedence; otherwise the metadata sidecars are
 * searched for a matching handle. Throws when a handle matches more than one
 * zcap (handles are not unique). Returns undefined when nothing matches.
 *
 * @param options {object}
 * @param options.ref {string}
 * @returns {Promise<{storageId: string, zcap: StoredZcap, meta?: ItemMetadata} | undefined>}
 */
export async function resolveZcapRef({ ref }: { ref: string }): Promise<
  | {
      storageId: string
      zcap: StoredZcap
      meta?: ItemMetadata
    }
  | undefined
> {
  const storageIds = await listCollection('zcaps')
  for (const storageId of storageIds) {
    const zcap = await loadFromCollection<StoredZcap>({
      collection: 'zcaps',
      storageId
    })
    if (zcap.id === ref) {
      const meta = await loadMetaFromCollection({
        collection: 'zcaps',
        storageId
      })
      return { storageId, zcap, meta }
    }
  }
  const match = await resolveByHandle({
    ref,
    noun: 'zcaps',
    alternative: 'capability id',
    storageIds,
    loadMeta: storageId =>
      loadMetaFromCollection({ collection: 'zcaps', storageId })
  })
  if (!match) {
    return undefined
  }
  const zcap = await loadFromCollection<StoredZcap>({
    collection: 'zcaps',
    storageId: match.storageId
  })
  return { storageId: match.storageId, zcap, meta: match.meta }
}

/**
 * A stored Verifiable Credential, as loaded from wallet storage. Only the
 * fields the CLI inspects are typed; the loaded object retains whatever else
 * the stored JSON carries (e.g. `@context`, `credentialSubject`, `proof`).
 */
export interface StoredCredential {
  id?: string
  type?: string | string[]
  issuer?: string | { id?: string }
  validFrom?: string
  validUntil?: string
  issuanceDate?: string
  expirationDate?: string
}

/**
 * Resolve a user-supplied credential reference -- a credential id, a storage
 * id (the file name shown for id-less credentials), or a metadata handle --
 * to a stored credential. Credential id matches take precedence, then storage
 * id matches; otherwise the metadata sidecars are searched for a matching
 * handle. Throws when a handle matches more than one credential (handles are
 * not unique). Returns undefined when nothing matches.
 *
 * @param options {object}
 * @param options.ref {string}
 * @returns {Promise<{storageId: string, credential: StoredCredential, meta?: ItemMetadata} | undefined>}
 */
export async function resolveCredentialRef({ ref }: { ref: string }): Promise<
  | {
      storageId: string
      credential: StoredCredential
      meta?: ItemMetadata
    }
  | undefined
> {
  const storageIds = await listCollection('credentials')
  for (const storageId of storageIds) {
    const credential = await loadFromCollection<StoredCredential>({
      collection: 'credentials',
      storageId
    })
    if (credential.id === ref) {
      const meta = await loadMetaFromCollection({
        collection: 'credentials',
        storageId
      })
      return { storageId, credential, meta }
    }
  }
  if (storageIds.includes(ref)) {
    const credential = await loadFromCollection<StoredCredential>({
      collection: 'credentials',
      storageId: ref
    })
    const meta = await loadMetaFromCollection({
      collection: 'credentials',
      storageId: ref
    })
    return { storageId: ref, credential, meta }
  }
  const match = await resolveByHandle({
    ref,
    noun: 'credentials',
    alternative: 'credential id',
    storageIds,
    loadMeta: storageId =>
      loadMetaFromCollection({ collection: 'credentials', storageId })
  })
  if (!match) {
    return undefined
  }
  const credential = await loadFromCollection<StoredCredential>({
    collection: 'credentials',
    storageId: match.storageId
  })
  return { storageId: match.storageId, credential, meta: match.meta }
}

/**
 * Resolve a user-supplied key reference -- a publicKeyMultibase fingerprint
 * or a metadata handle -- to a stored wallet key. Fingerprint matches take
 * precedence; otherwise the metadata sidecars are searched for a matching
 * handle. Throws when a handle matches more than one key (handles are not
 * unique). Returns undefined when nothing matches.
 *
 * @param options {object}
 * @param options.ref {string}
 * @returns {Promise<{storageId: string, key: StoredKeyPair, meta?: KeyMetadata} | undefined>}
 */
export async function resolveKeyRef({ ref }: { ref: string }): Promise<
  | {
      storageId: string
      key: StoredKeyPair
      meta?: KeyMetadata
    }
  | undefined
> {
  const byFingerprint = await findStoredKey({ fingerprint: ref })
  if (byFingerprint) {
    const meta = await loadMetaFromCollection<KeyMetadata>({
      collection: 'keys',
      storageId: byFingerprint.storageId
    })
    return { ...byFingerprint, meta }
  }
  const match = await resolveByHandle({
    ref,
    noun: 'keys',
    alternative: 'publicKeyMultibase fingerprint',
    storageIds: await listCollection('keys'),
    loadMeta: storageId =>
      loadMetaFromCollection<KeyMetadata>({ collection: 'keys', storageId })
  })
  if (!match) {
    return undefined
  }
  const key = await loadFromCollection<StoredKeyPair>({
    collection: 'keys',
    storageId: match.storageId
  })
  return { storageId: match.storageId, key, meta: match.meta }
}
