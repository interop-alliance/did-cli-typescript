/**
 * Recipient and key-agreement resolution for the `edv encrypt`/`edv decrypt`
 * commands. Normalizes the several recipient reference forms (a raw X25519
 * `publicKeyMultibase`, a wallet key fingerprint or handle, a DID or DID URL,
 * and a key-document JSON file) to the static public-key shape the
 * `@interop/minimal-cipher` `keyResolver` must return, builds the recipients
 * array plus that resolver, and reconstructs a stored X25519 secret key into
 * the `{ id, deriveSecret }` key-agreement API the cipher decrypts with.
 */
import { readFile } from 'node:fs/promises'
import { securityLoader } from '@interop/security-document-loader'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import { listCollection, loadFromCollection } from '../storage.js'
import { resolveKeyRef } from '../meta.js'

/** The X25519 key-agreement verification-method type minimal-cipher expects. */
export const KEY_AGREEMENT_TYPE = 'X25519KeyAgreementKey2020'

/** The key-wrap algorithm the `recommended` cipher version uses. */
export const KEY_WRAP_ALG = 'ECDH-ES+A256KW'

/**
 * Document loader for DID-URL recipient resolution: resolves a bare DID to its
 * DID document and dereferences a `did#fragment` URL straight to its
 * verification-method node, for both did:key (offline) and did:web (fetched).
 * Built once and reused. (Per project convention, DID/JSON-LD resolution goes
 * through `@interop/security-document-loader`, never a hand-rolled loader.)
 */
const documentLoader = securityLoader().build()

/**
 * A resolved recipient public key, in the static form minimal-cipher's
 * `keyResolver` must return and that the X25519 algorithm reads
 * `publicKeyMultibase` from.
 */
export interface RecipientKey {
  id: string
  type: 'X25519KeyAgreementKey2020'
  publicKeyMultibase: string
}

/** A stored X25519 key pair, as persisted by `key create --type x25519`. */
interface StoredKeyAgreementKey {
  id?: string
  type?: string
  publicKeyMultibase?: string
  privateKeyMultibase?: string
}

/**
 * Derive the `kid` for a recipient key: the verification-method `id` when the
 * key has one, otherwise a synthetic `did:key:<mb>#<mb>` built from the
 * multibase. The `kid` chosen at encrypt time must equal the `.id` of the key
 * used to decrypt for a round-trip to succeed, so encrypt and decrypt both
 * route every key through this function.
 *
 * @param options {object}
 * @param [options.id] {string}
 * @param options.publicKeyMultibase {string}
 * @returns {string}
 */
function recipientKeyId({
  id,
  publicKeyMultibase
}: {
  id?: string
  publicKeyMultibase: string
}): string {
  return id ?? `did:key:${publicKeyMultibase}#${publicKeyMultibase}`
}

/**
 * Split a DID URL into its base DID and `#fragment` (undefined when absent).
 *
 * @param options {object}
 * @param options.ref {string}
 * @returns {{did: string, fragment?: string}}
 */
function splitFragment({ ref }: { ref: string }): {
  did: string
  fragment?: string
} {
  const hash = ref.indexOf('#')
  if (hash === -1) {
    return { did: ref }
  }
  return { did: ref.slice(0, hash), fragment: ref.slice(hash + 1) }
}

/**
 * Resolve a DID URL through the security document loader. A bare DID resolves
 * to its DID document; a `did#fragment` URL is dereferenced straight to its
 * verification-method node.
 *
 * @param options {object}
 * @param options.url {string}
 * @returns {Promise<Record<string, any>>}
 */
async function resolveDidUrl({
  url
}: {
  url: string
}): Promise<Record<string, any>> {
  const { document } = (await documentLoader(url)) as {
    document: Record<string, any>
  }
  return document
}

/**
 * Validate that a verification method is a usable X25519 key-agreement key and
 * normalize it to a {@link RecipientKey}.
 *
 * @param options {object}
 * @param options.method {Record<string, any>}
 * @param options.ref {string}
 * @returns {RecipientKey}
 */
function toRecipientKey({
  method,
  ref
}: {
  method: Record<string, any>
  ref: string
}): RecipientKey {
  if (method.type !== KEY_AGREEMENT_TYPE || !method.publicKeyMultibase) {
    throw new Error(`Recipient "${ref}" is not an ${KEY_AGREEMENT_TYPE} key.`)
  }
  return {
    id: recipientKeyId({
      id: method.id,
      publicKeyMultibase: method.publicKeyMultibase
    }),
    type: KEY_AGREEMENT_TYPE,
    publicKeyMultibase: method.publicKeyMultibase
  }
}

/**
 * Resolve a DID or DID URL recipient to its X25519 key-agreement key. A bare
 * DID with a single keyAgreement key uses that key; one with several requires
 * the `#fragment` form to disambiguate.
 *
 * @param options {object}
 * @param options.ref {string}
 * @returns {Promise<RecipientKey>}
 */
async function resolveDidRecipient({
  ref
}: {
  ref: string
}): Promise<RecipientKey> {
  const { did, fragment } = splitFragment({ ref })

  // A fragment URL dereferences straight to its verification-method node.
  if (fragment !== undefined) {
    return toRecipientKey({ method: await resolveDidUrl({ url: ref }), ref })
  }

  // A bare DID: pick the single keyAgreement key, dereferencing any entries
  // that are id references rather than embedded verification methods.
  const didDocument = await resolveDidUrl({ url: did })
  const entries = (didDocument.keyAgreement ?? []) as (
    | string
    | Record<string, any>
  )[]
  const methods: Record<string, any>[] = []
  for (const entry of entries) {
    methods.push(
      typeof entry === 'string' ? await resolveDidUrl({ url: entry }) : entry
    )
  }

  const usable = methods.filter(
    method => method.type === KEY_AGREEMENT_TYPE && method.publicKeyMultibase
  )
  if (usable.length === 0) {
    throw new Error(`DID ${did} has no ${KEY_AGREEMENT_TYPE} keyAgreement key.`)
  }
  if (usable.length > 1) {
    throw new Error(
      `DID ${did} has ${usable.length} keyAgreement keys; ` +
        'use the did#fragment form to choose one.'
    )
  }
  return toRecipientKey({ method: usable[0], ref })
}

/**
 * Resolve one `--recipient` value to a recipient public key. Resolution order:
 * a raw X25519 `publicKeyMultibase` (starts `z6LS`), then a DID / DID URL, then
 * a wallet key fingerprint or handle.
 *
 * @param options {object}
 * @param options.ref {string}
 * @returns {Promise<RecipientKey>}
 */
export async function resolveRecipient({
  ref
}: {
  ref: string
}): Promise<RecipientKey> {
  if (ref.startsWith('z6LS')) {
    return {
      id: recipientKeyId({ publicKeyMultibase: ref }),
      type: KEY_AGREEMENT_TYPE,
      publicKeyMultibase: ref
    }
  }
  if (ref.startsWith('did:')) {
    return resolveDidRecipient({ ref })
  }
  const resolved = await resolveKeyRef({ ref })
  if (!resolved?.key.publicKeyMultibase) {
    throw new Error(`Could not resolve recipient "${ref}".`)
  }
  const stored = resolved.key as StoredKeyAgreementKey
  if (stored.type !== KEY_AGREEMENT_TYPE) {
    throw new Error(`Wallet key "${ref}" is not an ${KEY_AGREEMENT_TYPE} key.`)
  }
  return {
    id: recipientKeyId({
      id: stored.id,
      publicKeyMultibase: stored.publicKeyMultibase as string
    }),
    type: KEY_AGREEMENT_TYPE,
    publicKeyMultibase: stored.publicKeyMultibase as string
  }
}

/**
 * Load and validate a key-document JSON file holding an X25519 public key, and
 * normalize it to a {@link RecipientKey}.
 *
 * @param options {object}
 * @param options.path {string}
 * @returns {Promise<RecipientKey>}
 */
export async function resolveRecipientFile({
  path
}: {
  path: string
}): Promise<RecipientKey> {
  let method: Record<string, any>
  try {
    method = JSON.parse(await readFile(path, 'utf8'))
  } catch (err) {
    throw new Error(
      `Could not read key document "${path}": ${(err as Error).message}`,
      {
        cause: err
      }
    )
  }
  return toRecipientKey({ method, ref: path })
}

/**
 * Build the minimal-cipher `recipients` array and the `keyResolver` closure
 * over the resolved recipient keys. `keyResolver({ id })` returns the static
 * public key for a recipient and throws when the id is unknown.
 *
 * @param options {object}
 * @param options.keys {RecipientKey[]}
 * @returns {{recipients: {header: {kid: string, alg: string}}[], keyResolver: Function}}
 */
export function buildRecipients({ keys }: { keys: RecipientKey[] }): {
  recipients: { header: { kid: string; alg: string } }[]
  keyResolver: (options: { id?: string }) => Promise<RecipientKey>
} {
  const byId = new Map(keys.map(key => [key.id, key]))
  const recipients = keys.map(key => ({
    header: { kid: key.id, alg: KEY_WRAP_ALG }
  }))
  async function keyResolver({ id }: { id?: string }): Promise<RecipientKey> {
    const key = id ? byId.get(id) : undefined
    if (!key) {
      throw new Error(`No public key for recipient "${id}".`)
    }
    return key
  }
  return { recipients, keyResolver }
}

/**
 * Reconstruct a stored X25519 key pair into the `{ id, deriveSecret }`
 * key-agreement API minimal-cipher decrypts with, setting `.id` to the same
 * `kid` encrypt would have used so `_findRecipient` matches.
 *
 * @param options {object}
 * @param options.stored {StoredKeyAgreementKey}
 * @returns {Promise<X25519KeyAgreementKey2020>}
 */
async function reconstructKeyAgreementKey({
  stored
}: {
  stored: StoredKeyAgreementKey
}): Promise<InstanceType<typeof X25519KeyAgreementKey2020> & { id: string }> {
  const key = await X25519KeyAgreementKey2020.from(stored)
  key.id = recipientKeyId({
    id: stored.id,
    publicKeyMultibase: stored.publicKeyMultibase as string
  })
  return key as InstanceType<typeof X25519KeyAgreementKey2020> & { id: string }
}

/**
 * Resolve a `--key` reference (fingerprint or handle) to a reconstructed
 * X25519 key-agreement key. The referenced key must be a stored X25519 key
 * with its secret half.
 *
 * @param options {object}
 * @param options.ref {string}
 * @returns {Promise<X25519KeyAgreementKey2020>}
 */
export async function loadKeyAgreementKey({
  ref
}: {
  ref: string
}): Promise<InstanceType<typeof X25519KeyAgreementKey2020> & { id: string }> {
  const resolved = await resolveKeyRef({ ref })
  if (!resolved) {
    throw new Error(`No locally stored key found for "${ref}".`)
  }
  const stored = resolved.key as StoredKeyAgreementKey
  if (stored.type !== KEY_AGREEMENT_TYPE) {
    throw new Error(`Wallet key "${ref}" is not an ${KEY_AGREEMENT_TYPE} key.`)
  }
  if (!stored.privateKeyMultibase) {
    throw new Error(`Wallet key "${ref}" has no secret key to decrypt with.`)
  }
  return reconstructKeyAgreementKey({ stored })
}

/**
 * Auto-select the decryption key when `--key` is omitted: scan the stored
 * X25519 secret keys and return the one whose `kid` matches a recipient of the
 * JWE. Throws when none match or more than one does.
 *
 * @param options {object}
 * @param options.jwe {{recipients?: {header?: {kid?: string}}[]}}
 * @returns {Promise<X25519KeyAgreementKey2020>}
 */
export async function autoSelectKeyAgreementKey({
  jwe
}: {
  jwe: { recipients?: { header?: { kid?: string } }[] }
}): Promise<InstanceType<typeof X25519KeyAgreementKey2020> & { id: string }> {
  const kids = new Set(
    (jwe.recipients ?? [])
      .map(recipient => recipient?.header?.kid)
      .filter((kid): kid is string => typeof kid === 'string')
  )
  const storageIds = await listCollection('keys')
  const matches: StoredKeyAgreementKey[] = []
  for (const storageId of storageIds) {
    const stored = await loadFromCollection<StoredKeyAgreementKey>(
      'keys',
      storageId
    )
    if (
      stored.type !== KEY_AGREEMENT_TYPE ||
      !stored.privateKeyMultibase ||
      !stored.publicKeyMultibase
    ) {
      continue
    }
    const kid = recipientKeyId({
      id: stored.id,
      publicKeyMultibase: stored.publicKeyMultibase
    })
    if (kids.has(kid)) {
      matches.push(stored)
    }
  }
  if (matches.length === 0) {
    throw new Error(
      'No stored X25519 key matches any recipient of this JWE; ' +
        'pass --key to choose one.'
    )
  }
  if (matches.length > 1) {
    throw new Error(
      `${matches.length} stored X25519 keys match this JWE; ` +
        'pass --key to choose one.'
    )
  }
  return reconstructKeyAgreementKey({ stored: matches[0] })
}
