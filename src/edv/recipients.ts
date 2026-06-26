/**
 * Recipient and key-agreement resolution for the `edv encrypt`/`edv decrypt`
 * commands. Normalizes the several recipient reference forms (a raw X25519
 * `publicKeyMultibase`, a wallet key fingerprint or handle, a DID or DID URL,
 * and a key-document JSON file) into `X25519KeyAgreementKey2020` instances --
 * the shape `@interop/minimal-cipher`'s `keyResolver` returns (the cipher reads
 * `id` and `publicKeyMultibase` from a recipient on encrypt, and `id` and
 * `deriveSecret` from the key on decrypt, all of which an instance provides).
 * Builds the recipients array plus that resolver, and reconstructs stored keys
 * for decrypt.
 */
import { readFile } from 'node:fs/promises'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import { documentLoader } from '../documentLoader.js'
import { listCollection, loadFromCollection } from '../storage.js'
import { resolveKeyRef } from '../meta.js'

/** The X25519 key-agreement verification-method type minimal-cipher expects. */
export const KEY_AGREEMENT_TYPE = 'X25519KeyAgreementKey2020'

/** The multibase prefix of an X25519 `publicKeyMultibase`. */
export const X25519_MULTIBASE_PREFIX = 'z6LS'

/**
 * A verification-method node (or a DID document) carrying the fields recipient
 * resolution reads: the key `type` and `publicKeyMultibase`, plus `id` /
 * `controller` (for the did:key default) and a DID document's `keyAgreement`
 * array. All fields are optional -- a recipient may be a raw public key with no
 * id/controller, a key file, or a full DID document -- so the library's strict
 * `IVerificationMethod` / `IDIDDocument` types (which require `id`/`controller`/
 * `@context` and a literal `type`) do not fit; other JSON-LD fields a resolved
 * document carries are simply ignored.
 */
interface VerificationMethodNode {
  id?: string
  controller?: string
  type?: string
  publicKeyMultibase?: string
  keyAgreement?: (string | VerificationMethodNode)[]
}

/**
 * An X25519 key-agreement key instance with its `.id` (`kid`) populated. Used
 * both as a resolved recipient (encrypt reads `id` + `publicKeyMultibase`) and
 * as the decryption key (decrypt reads `id` + `deriveSecret`).
 */
export type KeyAgreementKey = InstanceType<typeof X25519KeyAgreementKey2020> & {
  id: string
}

/** A stored X25519 key pair, as persisted by `key create --type x25519`. */
interface StoredKeyAgreementKey {
  id?: string
  type?: string
  publicKeyMultibase?: string
  privateKeyMultibase?: string
}

/**
 * Construct an X25519 key-agreement key from a verification method or stored
 * key pair. `didKey: true` defaults a source with no `controller`/`id` to its
 * `did:key` form, so the key class derives `.id` as `did:key:<mb>#<mb>` -- the
 * `kid` encrypt and decrypt both match on -- while a source that already
 * carries an `id`/`controller` (e.g. a DID verification method) keeps it. A
 * `type: 'Multikey'` source is normalized via `fromMultikey`. The constructor
 * validates the multibase header bytes.
 *
 * @param source {VerificationMethodNode}
 * @returns {Promise<KeyAgreementKey>}
 */
async function keyAgreementKeyFrom(
  source: VerificationMethodNode
): Promise<KeyAgreementKey> {
  const key = await X25519KeyAgreementKey2020.from({ didKey: true, ...source })
  return key as KeyAgreementKey
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
 * @returns {Promise<VerificationMethodNode>}
 */
async function resolveDidUrl({
  url
}: {
  url: string
}): Promise<VerificationMethodNode> {
  const { document } = (await documentLoader(url)) as {
    document: VerificationMethodNode
  }
  return document
}

/**
 * True when a `publicKeyMultibase` carries the X25519 multicodec header. This
 * is the type-agnostic discriminator for a usable key-agreement key: it accepts
 * both an `X25519KeyAgreementKey2020` and a `Multikey` whose key is X25519,
 * while rejecting an Ed25519/other key, regardless of the `type` string a DID
 * document happens to use.
 *
 * @param publicKeyMultibase {string | undefined}
 * @returns {boolean}
 */
function isX25519PublicKey(publicKeyMultibase?: string): boolean {
  if (!publicKeyMultibase) {
    return false
  }
  try {
    // The constructor validates the X25519 header bytes and throws otherwise.
    X25519KeyAgreementKey2020.fromFingerprint({
      fingerprint: publicKeyMultibase
    })
    return true
  } catch {
    return false
  }
}

/**
 * Validate that a verification method is a usable X25519 key-agreement key
 * (an `X25519KeyAgreementKey2020` or a `Multikey` whose public key is X25519)
 * and construct it.
 *
 * @param options {object}
 * @param options.method {VerificationMethodNode}
 * @param options.ref {string}
 * @returns {Promise<KeyAgreementKey>}
 */
async function toKeyAgreementKey({
  method,
  ref
}: {
  method: VerificationMethodNode
  ref: string
}): Promise<KeyAgreementKey> {
  if (!isX25519PublicKey(method.publicKeyMultibase)) {
    throw new Error(`Recipient "${ref}" is not an ${KEY_AGREEMENT_TYPE} key.`)
  }
  return keyAgreementKeyFrom(method)
}

/**
 * Resolve a DID or DID URL recipient to its X25519 key-agreement key. A bare
 * DID with a single keyAgreement key uses that key; one with several requires
 * the `#fragment` form to disambiguate.
 *
 * @param options {object}
 * @param options.ref {string}
 * @returns {Promise<KeyAgreementKey>}
 */
async function resolveDidRecipient({
  ref
}: {
  ref: string
}): Promise<KeyAgreementKey> {
  const { did, fragment } = splitFragment({ ref })

  // A fragment URL dereferences straight to its verification-method node.
  if (fragment !== undefined) {
    return toKeyAgreementKey({ method: await resolveDidUrl({ url: ref }), ref })
  }

  // A bare DID: pick the single keyAgreement key, dereferencing any entries
  // that are id references rather than embedded verification methods.
  const didDocument = await resolveDidUrl({ url: did })
  const entries = didDocument.keyAgreement ?? []
  const methods: VerificationMethodNode[] = []
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
  return toKeyAgreementKey({ method: usable[0], ref })
}

/**
 * Resolve one `--recipient` value to a recipient key. Resolution order: a raw
 * X25519 `publicKeyMultibase` (starts `z6LS`), then a DID / DID URL, then a
 * wallet key fingerprint or handle.
 *
 * @param options {object}
 * @param options.ref {string}
 * @returns {Promise<KeyAgreementKey>}
 */
export async function resolveRecipient({
  ref
}: {
  ref: string
}): Promise<KeyAgreementKey> {
  if (ref.startsWith(X25519_MULTIBASE_PREFIX)) {
    return toKeyAgreementKey({
      method: { type: KEY_AGREEMENT_TYPE, publicKeyMultibase: ref },
      ref
    })
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
  return keyAgreementKeyFrom(stored)
}

/**
 * Load and validate a key-document JSON file holding an X25519 public key, and
 * construct its key-agreement key.
 *
 * @param options {object}
 * @param options.path {string}
 * @returns {Promise<KeyAgreementKey>}
 */
export async function resolveRecipientFile({
  path
}: {
  path: string
}): Promise<KeyAgreementKey> {
  let method: VerificationMethodNode
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
  return toKeyAgreementKey({ method, ref: path })
}

/**
 * Resolve a `--key` reference (fingerprint or handle) to a reconstructed
 * X25519 key-agreement key. The referenced key must be a stored X25519 key
 * with its secret half.
 *
 * @param options {object}
 * @param options.ref {string}
 * @returns {Promise<KeyAgreementKey>}
 */
export async function loadKeyAgreementKey({
  ref
}: {
  ref: string
}): Promise<KeyAgreementKey> {
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
  return keyAgreementKeyFrom(stored)
}

/**
 * Auto-select the decryption key when `--key` is omitted: scan the stored
 * X25519 secret keys and return the one whose `id` (`kid`) matches a recipient
 * of the JWE. Throws when none match or more than one does.
 *
 * @param options {object}
 * @param options.jwe {{recipients?: {header?: {kid?: string}}[]}}
 * @returns {Promise<KeyAgreementKey>}
 */
export async function autoSelectKeyAgreementKey({
  jwe
}: {
  jwe: { recipients?: { header?: { kid?: string } }[] }
}): Promise<KeyAgreementKey> {
  const kids = new Set(
    (jwe.recipients ?? [])
      .map(recipient => recipient?.header?.kid)
      .filter((kid): kid is string => typeof kid === 'string')
  )
  const storageIds = await listCollection('keys')
  const matches: KeyAgreementKey[] = []
  for (const storageId of storageIds) {
    const stored = await loadFromCollection<StoredKeyAgreementKey>({
      collection: 'keys',
      storageId
    })
    if (
      stored.type !== KEY_AGREEMENT_TYPE ||
      !stored.privateKeyMultibase ||
      !stored.publicKeyMultibase
    ) {
      continue
    }
    const key = await keyAgreementKeyFrom(stored)
    if (kids.has(key.id)) {
      matches.push(key)
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
  return matches[0]
}
