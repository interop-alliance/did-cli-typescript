/**
 * DID creation and key addition: `runCreate` (key, web, webvh, peer) and `runAddKey`
 * (add a verification key to a stored did:web). Both share the ECDSA-curve,
 * non-deterministic-seed-guard, and output helpers at the top of this module;
 * seed derivation comes from `../../keys/seed.js` and the webvh signer/sidecar
 * plumbing is reused from `./webvh-update.js`.
 */
import type { AbstractKeyPair } from '@interop/data-integrity-core'
import { driver } from '@interop/did-method-key'
import * as didPeer from '@interop/did-method-peer'
import * as didWeb from '@interop/did-web-resolver'
import {
  createDID,
  type DataIntegrityProofPurpose
} from '@interop/did-method-webvh'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'
import * as EcdsaMultikey from '@interop/ecdsa-multikey'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import type { IDidDocument } from '@interop/data-integrity-core'
import {
  loadDidDocument,
  loadDidKeys,
  saveDidLog,
  saveDidMeta,
  saveToDids,
  type ItemMetadata
} from '../../storage.js'
import { recordKeyDidAssociation } from '../../meta.js'
import {
  normalizeEcdsaCurve,
  SUPPORTED_ECDSA_CURVES,
  warnIfNotVcIssuanceCapable
} from '../../keys/ecdsa.js'
import { exportStoredKey } from '../../keys/export.js'
import { deriveSeed } from '../../keys/seed.js'
import { exportUpdateKey, generateStagedKey } from '../../keys/webvh-update.js'
import { requireSaveForMetaFlags } from '../collection-command.js'
import {
  makeWebvhEntrySigner,
  persistUpdateKeysSidecar
} from './webvh-update.js'

/**
 * Verification relationships a newly created did:webvh document key is wired
 * into -- everything but keyAgreement, which needs an X25519 key. Also the
 * `add-key` default purpose set (described in its help text).
 */
export const DEFAULT_VERIFICATION_PURPOSES = [
  'authentication',
  'assertionMethod',
  'capabilityDelegation',
  'capabilityInvocation'
] as const

/**
 * Whether `value` is a relationship a did:webvh document key may be wired
 * into with `--purpose` (keyAgreement is excluded because it needs an X25519
 * key, and the document key is always Ed25519).
 */
function isWebvhPurpose(value: string): value is DataIntegrityProofPurpose {
  return (DEFAULT_VERIFICATION_PURPOSES as readonly string[]).includes(value)
}

/**
 * Validate the `--purpose` values of a did:webvh document key, returning
 * them typed. Throws with a user-facing message on an unsupported
 * relationship.
 *
 * @param purpose {string[]}
 * @returns {DataIntegrityProofPurpose[]}
 */
export function parseWebvhPurposes(
  purpose: readonly string[]
): DataIntegrityProofPurpose[] {
  const purposes: DataIntegrityProofPurpose[] = []
  for (const value of purpose) {
    if (!isWebvhPurpose(value)) {
      const reason =
        value === 'keyAgreement'
          ? ' (keyAgreement needs an X25519 key; the document key is Ed25519)'
          : ''
      throw new Error(
        `Invalid --purpose "${value}"${reason}. ` +
          `Supported: ${DEFAULT_VERIFICATION_PURPOSES.join(', ')}`
      )
    }
    purposes.push(value)
  }
  return purposes
}

/**
 * Validate a `--verification-key` value as an Ed25519 Multikey public key,
 * returning the public-only key pair. Throws with a user-facing message.
 *
 * @param verificationKey {string}
 * @returns {Promise<Ed25519VerificationKey>}
 */
export async function parseVerificationKey(
  verificationKey: string
): Promise<Ed25519VerificationKey> {
  try {
    return await Ed25519VerificationKey.from({
      publicKeyMultibase: verificationKey
    })
  } catch (err) {
    throw new Error(
      `Invalid --verification-key "${verificationKey}": ` +
        'expected an Ed25519 Multikey public key (z6Mk...). ' +
        (err as Error).message,
      { cause: err }
    )
  }
}

/**
 * Verification method id fragment modes accepted by `--vm-id-fragment`.
 */
const VM_ID_FRAGMENT_MODES = ['short', 'multibase'] as const

function isVmIdFragmentMode(
  value: string
): value is (typeof VM_ID_FRAGMENT_MODES)[number] {
  return (VM_ID_FRAGMENT_MODES as readonly string[]).includes(value)
}

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
export async function saveDidArtifacts({
  method,
  didDocument,
  exportedKeys,
  fingerprints,
  handle,
  description
}: {
  method: string
  didDocument: IDidDocument
  exportedKeys: object
  fingerprints: (string | undefined)[]
  handle?: string
  description?: string
}): Promise<void> {
  const did = didDocument.id
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
 * Reject method-scoped `did create` flags given for a DID method they do not
 * apply to. A flag counts as given when its value is not undefined. Prints one
 * error per set of methods (listing the rejected flags that share it) and
 * returns true when any flag was wrongly supplied.
 *
 * @param options {object}
 * @param options.method {string}   The resolved DID method being created.
 * @param options.flags {{ flag: string, value: unknown, methods: string[] }[]}
 *   Each flag with its value and the methods it applies to.
 * @returns {boolean}   true when a flag was rejected.
 */
function rejectFlagsOutsideMethod({
  method,
  flags
}: {
  method: string
  flags: { flag: string; value: unknown; methods: string[] }[]
}): boolean {
  const rejectedByMethods = new Map<string, string[]>()
  for (const { flag, value, methods } of flags) {
    if (value === undefined || methods.includes(method)) {
      continue
    }
    const supported = methods.map(name => `did:${name}`).join(', ')
    rejectedByMethods.set(supported, [
      ...(rejectedByMethods.get(supported) ?? []),
      flag
    ])
  }
  for (const [supported, rejected] of rejectedByMethods) {
    console.error(`${rejected.join(', ')} is only supported for ${supported}`)
  }
  return rejectedByMethods.size > 0
}

/**
 * The verification key pair `did create` generates for did:key, did:web, and
 * did:peer.
 */
type VerificationKeyPair =
  Ed25519VerificationKey | Awaited<ReturnType<typeof EcdsaMultikey.generate>>

/**
 * Generate the verification key pair for a new did:key, did:web, or did:peer
 * from the shared `--type`, `--curve`, and `--with-seed` options. Ed25519 keys
 * are derived from the seed; ECDSA keys are non-deterministic and reject
 * `--with-seed`. Prints the error and returns undefined when the options are
 * invalid.
 *
 * @param options {object}
 * @param options.type {string}   Key type (ed25519 or ecdsa).
 * @param options.curve {string}   ECDSA curve, for `--type ecdsa`.
 * @param [options.withSeed] {boolean}   Include/derive the secret key seed.
 * @returns {Promise<{ keyPair: VerificationKeyPair, secretKeySeed?: string } | undefined>}
 */
async function generateVerificationKeyPair({
  type,
  curve,
  withSeed
}: {
  type: string
  curve: string
  withSeed?: boolean
}): Promise<
  { keyPair: VerificationKeyPair; secretKeySeed?: string } | undefined
> {
  switch (type) {
    case 'ed25519': {
      const { secretKeySeed, seedBytes } = await deriveSeed({ withSeed })
      const keyPair = await Ed25519VerificationKey.generate({
        seed: seedBytes
      })
      return { keyPair, secretKeySeed }
    }
    case 'ecdsa': {
      if (rejectSeedForNonDeterministic({ withSeed, keyLabel: 'ecdsa' })) {
        return undefined
      }
      const resolvedCurve = resolveEcdsaCurveOrReport(curve)
      if (!resolvedCurve) {
        return undefined
      }
      return { keyPair: await EcdsaMultikey.generate({ curve: resolvedCurve }) }
    }
    default:
      console.error(`Unknown key type: ${type}. Supported: ed25519, ecdsa`)
      return undefined
  }
}

/**
 * Export every generated key pair (keyed by verification method id) for the
 * stored keys file, and collect their `publicKeyMultibase` fingerprints.
 *
 * @param keyPairs {Map<string, AbstractKeyPair>}
 * @returns {Promise<{ exportedKeys: Record<string, unknown>, fingerprints: (string | undefined)[] }>}
 */
async function exportStoredKeys(
  keyPairs: Map<string, AbstractKeyPair>
): Promise<{
  exportedKeys: Record<string, unknown>
  fingerprints: (string | undefined)[]
}> {
  const exportedKeys: Record<string, unknown> = {}
  const fingerprints: (string | undefined)[] = []
  for (const [methodId, keyPair] of keyPairs) {
    const exportedKey = await exportStoredKey(keyPair)
    exportedKeys[methodId] = exportedKey
    fingerprints.push(exportedKey.publicKeyMultibase)
  }
  return { exportedKeys, fingerprints }
}

/**
 * Guard a non-deterministic key type against `--with-seed`: ECDSA and X25519
 * keys are generated non-deterministically and cannot be derived from a seed.
 * Prints the error and returns true when the flag was wrongly supplied.
 *
 * @param options {object}
 * @param [options.withSeed] {boolean}
 * @param options.keyLabel {string}   lowercase key type name (e.g. `ecdsa`).
 * @returns {boolean}   true when `--with-seed` was rejected.
 */
function rejectSeedForNonDeterministic({
  withSeed,
  keyLabel
}: {
  withSeed?: boolean
  keyLabel: string
}): boolean {
  if (!withSeed) {
    return false
  }
  console.error(
    `--with-seed is not supported for ${keyLabel} keys; ` +
      `${keyLabel.toUpperCase()} key generation is non-deterministic and ` +
      'cannot be derived from a seed.'
  )
  return true
}

/**
 * Normalize an ECDSA curve name and warn when it is not VC-issuance-capable,
 * returning the canonical curve. Prints the error and returns undefined for an
 * unknown curve.
 *
 * @param curveInput {string}
 * @returns {EcdsaCurve | undefined}
 */
function resolveEcdsaCurveOrReport(curveInput: string) {
  const curve = normalizeEcdsaCurve({ curve: curveInput })
  if (!curve) {
    console.error(
      `Unknown ecdsa curve: ${curveInput}. ` +
        `Supported: ${SUPPORTED_ECDSA_CURVES}`
    )
    return undefined
  }
  warnIfNotVcIssuanceCapable({ curve })
  return curve
}

/**
 * Print the standard `did create` / `add-key` result object: the DID id, the
 * secret key seed when one is being echoed back, then the DID document.
 *
 * @param options {object}
 * @param options.id {string}
 * @param options.didDocument {unknown}
 * @param [options.secretKeySeed] {string}   included only when defined.
 * @returns {void}
 */
function printDidOutput({
  id,
  didDocument,
  secretKeySeed
}: {
  id: string
  didDocument: unknown
  secretKeySeed?: string
}): void {
  const output: Record<string, unknown> = { id }
  if (secretKeySeed !== undefined) {
    output.secretKeySeed = secretKeySeed
  }
  output.didDocument = didDocument
  console.log(JSON.stringify(output, null, 2))
}

/**
 * Finish `did create` for a statically generated DID (key, web, peer): save
 * the document, keys file, and metadata when `--save` was given, then print
 * the result.
 *
 * @param options {object}
 * @param options.method {string}
 * @param options.didDocument {IDidDocument}
 * @param options.exportedKeys {object}   The keys file contents.
 * @param options.fingerprints {(string | undefined)[]}
 * @param [options.secretKeySeed] {string}   Echoed back with `--with-seed`.
 * @param options.options {object}   The `--save`, `--with-seed`, `--handle`,
 *   and `--description` values of the create command.
 * @returns {Promise<number>}   The process exit code (always 0).
 */
async function finishCreate({
  method,
  didDocument,
  exportedKeys,
  fingerprints,
  secretKeySeed,
  options
}: {
  method: string
  didDocument: IDidDocument
  exportedKeys: object
  fingerprints: (string | undefined)[]
  secretKeySeed?: string
  options: {
    withSeed?: boolean
    save?: boolean
    handle?: string
    description?: string
  }
}): Promise<number> {
  if (options.save) {
    await saveDidArtifacts({
      method,
      didDocument,
      exportedKeys,
      fingerprints,
      handle: options.handle,
      description: options.description
    })
  }
  printDidOutput({
    id: didDocument.id,
    didDocument,
    secretKeySeed: options.withSeed ? secretKeySeed : undefined
  })
  return 0
}

/**
 * Create a new DID of the given method (key, web, webvh, or peer), optionally
 * saving its document, keys, and metadata to local storage, and print it to
 * stdout.
 *
 * @param options {object}
 * @param [options.method] {string}   DID method: key (default), web, webvh,
 *   or peer.
 * @param options.type {string}   Key type (ed25519 or ecdsa).
 * @param options.curve {string}   ECDSA curve, for --type ecdsa.
 * @param [options.url] {string}   HTTPS url (required for did:web/did:webvh).
 * @param [options.prerotation] {boolean}   Arm did:webvh key pre-rotation.
 * @param [options.portable] {boolean}   Create a portable did:webvh.
 * @param [options.witness] {string[]}   did:webvh witness did:key DIDs.
 * @param [options.witnessThreshold] {string}   Required witness approvals.
 * @param [options.watcher] {string[]}   did:webvh watcher URLs.
 * @param [options.verificationKey] {string}   did:webvh external document key
 *   (Ed25519 `publicKeyMultibase`); no secret is generated or stored for it.
 * @param [options.purpose] {string[]}   did:webvh document key verification
 *   relationships (default: `DEFAULT_VERIFICATION_PURPOSES`).
 * @param [options.vmIdFragment] {string}   did:webvh verification method id
 *   fragment mode: short or multibase (default: the library default).
 * @param [options.keyAgreement] {boolean}   did:peer: also derive an X25519
 *   keyAgreement key from the Ed25519 verification key.
 * @param [options.withSeed] {boolean}   Include/derive the secret key seed.
 * @param [options.save] {boolean}   Save the DID to local storage.
 * @param [options.handle] {string}   Short tag stored in the metadata sidecar.
 * @param [options.description] {string}   Longer description for the sidecar.
 * @returns {Promise<number>}   The process exit code.
 */
export async function runCreate(options: {
  method?: string
  type: string
  curve: string
  url?: string
  prerotation?: boolean
  portable?: boolean
  witness?: string[]
  witnessThreshold?: string
  watcher?: string[]
  verificationKey?: string
  purpose?: string[]
  vmIdFragment?: string
  keyAgreement?: boolean
  withSeed?: boolean
  save?: boolean
  handle?: string
  description?: string
}): Promise<number> {
  const method = options.method ?? 'key'
  if (!requireSaveForMetaFlags(options)) {
    return 1
  }
  const webvh = ['webvh']
  if (
    rejectFlagsOutsideMethod({
      method,
      flags: [
        { flag: '--url', value: options.url, methods: ['web', 'webvh'] },
        { flag: '--prerotation', value: options.prerotation, methods: webvh },
        { flag: '--portable', value: options.portable, methods: webvh },
        { flag: '--witness', value: options.witness, methods: webvh },
        {
          flag: '--witness-threshold',
          value: options.witnessThreshold,
          methods: webvh
        },
        { flag: '--watcher', value: options.watcher, methods: webvh },
        {
          flag: '--verification-key',
          value: options.verificationKey,
          methods: webvh
        },
        { flag: '--purpose', value: options.purpose, methods: webvh },
        {
          flag: '--vm-id-fragment',
          value: options.vmIdFragment,
          methods: webvh
        },
        {
          flag: '--key-agreement',
          value: options.keyAgreement,
          methods: ['peer']
        }
      ]
    })
  ) {
    return 1
  }
  switch (method) {
    case 'key': {
      const generated = await generateVerificationKeyPair(options)
      if (!generated) {
        return 1
      }
      const { keyPair, secretKeySeed } = generated

      const didDriver = driver()
      didDriver.use({ keyPairClass: Ed25519VerificationKey })
      const { didDocument } = await didDriver.fromKeyPair({
        verificationKeyPair: keyPair
      })
      // did:key stores its single key unkeyed, not in a map by method id.
      const exportedKey = await exportStoredKey(keyPair)
      return finishCreate({
        method: 'key',
        didDocument,
        exportedKeys: exportedKey,
        fingerprints: [exportedKey.publicKeyMultibase],
        secretKeySeed,
        options
      })
    }
    case 'web': {
      if (!options.url) {
        console.error('did:web requires --url (e.g. --url https://example.com)')
        return 1
      }
      const generated = await generateVerificationKeyPair(options)
      if (!generated) {
        return 1
      }
      const { keyPair, secretKeySeed } = generated

      const didWebDriver = didWeb.driver()
      didWebDriver.use({ keyPairClass: Ed25519VerificationKey })
      const { didDocument, keyPairs } = await didWebDriver.generate({
        url: options.url,
        verificationKeyPair: keyPair
      })
      return finishCreate({
        method: 'web',
        didDocument,
        ...(await exportStoredKeys(keyPairs)),
        secretKeySeed,
        options
      })
    }
    case 'webvh': {
      if (!options.url) {
        console.error(
          'did:webvh requires --url (e.g. --url https://example.com)'
        )
        return 1
      }
      // The webvh library hardcodes the `eddsa-jcs-2022` cryptosuite, so
      // only Ed25519 update keys are supported for now.
      if (options.type !== 'ed25519') {
        console.error(
          `did:webvh only supports --type ed25519 (got ${options.type}); ` +
            'the eddsa-jcs-2022 cryptosuite requires an Ed25519 key.'
        )
        return 1
      }
      // Pre-rotation is the default; --no-prerotation opts out. With no
      // flag, commander leaves `prerotation` undefined, which is on.
      const prerotation = options.prerotation !== false
      // Portability is the default; --no-portable opts out (same shape).
      const portable = options.portable !== false

      // Witness declarations (declaration only -- generating the witness
      // proofs / did-witness.json sidecar is out of scope for now).
      const witnessDids = options.witness ?? []
      if (options.witnessThreshold !== undefined && witnessDids.length === 0) {
        console.error('--witness-threshold requires at least one --witness')
        return 1
      }
      for (const witnessDid of witnessDids) {
        if (!witnessDid.startsWith('did:key:')) {
          console.error(
            `Invalid witness "${witnessDid}": witnesses must be ` +
              'did:key DIDs'
          )
          return 1
        }
      }
      let witness:
        { threshold: number; witnesses: { id: string }[] } | undefined
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
            return 1
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
          return 1
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
          return 1
        }
      }

      // Document key relationships: default to everything but keyAgreement.
      let purposes: DataIntegrityProofPurpose[]
      try {
        purposes = parseWebvhPurposes(
          options.purpose ?? DEFAULT_VERIFICATION_PURPOSES
        )
      } catch (err) {
        console.error((err as Error).message)
        return 1
      }

      const vmIdFragment = options.vmIdFragment
      if (vmIdFragment !== undefined && !isVmIdFragmentMode(vmIdFragment)) {
        console.error(
          `Invalid --vm-id-fragment "${vmIdFragment}". ` +
            `Supported: ${VM_ID_FRAGMENT_MODES.join(', ')}`
        )
        return 1
      }

      // Document verification key V, decoupled from the update keys so
      // that rotating the update key never disturbs the document. With
      // --verification-key it is an external public-only key (validated
      // here as an Ed25519 Multikey); otherwise it is generated.
      const isExternalDocKey = options.verificationKey !== undefined
      let docKey: Ed25519VerificationKey
      if (options.verificationKey !== undefined) {
        try {
          docKey = await parseVerificationKey(options.verificationKey)
        } catch (err) {
          console.error((err as Error).message)
          return 1
        }
      } else {
        docKey = await Ed25519VerificationKey.generate()
      }

      const { secretKeySeed, seedBytes } = await deriveSeed({
        withSeed: options.withSeed
      })

      // Update key A: the active authorization key. It is what the DID
      // identifier (SCID) derives from, so it is the seed-derived one.
      const updateKey = await Ed25519VerificationKey.generate({
        seed: seedBytes
      })
      const signer = makeWebvhEntrySigner(updateKey)

      // Staged next update key B: when pre-rotation is on, commit its
      // hash now so the next update must reveal it.
      const stagedKey = prerotation ? await generateStagedKey() : undefined

      const result = await createDID({
        address: options.url,
        signer,
        // A portable DID (the default) can later be moved to a different
        // domain; --no-portable pins it to its origin.
        portable,
        updateKeys: [updateKey.publicKeyMultibase],
        ...(stagedKey ? { nextKeyHashes: [stagedKey.nextKeyHash] } : {}),
        ...(witness ? { witness } : {}),
        ...(watchers.length > 0 ? { watchers } : {}),
        ...(vmIdFragment ? { vmIdFragment } : {}),
        verificationMethods: [
          {
            type: 'Multikey',
            publicKeyMultibase: docKey.publicKeyMultibase,
            // Wire the document key into the same relationships as did:web
            // (everything but keyAgreement, which needs an X25519 key),
            // unless --purpose selects a subset.
            purpose: purposes
          }
        ]
      })

      if (options.save) {
        // Persist the document key V keyed by its document verification
        // method id (so it can be selected for signing), and set its id
        // to match.
        const docVmId = result.doc.verificationMethod?.[0]?.id
        if (!docVmId) {
          console.error(
            'Created did:webvh document is missing a verification method id'
          )
          return 1
        }
        // An external document key has no secret here, so its keys file
        // is written empty and no key/DID association is recorded.
        docKey.id = docVmId
        const exportedDoc = isExternalDocKey
          ? undefined
          : await exportStoredKey(docKey)
        // did-method-webvh types its document as `DIDDoc`, with every field
        // optional; the created document is a full DID document.
        await saveDidArtifacts({
          method: 'webvh',
          didDocument: result.doc as IDidDocument,
          exportedKeys: exportedDoc ? { [docVmId]: exportedDoc } : {},
          fingerprints: [exportedDoc?.publicKeyMultibase],
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

      printDidOutput({
        id: result.did,
        didDocument: result.doc,
        secretKeySeed: options.withSeed ? secretKeySeed : undefined
      })
      return 0
    }
    case 'peer': {
      // did:peer:4 is statically resolvable: the long form carries the whole
      // document, so no URL is needed.
      if (options.keyAgreement && options.type !== 'ed25519') {
        console.error(
          '--key-agreement derives an X25519 key from an Ed25519 key; ' +
            `it is not supported with --type ${options.type}`
        )
        return 1
      }
      const generated = await generateVerificationKeyPair(options)
      if (!generated) {
        return 1
      }
      const { keyPair, secretKeySeed } = generated

      // Deriving an X25519 key agreement key reuses the Ed25519 key's
      // material for encryption, so it is opt-in (--key-agreement).
      const didPeerDriver = didPeer.driver()
      didPeerDriver.use({
        keyPairClass: Ed25519VerificationKey,
        enableEncryptionKeyDerivation: options.keyAgreement === true
      })
      const { didDocument, keyPairs } = await didPeerDriver.generate({
        verificationKeyPair: keyPair
      })
      return finishCreate({
        method: 'peer',
        didDocument,
        ...(await exportStoredKeys(keyPairs)),
        secretKeySeed,
        options
      })
    }
    default:
      console.error(
        `Unknown method: ${method}. Supported: key, web, webvh, peer`
      )
      return 1
  }
}

/**
 * Add a verification key to an existing (locally stored) did:web document,
 * re-save the document and keys file, and print the updated document.
 *
 * @param options {object}
 * @param options.did {string}   The did:web DID to add a key to.
 * @param options.type {string}   Key type: ed25519, ecdsa, or x25519.
 * @param options.curve {string}   ECDSA curve, for --type ecdsa.
 * @param [options.purpose] {string[]}   Verification relationship(s) to wire
 *   the key into.
 * @param [options.withSeed] {boolean}   Include/derive the secret key seed
 *   (ed25519 only).
 * @returns {Promise<number>}   The process exit code.
 */
export async function runAddKey(options: {
  did: string
  type: string
  curve: string
  purpose?: string[]
  withSeed?: boolean
}): Promise<number> {
  const { did } = options
  if (!did.startsWith('did:web:')) {
    console.error('add-key is only supported for did:web DIDs')
    return 1
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
    return 1
  }
  // x25519 keys are key agreement keys; they can only be wired into the
  // keyAgreement verification relationship.
  let purposes = options.purpose
  if (options.type === 'x25519') {
    if (purposes && purposes.some(purpose => purpose !== 'keyAgreement')) {
      console.error(
        'x25519 keys can only be added to the keyAgreement ' +
          'verification relationship'
      )
      return 1
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
    return 1
  }

  // ed25519 keys are derived from a seed; ecdsa and x25519 keys are
  // generated non-deterministically and have no seed.
  let secretKeySeed: string | undefined
  let keyPair: any
  const didWebDriver = didWeb.driver()
  if (options.type === 'ed25519') {
    let seedBytes: Uint8Array | undefined
    ;({ secretKeySeed, seedBytes } = await deriveSeed({
      withSeed: options.withSeed
    }))
    keyPair = await Ed25519VerificationKey.generate({ seed: seedBytes })
    didWebDriver.use({ keyPairClass: Ed25519VerificationKey })
  } else if (options.type === 'ecdsa') {
    if (
      rejectSeedForNonDeterministic({
        withSeed: options.withSeed,
        keyLabel: 'ecdsa'
      })
    ) {
      return 1
    }
    const curve = resolveEcdsaCurveOrReport(options.curve)
    if (!curve) {
      return 1
    }
    keyPair = await EcdsaMultikey.generate({ curve })
  } else {
    if (
      rejectSeedForNonDeterministic({
        withSeed: options.withSeed,
        keyLabel: 'x25519'
      })
    ) {
      return 1
    }
    keyPair = await X25519KeyAgreementKey2020.generate()
  }

  const keyPairs = new Map<string, AbstractKeyPair>()
  try {
    await didWebDriver.addVerificationMethod({
      didDocument,
      keyPairs,
      keyPair,
      purposes
    })
  } catch (err) {
    console.error((err as Error).message)
    return 1
  }

  // Merge the new key into the stored keys file (keyed by VM id).
  const { exportedKeys: addedKeys, fingerprints: addedFingerprints } =
    await exportStoredKeys(keyPairs)
  Object.assign(exportedKeys, addedKeys)
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

  printDidOutput({
    id: didDocument.id as string,
    didDocument,
    secretKeySeed: options.withSeed ? secretKeySeed : undefined
  })
  return 0
}
