/**
 * DID creation and key addition: `runCreate` (key, web, webvh) and `runAddKey`
 * (add a verification key to a stored did:web). Both share the ECDSA-curve,
 * non-deterministic-seed-guard, and output helpers at the top of this module;
 * seed derivation comes from `../../keys/seed.js` and the webvh signer/sidecar
 * plumbing is reused from `./webvh-update.js`.
 */
import { driver } from '@interop/did-method-key'
import * as didWeb from '@interop/did-web-resolver'
import { createDID } from '@interop/did-method-webvh'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'
import * as EcdsaMultikey from '@interop/ecdsa-multikey'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
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
 * Create a new DID of the given method (key, web, or webvh), optionally saving
 * its document, keys, and metadata to local storage, and print it to stdout.
 *
 * @param options {object}
 * @param [options.method] {string}   DID method: key (default), web, or webvh.
 * @param options.type {string}   Key type (ed25519 or ecdsa).
 * @param options.curve {string}   ECDSA curve, for --type ecdsa.
 * @param [options.url] {string}   HTTPS url (required for did:web/did:webvh).
 * @param [options.prerotation] {boolean}   Arm did:webvh key pre-rotation.
 * @param [options.portable] {boolean}   Create a portable did:webvh.
 * @param [options.witness] {string[]}   did:webvh witness did:key DIDs.
 * @param [options.witnessThreshold] {string}   Required witness approvals.
 * @param [options.watcher] {string[]}   did:webvh watcher URLs.
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
  withSeed?: boolean
  save?: boolean
  handle?: string
  description?: string
}): Promise<number> {
  const method = options.method ?? 'key'
  if (!requireSaveForMetaFlags(options)) {
    return 1
  }
  switch (method) {
    case 'key': {
      switch (options.type) {
        case 'ed25519': {
          const { secretKeySeed, seedBytes } = await deriveSeed({
            withSeed: options.withSeed
          })
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
                (exported as { publicKeyMultibase?: string }).publicKeyMultibase
              ],
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
        case 'ecdsa': {
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
                (exported as { publicKeyMultibase?: string }).publicKeyMultibase
              ],
              handle: options.handle,
              description: options.description
            })
          }

          printDidOutput({ id: didDocument.id, didDocument })
          return 0
        }
        default:
          console.error(
            `Unknown key type: ${options.type}. Supported: ed25519, ecdsa`
          )
          return 1
      }
    }
    case 'web': {
      switch (options.type) {
        case 'ed25519': {
          if (!options.url) {
            console.error(
              'did:web requires --url (e.g. --url https://example.com)'
            )
            return 1
          }
          const { secretKeySeed, seedBytes } = await deriveSeed({
            withSeed: options.withSeed
          })

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

          printDidOutput({
            id: didDocument.id,
            didDocument,
            secretKeySeed: options.withSeed ? secretKeySeed : undefined
          })
          return 0
        }
        case 'ecdsa': {
          if (!options.url) {
            console.error(
              'did:web requires --url (e.g. --url https://example.com)'
            )
            return 1
          }
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

          printDidOutput({ id: didDocument.id, didDocument })
          return 0
        }
        default:
          console.error(
            `Unknown key type: ${options.type}. ` + `Supported: ed25519, ecdsa`
          )
          return 1
      }
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

      const { secretKeySeed, seedBytes } = await deriveSeed({
        withSeed: options.withSeed
      })

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
        verificationMethods: [
          {
            type: 'Multikey',
            publicKeyMultibase: docKey.publicKeyMultibase,
            // Wire the document key into the same relationships as did:web
            // (everything but keyAgreement, which needs an X25519 key).
            purpose: [...DEFAULT_VERIFICATION_PURPOSES]
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
          return 1
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

      printDidOutput({
        id: result.did,
        didDocument: result.doc,
        secretKeySeed: options.withSeed ? secretKeySeed : undefined
      })
      return 0
    }
    default:
      console.error(`Unknown method: ${method}. Supported: key, web, webvh`)
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
    return 1
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

  printDidOutput({
    id: didDocument.id as string,
    didDocument,
    secretKeySeed: options.withSeed ? secretKeySeed : undefined
  })
  return 0
}
