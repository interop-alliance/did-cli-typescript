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
  type DIDDoc,
  type DIDLog,
  type VerificationMethod
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
  generateUpdateKey,
  loadUpdateKey,
  type UpdateKeyPair
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
 * The five DID-Core verification relationships, in document order.
 */
const VERIFICATION_RELATIONSHIPS = [
  'authentication',
  'assertionMethod',
  'keyAgreement',
  'capabilityDelegation',
  'capabilityInvocation'
] as const

/**
 * Reconstruct the `createDID`/`updateDID` verification-method directives from a
 * resolved DID document's state, so an update that only rotates update keys can
 * re-supply the document unchanged. `updateDID` rebuilds the document from the
 * directives it is given -- omitting them would blank it -- so each method's
 * `purpose` is recovered from which relationship arrays reference its id.
 *
 * @param state {DIDDoc} a resolved did:webvh DID document.
 * @returns {{ verificationMethods: VerificationMethod[], alsoKnownAs?: string[], services?: object[] }}
 */
function reconstructDocInputs(state: DIDDoc): {
  verificationMethods: VerificationMethod[]
  alsoKnownAs?: string[]
  services?: object[]
} {
  const verificationMethods = (state.verificationMethod ?? []).map(vm => {
    const purpose = VERIFICATION_RELATIONSHIPS.filter(relationship => {
      const refs = ((state as Record<string, unknown>)[relationship] ??
        []) as unknown[]
      return refs.some(
        ref =>
          (typeof ref === 'string' ? ref : (ref as { id?: string }).id) ===
          vm.id
      )
    })
    return { ...vm, purpose }
  })
  return {
    verificationMethods,
    ...(state.alsoKnownAs ? { alsoKnownAs: state.alsoKnownAs } : {}),
    ...(state.service ? { services: state.service } : {})
  }
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

            const envSeed = process.env.SECRET_KEY_SEED
            const secretKeySeed = options.withSeed
              ? (envSeed ?? (await generateSecretKeySeed()))
              : envSeed
            const seedBytes = secretKeySeed
              ? decodeSecretKeySeed({ secretKeySeed })
              : undefined

            // Update key A: the active authorization key. It is what the DID
            // identifier (SCID) derives from, so it is the seed-derived one.
            const updateKey = await generateUpdateKey({ seed: seedBytes })
            const signer = makeWebvhSigner({ keyPair: updateKey })
            // `keyPair.signer()` requires an id to be set before signing.
            updateKey.id = signer.getVerificationMethodId()

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
              // Default to a portable DID until a --portable flag is added; a
              // portable DID can later be moved to a different domain.
              portable: true,
              updateKeys: [updateKey.publicKeyMultibase],
              ...(stagedKey ? { nextKeyHashes: [stagedKey.nextKeyHash] } : {}),
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
              const updateKeys: WebvhUpdateKeys = {
                active: await exportUpdateKey(updateKey)
              }
              if (stagedKey) {
                updateKeys.staged = stagedKey
              }
              const updateKeysPath = await saveDidUpdateKeys({
                did: result.did,
                updateKeys
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
        // current document is just its last entry's state), so its absence is
        // what "not locally stored" means -- no need to also read the doc file.
        let logText: string
        try {
          logText = await loadDidLog(targetDid)
        } catch {
          console.error(`No locally stored did:webvh found for ${didRef}`)
          process.exit(1)
          return
        }
        const log = parseDidLog(logText)

        let meta: Awaited<ReturnType<typeof resolveDIDFromLog>>['meta']
        try {
          ;({ meta } = await resolveDIDFromLog(log, {
            verifier: webvhLogVerifier
          }))
        } catch (err) {
          console.error(
            `Could not resolve the DID log: ${(err as Error).message}`
          )
          process.exit(1)
          return
        }
        if (meta.deactivated) {
          console.error('Cannot rotate keys: the DID is deactivated.')
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

        let stored: WebvhUpdateKeys | undefined
        try {
          stored = await loadDidUpdateKeys(targetDid)
        } catch (err) {
          if ((err as NodeJS.ErrnoException).code !== 'ENOENT') {
            throw err
          }
          stored = undefined
        }

        // Inbound: who signs this entry, and what becomes the active key.
        let signerKeyPair: UpdateKeyPair
        let newActive: WebvhUpdateKey
        let retiredActive: WebvhUpdateKey | undefined

        if (meta.prerotation) {
          // Pre-rotation reveal: the staged key signs its own activation.
          if (!stored?.staged) {
            console.error(
              'Cannot rotate: the pre-committed next-key secret was not ' +
                'found. Pre-rotation requires the staged key to sign its own ' +
                `activation; check for a backup of the ` +
                `${targetDid}.update-keys.json sidecar.`
            )
            process.exit(1)
            return
          }
          if (!meta.nextKeyHashes.includes(stored.staged.nextKeyHash)) {
            console.error(
              "Cannot rotate: the staged key's hash is not among the log's " +
                'committed nextKeyHashes. The local update-keys record has ' +
                'diverged from the published log (an update may have happened ' +
                'elsewhere); re-resolve before rotating.'
            )
            process.exit(1)
            return
          }
          signerKeyPair = await loadUpdateKey(stored.staged)
          newActive = {
            publicKeyMultibase: stored.staged.publicKeyMultibase,
            secretKeyMultibase: stored.staged.secretKeyMultibase
          }
          retiredActive = stored.active
        } else {
          // Ordinary rotation: the current active key signs.
          const activeRecord =
            stored?.active.secretKeyMultibase &&
            meta.updateKeys.includes(stored.active.publicKeyMultibase)
              ? stored.active
              : undefined
          if (!activeRecord) {
            console.error(
              'Cannot rotate: the current active update-key secret was not ' +
                `found in ${targetDid}.update-keys.json.`
            )
            process.exit(1)
            return
          }
          signerKeyPair = await loadUpdateKey(activeRecord)
          if (options.enablePrerotation && !options.updateKey) {
            // Stage only: arm pre-rotation without changing the active key.
            newActive = activeRecord
          } else if (options.updateKey) {
            // Rotate to externally-held key(s); the secret is not ours to store.
            newActive = { publicKeyMultibase: options.updateKey[0] }
            retiredActive = activeRecord
          } else {
            const fresh = await generateUpdateKey()
            newActive = await exportUpdateKey(fresh)
            retiredActive = activeRecord
          }
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

        const signer = makeWebvhSigner({ keyPair: signerKeyPair })
        // `keyPair.signer()` requires an id to be set before signing.
        signerKeyPair.id = signer.getVerificationMethodId()

        // Re-supply the document verification methods unchanged: updateDID
        // rebuilds the document from the inputs it is given, so omitting them
        // would blank it.
        const docInputs = reconstructDocInputs(log[log.length - 1].state)

        let result: Awaited<ReturnType<typeof updateDID>>
        try {
          result = await updateDID({
            log,
            signer,
            verifier: webvhLogVerifier,
            updateKeys: [newActive.publicKeyMultibase],
            nextKeyHashes,
            ...docInputs
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

        // Rewrite the update-keys sidecar: new active, new staged (or none),
        // and the retired secret only when explicitly kept.
        const updated: WebvhUpdateKeys = { active: newActive }
        if (newStaged) {
          updated.staged = newStaged
        }
        const retiredList = stored?.retired ? [...stored.retired] : []
        // retiredActive is undefined on the stage-only path, so this also
        // skips that case without a separate guard.
        if (options.keepOldKey && retiredActive?.secretKeyMultibase) {
          retiredList.push(retiredActive)
        }
        if (retiredList.length > 0) {
          updated.retired = retiredList
        }
        const updateKeysPath = await saveDidUpdateKeys({
          did: result.did,
          updateKeys: updated
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
