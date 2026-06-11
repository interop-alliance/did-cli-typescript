import { Command } from 'commander'
import {
  decodeSecretKeySeed,
  generateSecretKeySeed
} from '@digitalcredentials/bnid'
import { driver } from '@interop/did-method-key'
import * as didWeb from '@interop/did-web-resolver'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'
import * as EcdsaMultikey from '@interop/ecdsa-multikey'
import {
  listDids,
  loadDidDocument,
  loadDidKeys,
  loadDidMeta,
  saveDidMeta,
  saveToDids,
  type ItemMetadata
} from '../storage.js'
import { recordKeyDidAssociation, resolveDidRef } from '../meta.js'
import { renderTable } from '../table.js'
import {
  normalizeEcdsaCurve,
  SUPPORTED_ECDSA_CURVES,
  warnIfNotVcIssuanceCapable
} from '../keys/ecdsa.js'

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
      '--with-seed',
      'include the secret key seed in output (generated if SECRET_KEY_SEED is not set)'
    )
    .option('--save', 'save the DID document to local storage (~/.dids/)')
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
          case 'webvh':
            console.log(`Creating did:${method}...`)
            // TODO: implement
            break
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
      'key type (supported: ed25519, ecdsa)',
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
        if (options.type !== 'ed25519' && options.type !== 'ecdsa') {
          console.error(
            `Unknown key type: ${options.type}. Supported: ed25519, ecdsa`
          )
          process.exit(1)
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

        // ed25519 keys are derived from a seed; ecdsa keys are generated
        // non-deterministically and have no seed.
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
        } else {
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
        }

        const keyPairs = new Map<string, any>()
        try {
          await didWebDriver.addVerificationMethod({
            didDocument,
            keyPairs,
            keyPair,
            purposes: options.purpose
          })
        } catch (err) {
          console.error((err as Error).message)
          process.exit(1)
        }

        // Merge the new key into the stored keys file (keyed by VM id).
        const addedFingerprints: (string | undefined)[] = []
        for (const [methodId, addedKey] of keyPairs) {
          const exportedKey = (await addedKey.export({
            publicKey: true,
            secretKey: true
          })) as { publicKeyMultibase?: string }
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
    .command('resolve <did>')
    .description('Resolve a DID document')
    .option('-o, --output <format>', 'output format (json|pretty)', 'pretty')
    .action((did: string, options: { output: string }) => {
      console.log(`Resolving ${did} (format: ${options.output})`)
      // TODO: implement
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

  return did
}
