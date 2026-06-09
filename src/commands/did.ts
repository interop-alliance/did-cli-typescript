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
  saveToDids
} from '../storage.js'
import {
  normalizeEcdsaCurve,
  SUPPORTED_ECDSA_CURVES,
  warnIfNotVcIssuanceCapable
} from '../keys/ecdsa.js'

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
    .action(
      async (
        method: string = 'key',
        options: {
          type: string
          curve: string
          url?: string
          withSeed?: boolean
          save?: boolean
        }
      ) => {
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
                  const did = didDocument.id as string
                  const exported = await keyPair.export({
                    publicKey: true,
                    secretKey: true
                  })
                  const docPath = await saveToDids({
                    method: 'key',
                    did,
                    data: didDocument
                  })
                  await saveToDids({
                    method: 'key',
                    did,
                    suffix: 'keys',
                    data: exported
                  })
                  console.error(`DID saved to ${docPath}`)
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
                  const did = didDocument.id as string
                  const exported = await keyPair.export({
                    publicKey: true,
                    secretKey: true
                  })
                  const docPath = await saveToDids({
                    method: 'key',
                    did,
                    data: didDocument
                  })
                  await saveToDids({
                    method: 'key',
                    did,
                    suffix: 'keys',
                    data: exported
                  })
                  console.error(`DID saved to ${docPath}`)
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
                  const did = didDocument.id as string
                  const exported: Record<string, unknown> = {}
                  for (const [methodId, keyPair] of keyPairs) {
                    exported[methodId] = await keyPair.export({
                      publicKey: true,
                      secretKey: true
                    })
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
                    data: exported
                  })
                  console.error(`DID saved to ${docPath}`)
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
                  const did = didDocument.id as string
                  const exported: Record<string, unknown> = {}
                  for (const [methodId, savedKey] of keyPairs) {
                    exported[methodId] = await savedKey.export({
                      publicKey: true,
                      secretKey: true
                    })
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
                    data: exported
                  })
                  console.error(`DID saved to ${docPath}`)
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
        for (const [methodId, addedKey] of keyPairs) {
          exportedKeys[methodId] = await addedKey.export({
            publicKey: true,
            secretKey: true
          })
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
    .command('list')
    .description('List locally stored DIDs')
    .option('--json', 'output the list of DIDs as a JSON array')
    .action(async (options: { json?: boolean }) => {
      const dids = await listDids()
      if (options.json) {
        console.log(JSON.stringify(dids, null, 2))
        return
      }
      for (const did of dids) {
        console.log(did)
      }
    })

  return did
}
