import { Command } from 'commander'
import {
  decodeSecretKeySeed,
  generateSecretKeySeed
} from '@digitalcredentials/bnid'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'
import * as EcdsaMultikey from '@interop/ecdsa-multikey'
import {
  listCollection,
  loadFromCollection,
  saveToCollection
} from '../storage.js'
import {
  isEcdsaPublicKeyMultibase,
  normalizeEcdsaCurve,
  SUPPORTED_ECDSA_CURVES,
  warnIfNotVcIssuanceCapable
} from '../keys/ecdsa.js'

export function makeKeyCommand(): Command {
  const key = new Command('key').description('Manage cryptographic keys')

  key
    .command('create')
    .description('Create a new key')
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
    .option('--save', 'save the key to local wallet storage (~/.wallet/keys/)')
    .option(
      '--with-seed',
      'include the secret key seed in output (generated if SECRET_KEY_SEED is not set)'
    )
    .action(
      async (options: {
        type: string
        curve: string
        save?: boolean
        withSeed?: boolean
      }) => {
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
            const exported = await keyPair.export({
              publicKey: true,
              secretKey: true
            })
            if (options.save) {
              const date = new Date().toISOString().slice(0, 10)
              const rawId = exported.id ?? keyPair.publicKeyMultibase
              const storageId = `${date}-${options.type}-${rawId}`.replaceAll(
                ':',
                '_'
              )
              const filePath = await saveToCollection(
                'keys',
                storageId,
                exported
              )
              console.error(`Key saved to ${filePath}`)
            }
            const output = options.withSeed
              ? { secretKeySeed, keyPair: exported }
              : exported
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
            const exported = await keyPair.export({
              publicKey: true,
              secretKey: true
            })
            if (options.save) {
              const date = new Date().toISOString().slice(0, 10)
              const rawId = exported.id ?? exported.publicKeyMultibase
              const curveLabel = curve.replace('-', '').toLowerCase()
              const storageId =
                `${date}-ecdsa-${curveLabel}-${rawId}`.replaceAll(':', '_')
              const filePath = await saveToCollection(
                'keys',
                storageId,
                exported
              )
              console.error(`Key saved to ${filePath}`)
            }
            console.log(JSON.stringify(exported, null, 2))
            break
          }
          default:
            console.error(
              `Unknown key type: ${options.type}. Supported: ed25519, ecdsa`
            )
            process.exit(1)
        }
      }
    )

  key
    .command('list')
    .description('List locally stored keys')
    .option('--json', 'output the list of key IDs as a JSON array')
    .action(async (options: { json?: boolean }) => {
      const storageIds = await listCollection('keys')
      const keyIds: string[] = []
      for (const storageId of storageIds) {
        const key = await loadFromCollection<{ publicKeyMultibase?: string }>(
          'keys',
          storageId
        )
        if (key.publicKeyMultibase) {
          keyIds.push(key.publicKeyMultibase)
        }
      }
      keyIds.sort()
      if (options.json) {
        console.log(JSON.stringify(keyIds, null, 2))
        return
      }
      for (const keyId of keyIds) {
        console.log(keyId)
      }
    })

  key
    .command('show <id>')
    .aliases(['view', 'cat'])
    .description(
      'Show a locally stored key (public key object only) by its ' +
        'publicKeyMultibase fingerprint'
    )
    .action(async (id: string) => {
      const storageIds = await listCollection('keys')
      let storedKey:
        | { publicKeyMultibase?: string; secretKeyMultibase?: string }
        | undefined
      for (const storageId of storageIds) {
        const candidate = await loadFromCollection<{
          publicKeyMultibase?: string
          secretKeyMultibase?: string
        }>('keys', storageId)
        if (candidate.publicKeyMultibase === id) {
          storedKey = candidate
          break
        }
      }
      if (!storedKey) {
        console.error(`No locally stored key found for ${id}`)
        process.exit(1)
        return
      }

      // Re-import the stored key pair and re-export the public half only, so the
      // secret key material never leaves storage in the displayed output.
      const isEcdsa = isEcdsaPublicKeyMultibase({
        publicKeyMultibase: storedKey.publicKeyMultibase
      })
      const publicKey = isEcdsa
        ? await (
            await EcdsaMultikey.from(storedKey)
          ).export({
            publicKey: true,
            secretKey: false
          })
        : await (
            await Ed25519VerificationKey.from(storedKey)
          ).export({
            publicKey: true,
            secretKey: false
          })
      console.log(JSON.stringify(publicKey, null, 2))
    })

  key
    .command('export <id>')
    .description('Export a key by ID')
    .option('-f, --format <format>', 'export format (jwk|multibase)', 'jwk')
    .action((keyId: string, options: { format: string }) => {
      console.error(`Exporting key ${keyId} (format: ${options.format})`)
      // TODO: implement
    })

  return key
}
