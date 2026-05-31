import { Command } from 'commander'
import { decodeSecretKeySeed, generateSecretKeySeed } from '@digitalcredentials/bnid'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'
import { saveToCollection } from '../storage.js'

export function makeKeyCommand(): Command {
  const key = new Command('key').description('Manage cryptographic keys')

  key.command('create')
    .description('Create a new key')
    .option('-t, --type <type>', 'key type (supported: ed25519)', 'ed25519')
    .option('--save', 'save the key to local wallet storage (~/.wallet/keys/)')
    .option('--with-seed', 'include the secret key seed in output (generated if SECRET_KEY_SEED is not set)')
    .action(async (options: { type: string; save?: boolean; withSeed?: boolean }) => {
      switch (options.type) {
        case 'ed25519': {
          const envSeed = process.env.SECRET_KEY_SEED
          const secretKeySeed = options.withSeed
            ? (envSeed ?? await generateSecretKeySeed())
            : envSeed
          const seedBytes = secretKeySeed
            ? decodeSecretKeySeed({ secretKeySeed })
            : undefined
          const keyPair = await Ed25519VerificationKey.generate({ seed: seedBytes })
          const exported = keyPair.export({ publicKey: true, secretKey: true })
          if (options.save) {
            const date = new Date().toISOString().slice(0, 10)
            const rawId = exported.id ?? keyPair.publicKeyMultibase
            const storageId = `${date}-${options.type}-${rawId}`.replaceAll(':', '_')
            const filePath = await saveToCollection('keys', storageId, exported)
            console.error(`Key saved to ${filePath}`)
          }
          const output = options.withSeed
            ? { secretKeySeed, keyPair: exported }
            : exported
          console.log(JSON.stringify(output, null, 2))
          break
        }
        default:
          console.error(`Unknown key type: ${options.type}. Supported: ed25519`)
          process.exit(1)
      }
    })

  key.command('list')
    .description('List locally stored keys')
    .action(() => {
      console.log('Listing keys...')
      // TODO: implement
    })

  key.command('export <id>')
    .description('Export a key by ID')
    .option('-f, --format <format>', 'export format (jwk|multibase)', 'jwk')
    .action((keyId: string, options: { format: string }) => {
      console.log(`Exporting key ${keyId} (format: ${options.format})`)
      // TODO: implement
    })

  return key
}
