import { Command } from 'commander'
import { decodeSecretKeySeed } from '@digitalcredentials/bnid'
import * as Ed25519Multikey from '@digitalcredentials/ed25519-multikey'

export function makeKeyCommand(): Command {
  const key = new Command('key').description('Manage cryptographic keys')

  key.command('create')
    .description('Create a new key')
    .option('-t, --type <type>', 'key type (supported: ed25519)', 'ed25519')
    .action(async (options: { type: string }) => {
      switch (options.type) {
        case 'ed25519': {
          const secretKeySeed = process.env.SECRET_KEY_SEED
          const seedBytes = secretKeySeed
            ? decodeSecretKeySeed({ secretKeySeed })
            : undefined
          const keyPair = await Ed25519Multikey.generate({ seed: seedBytes })
          const exported = await keyPair.export({ publicKey: true, secretKey: true })
          console.log(JSON.stringify(exported, null, 2))
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
