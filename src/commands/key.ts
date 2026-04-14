import { Command } from 'commander'

export function makeKeyCommand(): Command {
  const key = new Command('key').description('Manage cryptographic keys')

  key.command('create <type>')
    .description('Create a new key (type: ed25519)')
    .action((type: string) => {
      switch (type) {
        case 'ed25519':
          console.log('Creating Ed25519 key...')
          // TODO: implement
          break
        default:
          console.error(`Unknown key type: ${type}. Supported: ed25519`)
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
