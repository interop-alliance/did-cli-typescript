import { Command } from 'commander'

export function makeIdCommand(): Command {
  const id = new Command('id').description('Manage DIDs')

  id.command('create <method>')
    .description('Create a new DID (method: key, web, webvh)')
    .action((method: string) => {
      switch (method) {
        case 'key':
        case 'web':
        case 'webvh':
          console.log(`Creating did:${method}...`)
          // TODO: implement
          break
        default:
          console.error(`Unknown method: ${method}. Supported: key, web, webvh`)
          process.exit(1)
      }
    })

  id.command('resolve <did>')
    .description('Resolve a DID document')
    .option('-o, --output <format>', 'output format (json|pretty)', 'pretty')
    .action((did: string, options: { output: string }) => {
      console.log(`Resolving ${did} (format: ${options.output})`)
      // TODO: implement
    })

  id.command('list')
    .description('List locally stored DIDs')
    .action(() => {
      console.log('Listing DIDs...')
      // TODO: implement
    })

  return id
}
