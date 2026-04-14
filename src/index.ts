#!/usr/bin/env node
import { Command } from 'commander'

const program = new Command()

program.name('did').description('DID CLI tool').version('0.1.0')

program
  .command('resolve <did>')
  .description('Resolve a DID document')
  .option('-o, --output <format>', 'output format (json|pretty)', 'pretty')
  .action((did, options) => {
    console.log(`Resolving DID: ${did}`)
    console.log(`Output format: ${options.output}`)
    // TODO: implement resolution
  })

program.parse()
