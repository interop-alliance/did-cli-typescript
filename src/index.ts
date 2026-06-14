#!/usr/bin/env node
import { createRequire } from 'node:module'
import { Command } from 'commander'
import { makeDidCommand } from './commands/did.js'
import { makeEdvCommand } from './commands/edv.js'
import { makeKeyCommand } from './commands/key.js'
import { makeVcCommand } from './commands/vc.js'
import { makeWalletCommand } from './commands/wallet.js'
import { makeWasCommand } from './commands/was.js'
import { makeZcapCommand } from './commands/zcap.js'

const { version } = createRequire(import.meta.url)('../package.json') as {
  version: string
}

const program = new Command()

program.name('di').description('DID CLI tool').version(version)

program.addCommand(makeDidCommand())
program.addCommand(makeEdvCommand())
program.addCommand(makeKeyCommand())
program.addCommand(makeVcCommand())
program.addCommand(makeWalletCommand())
program.addCommand(makeWasCommand())
program.addCommand(makeZcapCommand())

program.parse()
