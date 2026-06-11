#!/usr/bin/env node
import { Command } from 'commander'
import { makeDidCommand } from './commands/did.js'
import { makeKeyCommand } from './commands/key.js'
import { makeVcCommand } from './commands/vc.js'
import { makeWasCommand } from './commands/was.js'
import { makeZcapCommand } from './commands/zcap.js'

const program = new Command()

program.name('di').description('DID CLI tool').version('0.1.0')

program.addCommand(makeDidCommand())
program.addCommand(makeKeyCommand())
program.addCommand(makeVcCommand())
program.addCommand(makeWasCommand())
program.addCommand(makeZcapCommand())

program.parse()
