#!/usr/bin/env node
import { Command } from 'commander'
import { makeIdCommand } from './commands/id.js'
import { makeKeyCommand } from './commands/key.js'
import { makeVcCommand } from './commands/vc.js'
import { makeZcapCommand } from './commands/zcap.js'

const program = new Command()

program.name('did').description('DID CLI tool').version('0.1.0')

program.addCommand(makeIdCommand())
program.addCommand(makeKeyCommand())
program.addCommand(makeVcCommand())
program.addCommand(makeZcapCommand())

program.parse()
