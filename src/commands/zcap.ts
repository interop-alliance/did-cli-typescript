import { Command } from 'commander'

export function makeZcapCommand(): Command {
  const zcap = new Command('zcap').description('Manage authorization capabilities')

  zcap.command('create')
    .description('Create a new zcap')
    .action(() => {
      console.log('Creating zcap...')
      // TODO: implement
    })

  zcap.command('delegate')
    .description('Delegate a zcap')
    .action(() => {
      console.log('Delegating zcap...')
      // TODO: implement
    })

  zcap.command('list')
    .description('List locally stored zcaps')
    .action(() => {
      console.log('Listing zcaps...')
      // TODO: implement
    })

  zcap.command('revoke <id>')
    .description('Revoke a zcap by ID')
    .action((zcapId: string) => {
      console.log(`Revoking zcap ${zcapId}...`)
      // TODO: implement
    })

  return zcap
}
