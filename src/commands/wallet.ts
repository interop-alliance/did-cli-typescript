/**
 * The `wallet` command group reports on local wallet storage (`~/.wallet/`)
 * as a whole. `ls` prints a summary of how many items are saved in each
 * collection (keys, DIDs, zcaps, credentials, WAS spaces).
 */
import { Command } from 'commander'
import { listCollection, listDids } from '../storage.js'

/**
 * Count the items saved in each wallet collection.
 *
 * @returns {Promise<Record<string, number>>} collection label to item count.
 */
export async function countCollections(): Promise<Record<string, number>> {
  const [keys, dids, zcaps, vcs, spaces] = await Promise.all([
    listCollection('keys'),
    listDids(),
    listCollection('zcaps'),
    listCollection('credentials'),
    listCollection('was-spaces')
  ])
  return {
    keys: keys.length,
    dids: dids.length,
    zcaps: zcaps.length,
    vcs: vcs.length,
    spaces: spaces.length
  }
}

export function makeWalletCommand(): Command {
  const wallet = new Command('wallet').description(
    'Inspect local wallet storage'
  )

  wallet
    .command('ls')
    .alias('list')
    .description(
      'Show a summary of local wallet storage (item counts per collection)'
    )
    .option('--json', 'output the summary as a JSON object')
    .action(async (options: { json?: boolean }) => {
      const counts = await countCollections()
      if (options.json) {
        console.log(JSON.stringify(counts, null, 2))
        return
      }
      for (const [collection, count] of Object.entries(counts)) {
        console.log(`${collection}: ${count}`)
      }
    })

  return wallet
}
