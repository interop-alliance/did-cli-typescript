import { Command } from 'commander'
import {
  decodeSecretKeySeed,
  generateSecretKeySeed
} from '@digitalcredentials/bnid'
import { driver } from '@interop/did-method-key'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'
import { listDids, saveToDids } from '../storage.js'

export function makeIdCommand(): Command {
  const id = new Command('id').description('Manage DIDs')

  id.command('create [method]')
    .description('Create a new DID (method: key, web, webvh) [default: key]')
    .option('-t, --type <type>', 'key type (supported: ed25519)', 'ed25519')
    .option(
      '--with-seed',
      'include the secret key seed in output (generated if SECRET_KEY_SEED is not set)'
    )
    .option('--save', 'save the DID document to local storage (~/.dids/)')
    .action(
      async (
        method: string = 'key',
        options: { type: string; withSeed?: boolean; save?: boolean }
      ) => {
        switch (method) {
          case 'key': {
            switch (options.type) {
              case 'ed25519': {
                const envSeed = process.env.SECRET_KEY_SEED
                const secretKeySeed = options.withSeed
                  ? (envSeed ?? (await generateSecretKeySeed()))
                  : envSeed
                const seedBytes = secretKeySeed
                  ? decodeSecretKeySeed({ secretKeySeed })
                  : undefined
                const keyPair = await Ed25519VerificationKey.generate({
                  seed: seedBytes
                })

                const didDriver = driver()
                didDriver.use({ keyPairClass: Ed25519VerificationKey })
                const { didDocument } = await didDriver.fromKeyPair({
                  verificationKeyPair: keyPair
                })

                if (options.save) {
                  const did = didDocument.id as string
                  const exported = keyPair.export({
                    publicKey: true,
                    secretKey: true
                  })
                  const docPath = await saveToDids({
                    method: 'key',
                    did,
                    data: didDocument
                  })
                  await saveToDids({
                    method: 'key',
                    did,
                    suffix: 'keys',
                    data: exported
                  })
                  console.error(`DID saved to ${docPath}`)
                }

                const output: Record<string, unknown> = { id: didDocument.id }
                if (options.withSeed) {
                  output.secretKeySeed = secretKeySeed
                }
                output.didDocument = didDocument
                console.log(JSON.stringify(output, null, 2))
                break
              }
              default:
                console.error(
                  `Unknown key type: ${options.type}. Supported: ed25519`
                )
                process.exit(1)
            }
            break
          }
          case 'web':
          case 'webvh':
            console.log(`Creating did:${method}...`)
            // TODO: implement
            break
          default:
            console.error(
              `Unknown method: ${method}. Supported: key, web, webvh`
            )
            process.exit(1)
        }
      }
    )

  id.command('resolve <did>')
    .description('Resolve a DID document')
    .option('-o, --output <format>', 'output format (json|pretty)', 'pretty')
    .action((did: string, options: { output: string }) => {
      console.log(`Resolving ${did} (format: ${options.output})`)
      // TODO: implement
    })

  id.command('list')
    .description('List locally stored DIDs')
    .option('--json', 'output the list of DIDs as a JSON array')
    .action(async (options: { json?: boolean }) => {
      const dids = await listDids()
      if (options.json) {
        console.log(JSON.stringify(dids, null, 2))
        return
      }
      for (const did of dids) {
        console.log(did)
      }
    })

  return id
}
