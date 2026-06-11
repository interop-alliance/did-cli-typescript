/**
 * Env-gated end-to-end test of the `was` command group against a real WAS
 * server (e.g. a locally running was-teaching-server). Skipped unless
 * `WAS_TEST_SERVER_URL` points at a running server:
 *
 *     WAS_TEST_SERVER_URL=http://localhost:3002 npm run test:node
 *
 * Exercises the documented smoke flow: create a space and collection, put
 * and read back a resource, delegate read access to a second DID and read
 * through the capability, publish the resource and fetch its public URL
 * without auth, then delete the space.
 */
import { describe, it, beforeEach, afterEach, mock } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { driver } from '@interop/did-method-key'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'
import { makeWasCommand } from './was.js'
import { saveToDids } from '../storage.js'

const serverUrl = process.env.WAS_TEST_SERVER_URL

/**
 * Generates a did:key DID with an Ed25519 key and saves its document and
 * keys file to the (temp) local DID storage, the way `did create --save`
 * does.
 */
async function saveTestDid(): Promise<{ did: string }> {
  const keyPair = await Ed25519VerificationKey.generate()
  const didDriver = driver()
  didDriver.use({ keyPairClass: Ed25519VerificationKey })
  const { didDocument } = await didDriver.fromKeyPair({
    verificationKeyPair: keyPair
  })
  const did = didDocument.id
  const exported = await keyPair.export({ publicKey: true, secretKey: true })
  await saveToDids({ method: 'key', did, data: didDocument })
  await saveToDids({ method: 'key', did, suffix: 'keys', data: exported })
  return { did }
}

/**
 * Runs a `was` command with captured stdout/stderr and exit code, restoring
 * the console and process mocks afterwards.
 */
async function runWas(args: string[]): Promise<{
  logs: string[]
  errors: string[]
  exitCode?: number
}> {
  const logs: string[] = []
  const errors: string[] = []
  let exitCode: number | undefined
  mock.method(console, 'log', (...callArgs: unknown[]) =>
    logs.push(callArgs.join(' '))
  )
  mock.method(console, 'error', (...callArgs: unknown[]) =>
    errors.push(callArgs.join(' '))
  )
  mock.method(process, 'exit', (code: number) => {
    exitCode = code
  })
  try {
    await makeWasCommand().parseAsync(args, { from: 'user' })
  } finally {
    mock.restoreAll()
  }
  return { logs, errors, exitCode }
}

/**
 * Runs a `was` command that is expected to succeed, failing the test with
 * the command's stderr otherwise.
 */
async function runWasOk(args: string[]): Promise<string[]> {
  const { logs, errors, exitCode } = await runWas(args)
  assert.equal(
    exitCode,
    undefined,
    `was ${args.join(' ')} failed: ${errors.join('; ')}`
  )
  return logs
}

describe(
  'was integration (against WAS_TEST_SERVER_URL)',
  { skip: !serverUrl && 'set WAS_TEST_SERVER_URL to a running WAS server' },
  () => {
    let walletDir: string

    beforeEach(async () => {
      walletDir = await mkdtemp(join(tmpdir(), 'did-cli-test-wallet-'))
      process.env.WALLET_DIR = walletDir
    })

    afterEach(async () => {
      delete process.env.WALLET_DIR
      await rm(walletDir, { recursive: true, force: true })
    })

    it('runs the end-to-end WAS flow', async () => {
      const { did: alice } = await saveTestDid()
      const { did: bob } = await saveTestDid()
      const content = { hello: 'world' }

      // Create and register a space controlled by Alice.
      const createLogs = await runWasOk([
        'space',
        'create',
        '--name',
        'di integration test',
        '--server',
        serverUrl as string,
        '--did',
        alice,
        '--save',
        '--handle',
        'it-demo'
      ])
      const space = JSON.parse(createLogs[0]) as { id: string; url: string }
      assert.ok(space.id)

      try {
        // Collection + resource round-trip.
        await runWasOk([
          'collection',
          'create',
          'it-demo',
          '--name',
          'Docs',
          '--id',
          'it-docs'
        ])
        const payloadPath = join(walletDir, 'doc.json')
        await writeFile(payloadPath, JSON.stringify(content))
        await runWasOk(['put', 'it-demo/it-docs/doc-1', payloadPath])
        const getLogs = await runWasOk(['get', 'it-demo/it-docs/doc-1'])
        assert.deepEqual(JSON.parse(getLogs[0]), content)

        // Delegate read access to Bob and read through the capability.
        const grantLogs = await runWasOk([
          'grant',
          'it-demo/it-docs/doc-1',
          '--to',
          bob,
          '--action',
          'GET'
        ])
        const { encoded } = JSON.parse(grantLogs[0]) as { encoded: string }
        assert.ok(encoded.startsWith('z'))
        const capGetLogs = await runWasOk([
          'get',
          '--capability',
          encoded,
          '--did',
          bob
        ])
        assert.deepEqual(JSON.parse(capGetLogs[0]), content)

        // Publish the resource and fetch its public URL without auth.
        const publishLogs = await runWasOk(['publish', 'it-demo/it-docs/doc-1'])
        const publicUrl = publishLogs[0]
        const response = await fetch(publicUrl)
        assert.equal(response.status, 200)
        assert.deepEqual(await response.json(), content)
      } finally {
        // Clean up the server-side space (and the registry entry).
        await runWas(['rm', 'it-demo'])
      }
    })
  }
)
