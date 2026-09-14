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
 *
 * Also exercises `was request-grant` end to end through the server's
 * ephemeral-exchange facet, with a scripted wallet standing in for the user's:
 * it opens the interaction URL, delegates a public-collection capability from
 * the space controller's key, and posts the response presentation back.
 */
import { describe, it, beforeEach, afterEach, mock } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { driver } from '@interop/did-method-key'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'
import {
  composeVp,
  deliverPresentation,
  openInteractionRequest
} from '@interop/wallet-request'
import type { ICapabilityQueryDetail } from '@interop/data-integrity-core/vpr'
import { makeWasCommand } from './was.js'
import { saveToDids } from '../storage.js'
import { buildWasClient } from '../was/client.js'
import { PUBLIC_COLLECTION_TYPE } from '../was/request-grant.js'

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
 * Starts a `was` command with captured stdout/stderr and exit code. The
 * capture arrays are live while the command runs, which is what lets a test
 * read the interaction URL `request-grant` prints before it returns. The
 * console and process mocks are restored when the command settles.
 */
function startWas(args: string[]): {
  logs: string[]
  errors: string[]
  done: Promise<number | undefined>
} {
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
  const done = makeWasCommand()
    .parseAsync(args, { from: 'user' })
    .then(() => exitCode)
    .finally(() => mock.restoreAll())
  return { logs, errors, done }
}

/**
 * Runs a `was` command to completion with captured stdout/stderr and exit
 * code.
 */
async function runWas(args: string[]): Promise<{
  logs: string[]
  errors: string[]
  exitCode?: number
}> {
  const { logs, errors, done } = startWas(args)
  const exitCode = await done
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

/**
 * Waits for `request-grant` to print its interaction URL, polling the live
 * stderr capture. The URL is the one thing the scripted wallet needs from the
 * requesting side, exactly as a human would copy it into their wallet.
 */
async function awaitInteractionUrl(errors: string[]): Promise<string> {
  const deadline = Date.now() + 10_000
  while (Date.now() < deadline) {
    const match = errors.join('\n').match(/https?:\/\/\S+\/protocols\?iuv=1/)
    if (match) {
      return match[0]
    }
    await new Promise(resolve => setTimeout(resolve, 50))
  }
  throw new Error(
    `request-grant printed no interaction URL: ${errors.join('; ')}`
  )
}

/**
 * The scripted wallet: what a user's wallet does between opening the
 * interaction URL and the agent's poll completing. Opens the exchange to read
 * the VPR, checks it asks for a public collection, delegates that collection
 * from the space controller's key to the requesting agent, and posts the
 * response presentation (the zcap-only shape, unsigned, with the capability as
 * the presentation's `zcap` member) back to the exchange.
 */
async function approveGrant({
  interactionUrl,
  controller,
  collectionUrl
}: {
  interactionUrl: string
  controller: string
  collectionUrl: string
}): Promise<{ requestedController: string }> {
  const { exchangeUrl, request } = await openInteractionRequest({
    url: interactionUrl
  })
  const [query] = request.query as {
    type: string
    capabilityQuery: ICapabilityQueryDetail[]
  }[]
  assert.equal(query?.type, 'AuthorizationCapabilityQuery')
  const [detail] = query!.capabilityQuery
  const target = detail!.invocationTarget as { type: string; name: string }
  assert.equal(target.type, PUBLIC_COLLECTION_TYPE)
  assert.equal(target.name, 'web')

  const { client } = await buildWasClient({
    server: serverUrl as string,
    did: controller
  })
  const zcap = await client.grant({
    to: detail!.controller as string,
    actions: ['GET', 'PUT', 'POST'],
    expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
    target: collectionUrl
  })
  const verifiablePresentation = await composeVp({
    didAuthRequested: false,
    zcaps: [zcap]
  })
  await deliverPresentation({ request, exchangeUrl, verifiablePresentation })
  return { requestedController: detail!.controller as string }
}

describe(
  'was integration (against WAS_TEST_SERVER_URL)',
  { skip: !serverUrl && 'set WAS_TEST_SERVER_URL to a running WAS server' },
  () => {
    let walletDir: string

    beforeEach(async () => {
      walletDir = await mkdtemp(join(tmpdir(), 'did-cli-test-wallet-'))
      process.env.WALLET_DIR = walletDir
      process.env.DIDS_DIR = join(walletDir, 'dids')
    })

    afterEach(async () => {
      delete process.env.WALLET_DIR
      delete process.env.DIDS_DIR
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

        // Set custom metadata (name + tag) and read it back; the tag-only
        // update must preserve the name from the prior name-only update.
        await runWasOk([
          'resource-meta',
          'put',
          'it-demo/it-docs/doc-1',
          '--name',
          'Doc One'
        ])
        await runWasOk([
          'resource-meta',
          'put',
          'it-demo/it-docs/doc-1',
          '--tag',
          'env=integration'
        ])
        const metaLogs = await runWasOk([
          'resource-meta',
          'get',
          'it-demo/it-docs/doc-1'
        ])
        const meta = JSON.parse(metaLogs[0]) as {
          custom?: { name?: string; tags?: Record<string, string> }
        }
        assert.equal(meta.custom?.name, 'Doc One')
        assert.deepEqual(meta.custom?.tags, { env: 'integration' })

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
        assert.ok(encoded.startsWith('u'))
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

    it('requests a grant through the exchange facet and publishes a page', async () => {
      // The user's side: a space with a public `web` collection, controlled
      // by Alice. This is what a wallet provisions when it approves.
      const { did: alice } = await saveTestDid()
      const createLogs = await runWasOk([
        'space',
        'create',
        '--name',
        'di request-grant test',
        '--server',
        serverUrl as string,
        '--did',
        alice,
        '--save',
        '--handle',
        'it-grant'
      ])
      const space = JSON.parse(createLogs[0]) as { id: string; url: string }
      assert.ok(space.id)

      try {
        await runWasOk([
          'collection',
          'create',
          'it-grant',
          '--name',
          'Web',
          '--id',
          'web'
        ])
        await runWasOk(['publish', 'it-grant/web'])

        // The agent's side: ask for the grant and wait for the wallet.
        const grant = startWas([
          'request-grant',
          '--exchange',
          serverUrl as string,
          '--name',
          'it-agent',
          '--reason',
          'Publish a test page',
          '--save',
          '--handle',
          'agent',
          '--timeout',
          '60',
          '--json'
        ])
        const interactionUrl = await awaitInteractionUrl(grant.errors)
        const { requestedController } = await approveGrant({
          interactionUrl,
          controller: alice,
          collectionUrl: `${space.url}/web`
        })
        const exitCode = await grant.done
        assert.equal(
          exitCode,
          undefined,
          `request-grant failed: ${grant.errors.join('; ')}`
        )
        const granted = JSON.parse(grant.logs.join('\n')) as {
          controller: string
          handle: string
          capabilities: { invocationTarget: string; controller: string }[]
        }
        assert.equal(granted.controller, requestedController)
        assert.equal(granted.handle, 'agent')
        assert.equal(granted.capabilities.length, 1)
        assert.equal(granted.capabilities[0]?.controller, requestedController)
        assert.equal(
          granted.capabilities[0]?.invocationTarget,
          `${space.url}/web`
        )

        // Publish the page through the stored handle and read it back
        // anonymously as a page.
        const pagePath = join(walletDir, 'index.html')
        const html = '<!doctype html><title>Hi</title><h1>Published.</h1>'
        await writeFile(pagePath, html)
        const putLogs = await runWasOk([
          'put',
          pagePath,
          '--capability',
          'agent',
          '--did',
          'agent',
          '--resource',
          'index.html',
          '--content-type',
          'text/html'
        ])
        const { url } = JSON.parse(putLogs.join('\n')) as { url: string }
        assert.equal(url, `${space.url}/web/index.html`)
        const response = await fetch(url)
        assert.equal(response.status, 200)
        assert.match(response.headers.get('content-type') ?? '', /^text\/html/)
        assert.equal(await response.text(), html)
      } finally {
        await runWas(['rm', 'it-grant'])
      }
    })
  }
)
