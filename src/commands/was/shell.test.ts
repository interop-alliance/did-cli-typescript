/**
 * End-to-end tests for the interactive WAS shell driven without a TTY: a
 * scripted input stream is fed through `runWasShell` with a stubbed client, and
 * the recorded stub calls, captured stdout, and shell `output` stream are
 * asserted. The key properties: `cd`/`use` makes bare `ls` list the current
 * directory, a bad command reports an error but the next line still runs (the
 * no-`process.exit` property), and the session env defaults are restored on
 * exit.
 */
import { describe, it, beforeEach, afterEach, mock } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, rm } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { PassThrough } from 'node:stream'
import { driver } from '@interop/did-method-key'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'
import type { WasClient } from '@interop/was-client'
import { runWasShell } from './shell.js'
import { setWasClientFactory } from '../../was/client.js'
import { saveSpaceRecord } from '../../was/registry.js'
import { saveToDids } from '../../storage.js'

/**
 * Generates a did:key DID with an Ed25519 key and saves its document and keys
 * file to the (temp) local DID storage, the way `did create --save` does.
 */
async function saveTestDid(): Promise<string> {
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
  return did
}

/**
 * A stub `WasClient` recording collection/resource listing calls per space, so
 * shell dispatch can be asserted without a server.
 */
function makeStubClient(): {
  client: WasClient
  calls: { collections: string[]; listResources: string[] }
} {
  const calls = { collections: [] as string[], listResources: [] as string[] }
  const client = {
    space(spaceId: string) {
      return {
        id: spaceId,
        async collections() {
          calls.collections.push(spaceId)
          return {
            items: [
              { id: 'did', name: 'DID log', url: 'https://was.example/x' }
            ]
          }
        },
        collection(collectionId: string) {
          return {
            id: collectionId,
            async list() {
              calls.listResources.push(`${spaceId}/${collectionId}`)
              return {
                items: [
                  {
                    id: 'did.jsonl',
                    contentType: 'application/json',
                    url: 'https://was.example/y'
                  }
                ]
              }
            }
          }
        }
      }
    }
  }
  return { client: client as unknown as WasClient, calls }
}

describe('runWasShell', () => {
  let walletDir: string
  let logs: string[]
  let controller: string

  beforeEach(async () => {
    walletDir = await mkdtemp(join(tmpdir(), 'did-cli-test-shell-'))
    process.env.WALLET_DIR = walletDir
    delete process.env.WAS_SERVER_URL
    delete process.env.WAS_DID
    logs = []
    mock.method(console, 'log', (...args: unknown[]) =>
      logs.push(args.join(' '))
    )
    mock.method(console, 'error', () => {})
    controller = await saveTestDid()
    await saveSpaceRecord({
      record: {
        id: 'urn:uuid:demo-space',
        name: 'Demo',
        server: 'https://was.example',
        controller
      },
      handle: 'demo'
    })
  })

  afterEach(async () => {
    mock.restoreAll()
    setWasClientFactory()
    delete process.env.WALLET_DIR
    delete process.env.WAS_SERVER_URL
    delete process.env.WAS_DID
    await rm(walletDir, { recursive: true, force: true })
  })

  /**
   * Runs the shell over a scripted set of lines and returns the collected
   * stub calls, stdout logs, and shell output.
   */
  async function runScript(lines: string[]): Promise<{
    calls: { collections: string[]; listResources: string[] }
    output: string
    code: number
  }> {
    const { client, calls } = makeStubClient()
    setWasClientFactory(() => client)
    const input = new PassThrough()
    input.end(lines.map(line => `${line}\n`).join(''))
    const output = new PassThrough()
    const chunks: string[] = []
    output.on('data', chunk => chunks.push(chunk.toString()))
    const code = await runWasShell({ input, output })
    return { calls, output: chunks.join(''), code }
  }

  it(
    'lists the current directory for a bare ls after use, and keeps ' +
      'running past a bad command',
    async () => {
      const { calls, output, code } = await runScript([
        'use demo',
        'pwd',
        'ls',
        'bogus',
        'ls',
        'exit'
      ])

      assert.equal(code, 0)
      // Bare `ls` under the `demo` space listed its collections, both times.
      assert.deepEqual(calls.collections, [
        'urn:uuid:demo-space',
        'urn:uuid:demo-space'
      ])
      // The listing rendered to stdout.
      assert.match(logs.join('\n'), /did\s+DID log/)
      // `pwd` reported the selected directory on the shell output (stderr).
      assert.match(output, /\/demo/)
      // The bogus command errored, but the second `ls` still ran (2 calls).
      assert.match(output, /unknown command 'bogus'/)
    }
  )

  it('descends into a collection and lists its resources', async () => {
    const { calls } = await runScript(['use demo', 'cd did', 'ls', 'exit'])
    assert.deepEqual(calls.listResources, ['urn:uuid:demo-space/did'])
    assert.match(logs.join('\n'), /did\.jsonl/)
  })

  it('restores the WAS_SERVER_URL env default on exit', async () => {
    process.env.WAS_SERVER_URL = 'https://original.example'
    await runScript(['connect https://other.example', 'pwd', 'exit'])
    assert.equal(process.env.WAS_SERVER_URL, 'https://original.example')
  })

  it('leaves WAS_SERVER_URL unset when it started unset', async () => {
    assert.equal(process.env.WAS_SERVER_URL, undefined)
    await runScript(['connect https://other.example', 'exit'])
    assert.equal(process.env.WAS_SERVER_URL, undefined)
  })

  it('guards stdin-payload commands with a helpful message', async () => {
    const { output } = await runScript([
      'use demo',
      'put did/did.jsonl',
      'exit'
    ])
    assert.match(output, /Provide a file argument inside the shell/)
  })

  it('ignores blank lines and # comments', async () => {
    const { calls } = await runScript([
      '   ',
      '# a comment',
      'use demo',
      'ls',
      'exit'
    ])
    assert.deepEqual(calls.collections, ['urn:uuid:demo-space'])
  })

  it('exits cleanly on end-of-input without an explicit exit', async () => {
    const { code } = await runScript(['use demo', 'pwd'])
    assert.equal(code, 0)
  })
})
