import { describe, it, beforeEach, afterEach, mock } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { driver } from '@interop/did-method-key'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'
import type { WasClient } from '@interop/was-client'
import { makeWasCommand } from './was.js'
import { setWasClientFactory } from '../was/client.js'
import { listSpaceRecords, saveSpaceRecord } from '../was/registry.js'
import {
  listCollection,
  loadFromCollection,
  saveMetaToCollection,
  saveToCollection,
  saveToDids
} from '../storage.js'
import { encodeCapability } from '../zcap/encoding.js'
import type { IZcap } from '@interop/was-client'

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
 * Canned responses for the stub client; `null` mimics a 404 miss.
 */
interface StubResponses {
  collections?: object | null
  describeCollection?: object | null
  resourceListing?: object | null
  get?: object | Blob | null
  meta?: object | null
  add?: object
  grant?: object
  policy?: object | null
  exportBytes?: Uint8Array
  importStats?: object
  backends?: object[] | null
  quotas?: object | null
  collectionBackend?: object | null
  collectionQuota?: object | null
}

/**
 * Builds a stub standing in for the `WasClient` handle graph, recording
 * every call so command wiring can be asserted without a server.
 */
function makeStubClient(responses: StubResponses = {}): {
  client: WasClient
  calls: Record<string, unknown[][]>
} {
  const calls: Record<string, unknown[][]> = {}
  function record(name: string, ...args: unknown[]): void {
    calls[name] = calls[name] ?? []
    calls[name].push(args)
  }
  /** The policy verbs every handle depth exposes, tagged with the depth. */
  function policyMethods(depth: string) {
    return {
      async getPolicy() {
        record('getPolicy', depth)
        return responses.policy ?? null
      },
      async setPolicy(policyDoc: object) {
        record('setPolicy', depth, policyDoc)
      },
      async clearPolicy() {
        record('clearPolicy', depth)
      },
      async setPublic() {
        record('setPublic', depth)
      }
    }
  }
  const client = {
    async createSpace(desc: { id?: string; name?: string }) {
      record('createSpace', desc)
      return { id: desc.id ?? 'space-new' }
    },
    async grant(options: object) {
      record('grant', options)
      return (
        responses.grant ?? {
          id: 'urn:zcap:delegated:zGranted',
          ...options
        }
      )
    },
    fromCapability(zcap: { invocationTarget: string }) {
      record('fromCapability', zcap)
      const segments = new URL(zcap.invocationTarget).pathname
        .split('/')
        .filter(Boolean)
      const [, spaceId, collectionId, resourceId] = segments
      const space = this.space(spaceId)
      if (resourceId) {
        return {
          ...space.collection(collectionId).resource(resourceId),
          spaceId,
          collectionId
        }
      }
      if (collectionId) {
        return { ...space.collection(collectionId), spaceId }
      }
      return space
    },
    space(spaceId: string) {
      record('space', spaceId)
      return {
        id: spaceId,
        async createCollection(desc: { id?: string; name?: string }) {
          record('createCollection', desc)
          return { id: desc.id ?? 'generated-coll' }
        },
        async collections() {
          record('collections')
          return responses.collections ?? null
        },
        async delete() {
          record('deleteSpace')
        },
        async backends() {
          record('backends')
          return responses.backends ?? null
        },
        async quotas() {
          record('quotas')
          return responses.quotas ?? null
        },
        async export() {
          record('exportSpace')
          return responses.exportBytes ?? new Uint8Array([0x74, 0x61, 0x72])
        },
        async import(tar: Uint8Array) {
          record('importSpace', tar)
          return (
            responses.importStats ?? {
              collectionsCreated: 1,
              collectionsSkipped: 0,
              resourcesCreated: 2,
              resourcesSkipped: 0,
              policiesCreated: 0,
              policiesSkipped: 0
            }
          )
        },
        ...policyMethods('space'),
        collection(collectionId: string) {
          record('collection', collectionId)
          return {
            id: collectionId,
            ...policyMethods('collection'),
            async describe() {
              record('describeCollection')
              return responses.describeCollection ?? null
            },
            async configure(desc: { name?: string }) {
              record('configureCollection', desc)
              return { id: collectionId, type: ['Collection'], ...desc }
            },
            async delete() {
              record('deleteCollection')
            },
            async backend() {
              record('collectionBackend')
              return responses.collectionBackend ?? null
            },
            async quota() {
              record('collectionQuota')
              return responses.collectionQuota ?? null
            },
            async add(data: unknown, options: object) {
              record('add', data, options)
              return (
                responses.add ?? {
                  id: 'res-1',
                  url: 'https://was.example/space/s/docs/res-1'
                }
              )
            },
            async list() {
              record('listResources')
              return responses.resourceListing ?? null
            },
            resource(resourceId: string) {
              record('resource', resourceId)
              return {
                id: resourceId,
                ...policyMethods('resource'),
                async get() {
                  record('get')
                  return responses.get ?? null
                },
                async put(data: unknown, options: object) {
                  record('put', data, options)
                },
                async meta() {
                  record('meta')
                  return responses.meta ?? null
                },
                async setMeta(meta: object) {
                  record('setMeta', meta)
                },
                async setName(name: string) {
                  record('setName', name)
                },
                async setTags(tags: Record<string, string>) {
                  record('setTags', tags)
                },
                async delete() {
                  record('deleteResource')
                }
              }
            }
          }
        }
      }
    }
  }
  return { client: client as unknown as WasClient, calls }
}

describe('di was', () => {
  let walletDir: string
  let logs: string[]
  let errors: string[]
  let exitCode: number | undefined

  beforeEach(async () => {
    walletDir = await mkdtemp(join(tmpdir(), 'did-cli-test-wallet-'))
    process.env.WALLET_DIR = walletDir
    logs = []
    errors = []
    exitCode = undefined
    mock.method(console, 'log', (...args: unknown[]) =>
      logs.push(args.join(' '))
    )
    mock.method(console, 'error', (...args: unknown[]) =>
      errors.push(args.join(' '))
    )
    mock.method(process, 'exit', (code: number) => {
      exitCode = code
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

  async function registerTestSpace(): Promise<void> {
    await saveSpaceRecord({
      record: {
        id: 'urn:uuid:1234',
        name: 'Home',
        server: 'https://was.example',
        controller: 'did:key:z6MkExample'
      },
      handle: 'home',
      description: 'Main storage space'
    })
  }

  describe('space list', () => {
    it('prints nothing when no spaces are registered', async () => {
      await makeWasCommand().parseAsync(['space', 'list'], { from: 'user' })
      assert.equal(exitCode, undefined)
      assert.deepEqual(logs, [])
    })

    it('renders a metadata table of registered spaces', async () => {
      await registerTestSpace()
      await makeWasCommand().parseAsync(['space', 'list'], { from: 'user' })
      assert.equal(exitCode, undefined)
      const output = logs.join('\n')
      assert.match(output, /HANDLE\s+NAME\s+SPACE ID\s+SERVER\s+CREATED/)
      assert.match(
        output,
        /home\s+Home\s+urn:uuid:1234\s+https:\/\/was\.example/
      )
    })

    it('--plain prints one space id per line', async () => {
      await registerTestSpace()
      await makeWasCommand().parseAsync(['space', 'list', '--plain'], {
        from: 'user'
      })
      assert.deepEqual(logs, ['urn:uuid:1234'])
    })

    it('--json outputs records with metadata', async () => {
      await registerTestSpace()
      await makeWasCommand().parseAsync(['space', 'list', '--json'], {
        from: 'user'
      })
      const output = JSON.parse(logs[0])
      assert.equal(output.length, 1)
      assert.equal(output[0].id, 'urn:uuid:1234')
      assert.equal(output[0].name, 'Home')
      assert.equal(output[0].server, 'https://was.example')
      assert.equal(output[0].controller, 'did:key:z6MkExample')
      assert.equal(output[0].handle, 'home')
      assert.equal(output[0].description, 'Main storage space')
      assert.ok(output[0].created)
    })
  })

  describe('space show --meta', () => {
    it('renders the registry metadata table by handle', async () => {
      await registerTestSpace()
      await makeWasCommand().parseAsync(['space', 'show', 'home', '--meta'], {
        from: 'user'
      })
      assert.equal(exitCode, undefined)
      const output = logs.join('\n')
      assert.match(output, /ID\s+urn:uuid:1234/)
      assert.match(output, /Server\s+https:\/\/was\.example/)
      assert.match(output, /Controller\s+did:key:z6MkExample/)
    })

    it('--json outputs the record with metadata', async () => {
      await registerTestSpace()
      await makeWasCommand().parseAsync(
        ['space', 'show', 'urn:uuid:1234', '--meta', '--json'],
        { from: 'user' }
      )
      const output = JSON.parse(logs[0])
      assert.equal(output.id, 'urn:uuid:1234')
      assert.equal(output.handle, 'home')
    })

    it('exits 2 for an unknown space reference', async () => {
      await makeWasCommand().parseAsync(['space', 'show', 'nope', '--meta'], {
        from: 'user'
      })
      assert.equal(exitCode, 2)
      assert.match(errors[0], /No locally registered space found for "nope"/)
    })

    it('exits 2 for a collection address', async () => {
      await makeWasCommand().parseAsync(
        ['space', 'show', 'home/credentials', '--meta'],
        { from: 'user' }
      )
      assert.equal(exitCode, 2)
      assert.match(errors[0], /space commands take a space address/)
    })
  })

  describe('space forget', () => {
    it('removes the registry entry and its sidecar', async () => {
      await registerTestSpace()
      await makeWasCommand().parseAsync(['space', 'forget', 'home'], {
        from: 'user'
      })
      assert.equal(exitCode, undefined)
      assert.equal(errors.length, 2)
      assert.ok(errors.every(line => line.startsWith('Removed ')))
      assert.deepEqual(await listSpaceRecords(), [])
    })

    it('exits 2 when the space is not registered', async () => {
      await makeWasCommand().parseAsync(['space', 'forget', 'nope'], {
        from: 'user'
      })
      assert.equal(exitCode, 2)
      assert.match(errors[0], /No locally registered space found/)
    })
  })

  describe('space meta', () => {
    it('updates the handle and description, leaving the record intact', async () => {
      await registerTestSpace()
      await makeWasCommand().parseAsync(
        [
          'space',
          'meta',
          'home',
          '--handle',
          'main',
          '--description',
          'Primary space'
        ],
        { from: 'user' }
      )
      assert.equal(exitCode, undefined)
      assert.match(errors[0], /^Updated metadata in /)
      const entries = await listSpaceRecords()
      assert.equal(entries.length, 1)
      assert.equal(entries[0].meta?.handle, 'main')
      assert.equal(entries[0].meta?.description, 'Primary space')
      assert.equal(entries[0].record.name, 'Home')
      assert.equal(entries[0].record.id, 'urn:uuid:1234')
    })

    it('updates only the description, preserving the existing handle', async () => {
      await registerTestSpace()
      await makeWasCommand().parseAsync(
        ['space', 'meta', 'home', '--description', 'New notes'],
        { from: 'user' }
      )
      assert.equal(exitCode, undefined)
      const entries = await listSpaceRecords()
      assert.equal(entries[0].meta?.handle, 'home')
      assert.equal(entries[0].meta?.description, 'New notes')
    })

    it('clears the handle when given an empty string', async () => {
      await registerTestSpace()
      await makeWasCommand().parseAsync(
        ['space', 'meta', 'urn:uuid:1234', '--handle', ''],
        { from: 'user' }
      )
      assert.equal(exitCode, undefined)
      const entries = await listSpaceRecords()
      assert.equal(entries[0].meta?.handle, undefined)
      assert.equal(entries[0].meta?.description, 'Main storage space')
    })

    it('exits 2 when neither --handle nor --description is given', async () => {
      await registerTestSpace()
      await makeWasCommand().parseAsync(['space', 'meta', 'home'], {
        from: 'user'
      })
      assert.equal(exitCode, 2)
      assert.match(errors[0], /Provide --handle and\/or --description to set/)
    })

    it('exits 2 when the space is not registered', async () => {
      await makeWasCommand().parseAsync(
        ['space', 'meta', 'nope', '--handle', 'x'],
        { from: 'user' }
      )
      assert.equal(exitCode, 2)
      assert.match(errors[0], /No locally registered space found/)
    })
  })

  describe('input validation', () => {
    it('space create rejects --handle without --save', async () => {
      await makeWasCommand().parseAsync(
        ['space', 'create', '--name', 'Home', '--handle', 'home'],
        { from: 'user' }
      )
      assert.equal(exitCode, 2)
      assert.match(errors[0], /--handle and --description require --save/)
    })

    it('space create exits 2 without a server URL', async () => {
      await makeWasCommand().parseAsync(['space', 'create', '--name', 'Home'], {
        from: 'user'
      })
      assert.equal(exitCode, 2)
      assert.match(errors[0], /No WAS server URL/)
    })

    it('space show exits 2 for a malformed address', async () => {
      await makeWasCommand().parseAsync(
        ['space', 'show', 'home//bad', '--meta'],
        { from: 'user' }
      )
      assert.equal(exitCode, 2)
      assert.match(errors[0], /empty path segment/)
    })
  })

  describe('with a stubbed client', () => {
    /**
     * Saves a test DID, registers a space pointing at it under the handle
     * `home`, and installs a stub client; returns the recorded calls.
     */
    async function setUpStub(
      responses: StubResponses = {}
    ): Promise<Record<string, unknown[][]>> {
      const { did } = await saveTestDid()
      await saveSpaceRecord({
        record: {
          id: 'space-1',
          name: 'Home',
          server: 'https://was.example',
          controller: did
        },
        handle: 'home'
      })
      const { client, calls } = makeStubClient(responses)
      setWasClientFactory(() => client)
      return calls
    }

    describe('space create', () => {
      it('creates a space without a name', async () => {
        const { did } = await saveTestDid()
        const { client, calls } = makeStubClient()
        setWasClientFactory(() => client)
        await makeWasCommand().parseAsync(
          ['space', 'create', '--server', 'https://was.example', '--did', did],
          { from: 'user' }
        )
        assert.equal(exitCode, undefined)
        assert.deepEqual(calls.createSpace, [[{}]])
        const output = JSON.parse(logs[0])
        assert.equal(output.id, 'space-new')
        assert.equal(output.url, 'https://was.example/space/space-new')
        assert.equal(output.controller, did)
        assert.ok(!('name' in output))
      })

      it('passes --name through and records it on --save', async () => {
        const { did } = await saveTestDid()
        const { client, calls } = makeStubClient()
        setWasClientFactory(() => client)
        await makeWasCommand().parseAsync(
          [
            'space',
            'create',
            '--name',
            'Home',
            '--server',
            'https://was.example',
            '--did',
            did,
            '--save',
            '--handle',
            'home'
          ],
          { from: 'user' }
        )
        assert.equal(exitCode, undefined)
        assert.deepEqual(calls.createSpace, [[{ name: 'Home' }]])
        const [entry] = await listSpaceRecords()
        assert.deepEqual(entry.record, {
          id: 'space-new',
          name: 'Home',
          server: 'https://was.example',
          controller: did
        })
        assert.equal(entry.meta?.handle, 'home')
      })
    })

    describe('collection commands', () => {
      it('create posts the collection and prints { id, url, name }', async () => {
        const calls = await setUpStub()
        await makeWasCommand().parseAsync(
          ['collection', 'create', 'home', '--name', 'Docs', '--id', 'docs'],
          { from: 'user' }
        )
        assert.equal(exitCode, undefined)
        assert.deepEqual(calls.createCollection, [
          [{ name: 'Docs', id: 'docs' }]
        ])
        const output = JSON.parse(logs[0])
        assert.equal(output.id, 'docs')
        assert.equal(output.name, 'Docs')
        assert.equal(output.url, 'https://was.example/space/space-1/docs')
      })

      it('create works without a name', async () => {
        const calls = await setUpStub()
        await makeWasCommand().parseAsync(
          ['collection', 'create', 'home', '--id', 'docs'],
          { from: 'user' }
        )
        assert.equal(exitCode, undefined)
        assert.deepEqual(calls.createCollection, [[{ id: 'docs' }]])
        const output = JSON.parse(logs[0])
        assert.equal(output.id, 'docs')
        assert.ok(!('name' in output))
      })

      it('list renders a table of collections', async () => {
        await setUpStub({
          collections: {
            url: 'https://was.example/space/space-1/collections/',
            totalItems: 1,
            items: [
              {
                id: 'docs',
                name: 'Docs',
                url: 'https://was.example/space/space-1/docs'
              }
            ]
          }
        })
        await makeWasCommand().parseAsync(['collection', 'list', 'home'], {
          from: 'user'
        })
        assert.equal(exitCode, undefined)
        const output = logs.join('\n')
        assert.match(output, /ID\s+NAME\s+URL/)
        assert.match(output, /docs\s+Docs\s+https:/)
      })

      it('list exits 1 on a missing/unauthorized space', async () => {
        await setUpStub({ collections: null })
        await makeWasCommand().parseAsync(['collection', 'list', 'home'], {
          from: 'user'
        })
        assert.equal(exitCode, 1)
        assert.match(
          errors[0],
          /Not found \(or not visible to you\): https:\/\/was\.example\/space\/space-1/
        )
      })

      it('show prints the collection description', async () => {
        await setUpStub({
          describeCollection: { id: 'docs', type: ['Collection'], name: 'Docs' }
        })
        await makeWasCommand().parseAsync(['collection', 'show', 'home/docs'], {
          from: 'user'
        })
        assert.equal(exitCode, undefined)
        assert.deepEqual(JSON.parse(logs[0]), {
          id: 'docs',
          type: ['Collection'],
          name: 'Docs'
        })
      })

      it('show exits 2 for a space-only address', async () => {
        await setUpStub()
        await makeWasCommand().parseAsync(['collection', 'show', 'home'], {
          from: 'user'
        })
        assert.equal(exitCode, 2)
        assert.match(errors[0], /must address a collection/)
      })

      it('update configures the collection', async () => {
        const calls = await setUpStub()
        await makeWasCommand().parseAsync(
          ['collection', 'update', 'home/docs', '--name', 'Renamed'],
          { from: 'user' }
        )
        assert.equal(exitCode, undefined)
        assert.deepEqual(calls.configureCollection, [[{ name: 'Renamed' }]])
        assert.equal(JSON.parse(logs[0]).name, 'Renamed')
      })

      it('delete reports the deleted URL', async () => {
        const calls = await setUpStub()
        await makeWasCommand().parseAsync(
          ['collection', 'delete', 'home/docs'],
          {
            from: 'user'
          }
        )
        assert.equal(exitCode, undefined)
        assert.equal(calls.deleteCollection.length, 1)
        assert.match(
          errors[0],
          /Deleted https:\/\/was\.example\/space\/space-1\/docs on the server\./
        )
      })
    })

    describe('collection backend', () => {
      it('renders the backend descriptor as a table', async () => {
        const calls = await setUpStub({
          collectionBackend: {
            id: 'default',
            name: 'Filesystem',
            managedBy: 'server',
            storageMode: ['document', 'blob'],
            persistence: 'durable'
          }
        })
        await makeWasCommand().parseAsync(
          ['collection', 'backend', 'home/docs'],
          { from: 'user' }
        )
        assert.equal(exitCode, undefined)
        assert.equal(calls.collectionBackend.length, 1)
        const table = logs.join('\n')
        assert.match(table, /default/)
        assert.match(table, /Filesystem/)
        assert.match(table, /document, blob/)
      })

      it('outputs raw JSON with --json', async () => {
        await setUpStub({
          collectionBackend: { id: 'default', managedBy: 'server' }
        })
        await makeWasCommand().parseAsync(
          ['collection', 'backend', 'home/docs', '--json'],
          { from: 'user' }
        )
        assert.equal(exitCode, undefined)
        assert.deepEqual(JSON.parse(logs.join('\n')), {
          id: 'default',
          managedBy: 'server'
        })
      })

      it('exits 1 on a missing/unauthorized collection', async () => {
        await setUpStub({ collectionBackend: null })
        await makeWasCommand().parseAsync(
          ['collection', 'backend', 'home/docs'],
          { from: 'user' }
        )
        assert.equal(exitCode, 1)
        assert.match(
          errors[0],
          /Not found \(or not visible to you\): https:\/\/was\.example\/space\/space-1\/docs/
        )
      })

      it('exits 2 for a space-only address', async () => {
        await setUpStub()
        await makeWasCommand().parseAsync(['collection', 'backend', 'home'], {
          from: 'user'
        })
        assert.equal(exitCode, 2)
        assert.match(errors[0], /must address a collection/)
      })
    })

    describe('collection quota', () => {
      it('renders the usage report as a table', async () => {
        const calls = await setUpStub({
          collectionQuota: {
            id: 'default',
            name: 'Filesystem',
            managedBy: 'server',
            state: 'ok',
            usageBytes: 2048,
            limit: { capacityBytes: 1048576, isUnlimited: false },
            restrictedActions: [],
            measuredAt: '2026-06-13T00:00:00Z'
          }
        })
        await makeWasCommand().parseAsync(
          ['collection', 'quota', 'home/docs'],
          {
            from: 'user'
          }
        )
        assert.equal(exitCode, undefined)
        assert.equal(calls.collectionQuota.length, 1)
        const table = logs.join('\n')
        assert.match(table, /default \(Filesystem\)/)
        assert.match(table, /ok/)
        assert.match(table, /2048/)
        assert.match(table, /1048576/)
      })

      it('shows "unlimited" for an unlimited backend', async () => {
        await setUpStub({
          collectionQuota: {
            id: 'default',
            managedBy: 'server',
            state: 'ok',
            usageBytes: 0,
            limit: { isUnlimited: true },
            restrictedActions: [],
            measuredAt: '2026-06-13T00:00:00Z'
          }
        })
        await makeWasCommand().parseAsync(
          ['collection', 'quota', 'home/docs'],
          {
            from: 'user'
          }
        )
        assert.equal(exitCode, undefined)
        assert.match(logs.join('\n'), /unlimited/)
      })

      it('outputs raw JSON with --json', async () => {
        const usage = {
          id: 'default',
          managedBy: 'server',
          state: 'ok',
          usageBytes: 0,
          limit: { isUnlimited: true },
          restrictedActions: [],
          measuredAt: '2026-06-13T00:00:00Z'
        }
        await setUpStub({ collectionQuota: usage })
        await makeWasCommand().parseAsync(
          ['collection', 'quota', 'home/docs', '--json'],
          { from: 'user' }
        )
        assert.equal(exitCode, undefined)
        assert.deepEqual(JSON.parse(logs.join('\n')), usage)
      })

      it('exits 1 on a missing/unauthorized collection', async () => {
        await setUpStub({ collectionQuota: null })
        await makeWasCommand().parseAsync(
          ['collection', 'quota', 'home/docs'],
          {
            from: 'user'
          }
        )
        assert.equal(exitCode, 1)
        assert.match(
          errors[0],
          /Not found \(or not visible to you\): https:\/\/was\.example\/space\/space-1\/docs/
        )
      })

      it('exits 2 for a space-only address', async () => {
        await setUpStub()
        await makeWasCommand().parseAsync(['collection', 'quota', 'home'], {
          from: 'user'
        })
        assert.equal(exitCode, 2)
        assert.match(errors[0], /must address a collection/)
      })
    })

    describe('resource commands', () => {
      it('add sends a JSON file payload and prints the add result', async () => {
        const calls = await setUpStub({
          add: {
            id: 'res-1',
            url: 'https://was.example/space/space-1/docs/res-1',
            contentType: 'application/json'
          }
        })
        const filePath = join(walletDir, 'vc.json')
        await writeFile(filePath, '{"name": "Alice"}')
        await makeWasCommand().parseAsync(
          ['resource', 'add', 'home/docs', filePath],
          { from: 'user' }
        )
        assert.equal(exitCode, undefined)
        assert.deepEqual(calls.add, [[{ name: 'Alice' }, {}]])
        assert.equal(JSON.parse(logs[0]).id, 'res-1')
      })

      it('add sends binary bytes with an explicit content type', async () => {
        const calls = await setUpStub()
        const filePath = join(walletDir, 'pic.bin')
        await writeFile(filePath, Buffer.from([1, 2, 3]))
        await makeWasCommand().parseAsync(
          [
            'resource',
            'add',
            'home/docs',
            filePath,
            '--content-type',
            'image/png'
          ],
          { from: 'user' }
        )
        assert.equal(exitCode, undefined)
        const [data, options] = calls.add[0]
        assert.ok(data instanceof Uint8Array)
        assert.deepEqual(options, { contentType: 'image/png' })
      })

      it('put stores the payload and prints { id, url }', async () => {
        const calls = await setUpStub()
        const filePath = join(walletDir, 'vc.json')
        await writeFile(filePath, '{"name": "Alice"}')
        await makeWasCommand().parseAsync(
          ['resource', 'put', 'home/docs/vc-1', filePath],
          { from: 'user' }
        )
        assert.equal(exitCode, undefined)
        assert.deepEqual(calls.put, [[{ name: 'Alice' }, {}]])
        assert.deepEqual(JSON.parse(logs[0]), {
          id: 'vc-1',
          url: 'https://was.example/space/space-1/docs/vc-1'
        })
      })

      it('put exits 2 for a collection-depth address', async () => {
        await setUpStub()
        await makeWasCommand().parseAsync(['resource', 'put', 'home/docs'], {
          from: 'user'
        })
        assert.equal(exitCode, 2)
        assert.match(errors[0], /must address a resource/)
      })

      it('get pretty-prints a JSON resource', async () => {
        await setUpStub({ get: { name: 'Alice' } })
        await makeWasCommand().parseAsync(
          ['resource', 'get', 'home/docs/vc-1'],
          {
            from: 'user'
          }
        )
        assert.equal(exitCode, undefined)
        assert.deepEqual(JSON.parse(logs[0]), { name: 'Alice' })
      })

      it('get writes binary content to --output', async () => {
        await setUpStub({
          get: new Blob([Buffer.from('raw bytes')], { type: 'image/png' })
        })
        const output = join(walletDir, 'out.bin')
        await makeWasCommand().parseAsync(
          ['resource', 'get', 'home/docs/pic-1', '--output', output],
          { from: 'user' }
        )
        assert.equal(exitCode, undefined)
        assert.equal(await readFile(output, 'utf8'), 'raw bytes')
      })

      it('get exits 1 on a miss', async () => {
        await setUpStub({ get: null })
        await makeWasCommand().parseAsync(
          ['resource', 'get', 'home/docs/vc-1'],
          {
            from: 'user'
          }
        )
        assert.equal(exitCode, 1)
        assert.match(
          errors[0],
          /Not found \(or not visible to you\): https:\/\/was\.example\/space\/space-1\/docs\/vc-1/
        )
      })

      it('list renders a table of resources', async () => {
        await setUpStub({
          resourceListing: {
            id: 'docs',
            url: 'https://was.example/space/space-1/docs/',
            type: ['Collection'],
            totalItems: 1,
            items: [
              {
                id: 'vc-1',
                contentType: 'application/json',
                url: 'https://was.example/space/space-1/docs/vc-1'
              }
            ]
          }
        })
        await makeWasCommand().parseAsync(['resource', 'list', 'home/docs'], {
          from: 'user'
        })
        assert.equal(exitCode, undefined)
        const output = logs.join('\n')
        assert.match(output, /ID\s+CONTENT TYPE\s+URL/)
        assert.match(output, /vc-1\s+application\/json\s+https:/)
      })

      it('delete reports the deleted URL', async () => {
        const calls = await setUpStub()
        await makeWasCommand().parseAsync(
          ['resource', 'delete', 'home/docs/vc-1'],
          { from: 'user' }
        )
        assert.equal(exitCode, undefined)
        assert.equal(calls.deleteResource.length, 1)
        assert.match(
          errors[0],
          /Deleted .*\/space-1\/docs\/vc-1 on the server\./
        )
      })
    })

    describe('resource-meta commands', () => {
      it('get pretty-prints a resource metadata object', async () => {
        await setUpStub({
          meta: {
            contentType: 'application/json',
            size: 42,
            custom: { name: 'Diploma', tags: { year: '2026' } }
          }
        })
        await makeWasCommand().parseAsync(
          ['resource-meta', 'get', 'home/docs/vc-1'],
          { from: 'user' }
        )
        assert.equal(exitCode, undefined)
        assert.deepEqual(JSON.parse(logs.join('\n')), {
          contentType: 'application/json',
          size: 42,
          custom: { name: 'Diploma', tags: { year: '2026' } }
        })
      })

      it('get exits 1 on a metadata miss', async () => {
        await setUpStub({ meta: null })
        await makeWasCommand().parseAsync(
          ['resource-meta', 'get', 'home/docs/vc-1'],
          { from: 'user' }
        )
        assert.equal(exitCode, 1)
        assert.match(errors[0], /Not found \(or not visible to you\)/)
      })

      it('put --name only calls setName (preserving tags)', async () => {
        const calls = await setUpStub({
          meta: { contentType: 'application/json', size: 1 }
        })
        await makeWasCommand().parseAsync(
          ['resource-meta', 'put', 'home/docs/vc-1', '--name', 'Renamed'],
          { from: 'user' }
        )
        assert.equal(exitCode, undefined)
        assert.deepEqual(calls.setName, [['Renamed']])
        assert.equal(calls.setMeta, undefined)
        assert.equal(calls.setTags, undefined)
      })

      it('put --tag only calls setTags with parsed key=value pairs', async () => {
        const calls = await setUpStub({
          meta: { contentType: 'application/json', size: 1 }
        })
        await makeWasCommand().parseAsync(
          [
            'resource-meta',
            'put',
            'home/docs/vc-1',
            '--tag',
            'year=2026',
            '--tag',
            'status=verified'
          ],
          { from: 'user' }
        )
        assert.equal(exitCode, undefined)
        assert.deepEqual(calls.setTags, [
          [{ year: '2026', status: 'verified' }]
        ])
        assert.equal(calls.setName, undefined)
        assert.equal(calls.setMeta, undefined)
      })

      it('put --name and --tag together is a full setMeta replacement', async () => {
        const calls = await setUpStub({
          meta: { contentType: 'application/json', size: 1 }
        })
        await makeWasCommand().parseAsync(
          [
            'resource-meta',
            'put',
            'home/docs/vc-1',
            '--name',
            'Diploma',
            '--tag',
            'year=2026'
          ],
          { from: 'user' }
        )
        assert.equal(exitCode, undefined)
        assert.deepEqual(calls.setMeta, [
          [{ custom: { name: 'Diploma', tags: { year: '2026' } } }]
        ])
      })

      it('put --json replaces custom from inline JSON', async () => {
        const calls = await setUpStub({
          meta: { contentType: 'application/json', size: 1 }
        })
        await makeWasCommand().parseAsync(
          [
            'resource-meta',
            'put',
            'home/docs/vc-1',
            '--json',
            '{"name":"From JSON","tags":{"a":"b"}}'
          ],
          { from: 'user' }
        )
        assert.equal(exitCode, undefined)
        assert.deepEqual(calls.setMeta, [
          [{ custom: { name: 'From JSON', tags: { a: 'b' } } }]
        ])
      })

      it('put --json reads custom from a JSON file', async () => {
        const calls = await setUpStub({
          meta: { contentType: 'application/json', size: 1 }
        })
        const filePath = join(walletDir, 'custom.json')
        await writeFile(filePath, '{"name":"From File"}')
        await makeWasCommand().parseAsync(
          ['resource-meta', 'put', 'home/docs/vc-1', '--json', filePath],
          { from: 'user' }
        )
        assert.equal(exitCode, undefined)
        assert.deepEqual(calls.setMeta, [[{ custom: { name: 'From File' } }]])
      })

      it('put exits 2 with neither --name, --tag, nor --json', async () => {
        await setUpStub()
        await makeWasCommand().parseAsync(
          ['resource-meta', 'put', 'home/docs/vc-1'],
          { from: 'user' }
        )
        assert.equal(exitCode, 2)
        assert.match(errors[0], /Provide --name, --tag <key=value>, or --json/)
      })

      it('put exits 2 when --json is combined with --name', async () => {
        await setUpStub()
        await makeWasCommand().parseAsync(
          [
            'resource-meta',
            'put',
            'home/docs/vc-1',
            '--name',
            'X',
            '--json',
            '{}'
          ],
          { from: 'user' }
        )
        assert.equal(exitCode, 2)
        assert.match(errors[0], /Provide either --json or --name\/--tag/)
      })

      it('put exits 2 on a malformed --tag', async () => {
        await setUpStub()
        await makeWasCommand().parseAsync(
          ['resource-meta', 'put', 'home/docs/vc-1', '--tag', 'oops'],
          { from: 'user' }
        )
        assert.equal(exitCode, 2)
        assert.match(errors[0], /Invalid --tag "oops"; expected key=value/)
      })

      it('meta alias works for get', async () => {
        await setUpStub({
          meta: { contentType: 'text/plain', size: 3 }
        })
        await makeWasCommand().parseAsync(['meta', 'get', 'home/docs/vc-1'], {
          from: 'user'
        })
        assert.equal(exitCode, undefined)
        assert.deepEqual(JSON.parse(logs.join('\n')), {
          contentType: 'text/plain',
          size: 3
        })
      })
    })

    describe('top-level shorthand verbs', () => {
      it('ls of a space lists its collections', async () => {
        const calls = await setUpStub({
          collections: {
            url: 'https://was.example/space/space-1/collections/',
            totalItems: 0,
            items: []
          }
        })
        await makeWasCommand().parseAsync(['ls', 'home'], { from: 'user' })
        assert.equal(exitCode, undefined)
        assert.equal(calls.collections.length, 1)
      })

      it('ls of a collection lists its resources', async () => {
        const calls = await setUpStub({
          resourceListing: {
            id: 'docs',
            url: 'https://was.example/space/space-1/docs/',
            type: ['Collection'],
            totalItems: 0,
            items: []
          }
        })
        await makeWasCommand().parseAsync(['ls', 'home/docs'], { from: 'user' })
        assert.equal(exitCode, undefined)
        assert.equal(calls.listResources.length, 1)
      })

      it('ls of a resource exits 2', async () => {
        await setUpStub()
        await makeWasCommand().parseAsync(['ls', 'home/docs/vc-1'], {
          from: 'user'
        })
        assert.equal(exitCode, 2)
        assert.match(errors[0], /ls takes a space or collection address/)
      })

      it('rm dispatches on the path depth', async () => {
        const calls = await setUpStub()
        await makeWasCommand().parseAsync(['rm', 'home/docs/vc-1'], {
          from: 'user'
        })
        assert.equal(calls.deleteResource.length, 1)
        await makeWasCommand().parseAsync(['rm', 'home/docs'], { from: 'user' })
        assert.equal(calls.deleteCollection.length, 1)
        await makeWasCommand().parseAsync(['rm', 'home'], { from: 'user' })
        assert.equal(calls.deleteSpace.length, 1)
        assert.equal(exitCode, undefined)
        // Deleting the space also dropped its registry entry.
        assert.deepEqual(await listSpaceRecords(), [])
      })

      it('get is a shorthand for resource get', async () => {
        await setUpStub({ get: { name: 'Alice' } })
        await makeWasCommand().parseAsync(['get', 'home/docs/vc-1'], {
          from: 'user'
        })
        assert.equal(exitCode, undefined)
        assert.deepEqual(JSON.parse(logs[0]), { name: 'Alice' })
      })

      it('put is a shorthand for resource put', async () => {
        const calls = await setUpStub()
        const filePath = join(walletDir, 'note.txt')
        await writeFile(filePath, 'plain text')
        await makeWasCommand().parseAsync(
          ['put', 'home/docs/note-1', filePath],
          {
            from: 'user'
          }
        )
        assert.equal(exitCode, undefined)
        const [data, options] = calls.put[0]
        assert.ok(data instanceof Uint8Array)
        assert.deepEqual(options, { contentType: 'application/octet-stream' })
      })
    })

    describe('grant', () => {
      it('delegates with normalized actions and the depth target URL', async () => {
        const calls = await setUpStub()
        await makeWasCommand().parseAsync(
          [
            'grant',
            'home/docs',
            '--to',
            'did:key:z6MkBob',
            '--action',
            'get',
            'put'
          ],
          { from: 'user' }
        )
        assert.equal(exitCode, undefined)
        const [grantOptions] = calls.grant[0] as [
          { to: string; actions: string[]; expires: string; target: string }
        ]
        assert.equal(grantOptions.to, 'did:key:z6MkBob')
        assert.deepEqual(grantOptions.actions, ['GET', 'PUT'])
        assert.equal(
          grantOptions.target,
          'https://was.example/space/space-1/docs'
        )
        assert.ok(grantOptions.expires)
        const output = JSON.parse(logs[0])
        assert.equal(
          output.delegatedCapability.id,
          'urn:zcap:delegated:zGranted'
        )
        assert.ok(output.encoded.startsWith('z'))
      })

      it('targets the space or resource URL by path depth', async () => {
        const calls = await setUpStub()
        await makeWasCommand().parseAsync(
          ['grant', 'home', '--to', 'did:key:z6MkBob', '--action', 'GET'],
          { from: 'user' }
        )
        await makeWasCommand().parseAsync(
          [
            'grant',
            'home/docs/vc-1',
            '--to',
            'did:key:z6MkBob',
            '--action',
            'GET'
          ],
          { from: 'user' }
        )
        const targets = calls.grant.map(
          args => (args[0] as { target: string }).target
        )
        assert.deepEqual(targets, [
          'https://was.example/space/space-1',
          'https://was.example/space/space-1/docs/vc-1'
        ])
      })

      it('rejects an unknown action verb', async () => {
        await setUpStub()
        await makeWasCommand().parseAsync(
          ['grant', 'home/docs', '--to', 'did:key:z6MkBob', '--action', 'fly'],
          { from: 'user' }
        )
        assert.equal(exitCode, 2)
        assert.match(errors[0], /Unknown action "fly"/)
      })

      it('passes an explicit --expires through', async () => {
        const calls = await setUpStub()
        await makeWasCommand().parseAsync(
          [
            'grant',
            'home/docs',
            '--to',
            'did:key:z6MkBob',
            '--action',
            'GET',
            '--expires',
            '2027-06-11T00:00:00Z'
          ],
          { from: 'user' }
        )
        const [grantOptions] = calls.grant[0] as [{ expires: string }]
        assert.equal(grantOptions.expires, '2027-06-11T00:00:00Z')
      })

      it('--save stores the capability in the zcap store', async () => {
        await setUpStub()
        await makeWasCommand().parseAsync(
          [
            'grant',
            'home/docs',
            '--to',
            'did:key:z6MkBob',
            '--action',
            'GET',
            '--save',
            '--handle',
            'bob-share'
          ],
          { from: 'user' }
        )
        assert.equal(exitCode, undefined)
        const storageIds = await listCollection('zcaps')
        assert.equal(storageIds.length, 1)
        const saved = await loadFromCollection<{ id: string }>({
          collection: 'zcaps',
          storageId: storageIds[0]
        })
        assert.equal(saved.id, 'urn:zcap:delegated:zGranted')
        assert.match(errors[0], /Capability saved to /)
      })

      it('rejects --handle without --save', async () => {
        await setUpStub()
        await makeWasCommand().parseAsync(
          [
            'grant',
            'home/docs',
            '--to',
            'did:key:z6MkBob',
            '--action',
            'GET',
            '--handle',
            'bob-share'
          ],
          { from: 'user' }
        )
        assert.equal(exitCode, 2)
        assert.match(errors[0], /--handle and --description require --save/)
      })
    })

    describe('--capability addressing', () => {
      /**
       * Saves a test DID and installs a stub client (no registry entry --
       * everything resolves from the capability itself); returns the
       * recorded calls and a zcap-builder bound to the saved DID.
       */
      async function setUpCapabilityStub(
        responses: StubResponses = {}
      ): Promise<{
        calls: Record<string, unknown[][]>
        makeZcap: (target: string) => IZcap
      }> {
        const { did } = await saveTestDid()
        const { client, calls } = makeStubClient(responses)
        setWasClientFactory(() => client)
        function makeZcap(target: string): IZcap {
          return {
            id: 'urn:zcap:delegated:zReceived',
            controller: did,
            invocationTarget: target,
            parentCapability: `urn:zcap:root:${encodeURIComponent(target)}`
          } as IZcap
        }
        return { calls, makeZcap }
      }

      it('get reads a resource through an encoded capability', async () => {
        const { calls, makeZcap } = await setUpCapabilityStub({
          get: { name: 'Alice' }
        })
        const zcap = makeZcap('https://was.example/space/space-1/docs/vc-1')
        await makeWasCommand().parseAsync(
          ['get', '--capability', encodeCapability(zcap)],
          { from: 'user' }
        )
        assert.equal(exitCode, undefined)
        assert.deepEqual(JSON.parse(logs[0]), { name: 'Alice' })
        assert.deepEqual(calls.fromCapability[0], [zcap])
        // The signing DID fell back to the capability's controller.
        assert.equal(calls.get.length, 1)
      })

      it('get resolves a stored zcap by handle', async () => {
        const { makeZcap } = await setUpCapabilityStub({
          get: { name: 'Alice' }
        })
        const zcap = makeZcap('https://was.example/space/space-1/docs/vc-1')
        await saveToCollection({
          collection: 'zcaps',
          storageId: 'stored-share',
          data: zcap
        })
        await saveMetaToCollection({
          collection: 'zcaps',
          storageId: 'stored-share',
          meta: { handle: 'bob-share' }
        })
        await makeWasCommand().parseAsync(
          ['get', '--capability', 'bob-share'],
          { from: 'user' }
        )
        assert.equal(exitCode, undefined)
        assert.deepEqual(JSON.parse(logs[0]), { name: 'Alice' })
      })

      it('get rejects a collection-depth capability', async () => {
        const { makeZcap } = await setUpCapabilityStub()
        const zcap = makeZcap('https://was.example/space/space-1/docs')
        await makeWasCommand().parseAsync(
          ['get', '--capability', encodeCapability(zcap)],
          { from: 'user' }
        )
        assert.equal(exitCode, 2)
        assert.match(
          errors[0],
          /capability targets a collection; get needs a resource capability/
        )
      })

      it('ls dispatches on the capability target depth', async () => {
        const { calls, makeZcap } = await setUpCapabilityStub({
          collections: { url: 'u', totalItems: 0, items: [] },
          resourceListing: {
            id: 'docs',
            url: 'u',
            type: ['Collection'],
            totalItems: 0,
            items: []
          }
        })
        await makeWasCommand().parseAsync(
          [
            'ls',
            '--capability',
            encodeCapability(makeZcap('https://was.example/space/space-1'))
          ],
          { from: 'user' }
        )
        assert.equal(calls.collections.length, 1)
        await makeWasCommand().parseAsync(
          [
            'ls',
            '--capability',
            encodeCapability(makeZcap('https://was.example/space/space-1/docs'))
          ],
          { from: 'user' }
        )
        assert.equal(calls.listResources.length, 1)
        assert.equal(exitCode, undefined)
      })

      it('put shifts the positional file argument', async () => {
        const { calls, makeZcap } = await setUpCapabilityStub()
        const zcap = makeZcap('https://was.example/space/space-1/docs/vc-1')
        const filePath = join(walletDir, 'vc.json')
        await writeFile(filePath, '{"name": "Alice"}')
        await makeWasCommand().parseAsync(
          ['put', filePath, '--capability', encodeCapability(zcap)],
          { from: 'user' }
        )
        assert.equal(exitCode, undefined)
        assert.deepEqual(calls.put, [[{ name: 'Alice' }, {}]])
        assert.deepEqual(JSON.parse(logs[0]), {
          id: 'vc-1',
          url: 'https://was.example/space/space-1/docs/vc-1'
        })
      })

      it('resource add accepts a collection capability', async () => {
        const { calls, makeZcap } = await setUpCapabilityStub({
          add: {
            id: 'res-9',
            url: 'https://was.example/space/space-1/docs/res-9'
          }
        })
        const zcap = makeZcap('https://was.example/space/space-1/docs')
        const filePath = join(walletDir, 'vc.json')
        await writeFile(filePath, '{"name": "Alice"}')
        await makeWasCommand().parseAsync(
          ['resource', 'add', filePath, '--capability', encodeCapability(zcap)],
          { from: 'user' }
        )
        assert.equal(exitCode, undefined)
        assert.deepEqual(calls.add, [[{ name: 'Alice' }, {}]])
        assert.equal(JSON.parse(logs[0]).id, 'res-9')
      })

      it('rm deletes at the capability target depth', async () => {
        const { calls, makeZcap } = await setUpCapabilityStub()
        await makeWasCommand().parseAsync(
          [
            'rm',
            '--capability',
            encodeCapability(
              makeZcap('https://was.example/space/space-1/docs/vc-1')
            )
          ],
          { from: 'user' }
        )
        assert.equal(exitCode, undefined)
        assert.equal(calls.deleteResource.length, 1)
        assert.match(
          errors[0],
          /Deleted https:\/\/was\.example\/space\/space-1\/docs\/vc-1 on the server\./
        )
      })

      it('rejects a path and --capability together', async () => {
        const { makeZcap } = await setUpCapabilityStub()
        const zcap = makeZcap('https://was.example/space/space-1/docs/vc-1')
        await makeWasCommand().parseAsync(
          ['get', 'home/docs/vc-1', '--capability', encodeCapability(zcap)],
          { from: 'user' }
        )
        assert.equal(exitCode, 2)
        assert.match(errors[0], /Provide either a path or --capability/)
      })

      it('rejects neither a path nor --capability', async () => {
        await setUpCapabilityStub()
        await makeWasCommand().parseAsync(['get'], { from: 'user' })
        assert.equal(exitCode, 2)
        assert.match(errors[0], /Provide a path or --capability/)
      })
    })

    describe('policy and publishing', () => {
      it('policy show prints the policy document', async () => {
        const calls = await setUpStub({ policy: { type: 'PublicCanRead' } })
        await makeWasCommand().parseAsync(['policy', 'show', 'home'], {
          from: 'user'
        })
        assert.equal(exitCode, undefined)
        assert.deepEqual(calls.getPolicy, [['space']])
        assert.deepEqual(JSON.parse(logs[0]), { type: 'PublicCanRead' })
      })

      it('policy show exits 1 when no policy is set', async () => {
        await setUpStub({ policy: null })
        await makeWasCommand().parseAsync(['policy', 'show', 'home'], {
          from: 'user'
        })
        assert.equal(exitCode, 1)
        assert.match(
          errors[0],
          /No policy set \(or not visible to you\): https:\/\/was\.example\/space\/space-1/
        )
      })

      it('policy commands dispatch on the path depth', async () => {
        const calls = await setUpStub({ policy: { type: 'PublicCanRead' } })
        await makeWasCommand().parseAsync(
          ['policy', 'show', 'home/docs/vc-1'],
          { from: 'user' }
        )
        await makeWasCommand().parseAsync(['policy', 'clear', 'home/docs'], {
          from: 'user'
        })
        assert.deepEqual(calls.getPolicy, [['resource']])
        assert.deepEqual(calls.clearPolicy, [['collection']])
      })

      it('policy set --type sends a type-only policy', async () => {
        const calls = await setUpStub()
        await makeWasCommand().parseAsync(
          ['policy', 'set', 'home/docs', '--type', 'PublicCanRead'],
          { from: 'user' }
        )
        assert.equal(exitCode, undefined)
        assert.deepEqual(calls.setPolicy, [
          ['collection', { type: 'PublicCanRead' }]
        ])
        assert.deepEqual(JSON.parse(logs[0]), { type: 'PublicCanRead' })
        assert.match(
          errors[0],
          /Policy set on https:\/\/was\.example\/space\/space-1\/docs/
        )
      })

      it('policy set reads a policy JSON file', async () => {
        const calls = await setUpStub()
        const filePath = join(walletDir, 'policy.json')
        await writeFile(
          filePath,
          '{"type": "CustomPolicy", "allow": ["did:key:z6MkBob"]}'
        )
        await makeWasCommand().parseAsync(['policy', 'set', 'home', filePath], {
          from: 'user'
        })
        assert.equal(exitCode, undefined)
        assert.deepEqual(calls.setPolicy, [
          ['space', { type: 'CustomPolicy', allow: ['did:key:z6MkBob'] }]
        ])
      })

      it('policy set rejects --type together with a file', async () => {
        await setUpStub()
        await makeWasCommand().parseAsync(
          ['policy', 'set', 'home', 'policy.json', '--type', 'PublicCanRead'],
          { from: 'user' }
        )
        assert.equal(exitCode, 2)
        assert.match(errors[0], /either --type or a policy file, not both/)
      })

      it('policy set requires --type or a file', async () => {
        await setUpStub()
        await makeWasCommand().parseAsync(['policy', 'set', 'home'], {
          from: 'user'
        })
        assert.equal(exitCode, 2)
        assert.match(errors[0], /Provide --type <type> or a policy JSON file/)
      })

      it('policy set rejects a file without a "type" field', async () => {
        await setUpStub()
        const filePath = join(walletDir, 'policy.json')
        await writeFile(filePath, '{"allow": []}')
        await makeWasCommand().parseAsync(['policy', 'set', 'home', filePath], {
          from: 'user'
        })
        assert.equal(exitCode, 2)
        assert.match(errors[0], /must hold a policy object with a "type" field/)
      })

      it('publish makes the path public and prints the public URL', async () => {
        const calls = await setUpStub()
        await makeWasCommand().parseAsync(['publish', 'home/docs'], {
          from: 'user'
        })
        assert.equal(exitCode, undefined)
        assert.deepEqual(calls.setPublic, [['collection']])
        assert.deepEqual(logs, ['https://was.example/space/space-1/docs'])
        assert.match(
          errors[0],
          /Published \(world-readable\): https:\/\/was\.example\/space\/space-1\/docs/
        )
      })

      it('unpublish clears the policy at the path depth', async () => {
        const calls = await setUpStub()
        await makeWasCommand().parseAsync(['unpublish', 'home/docs/vc-1'], {
          from: 'user'
        })
        assert.equal(exitCode, undefined)
        assert.deepEqual(calls.clearPolicy, [['resource']])
        assert.match(errors[0], /Unpublished \(capability-only access\)/)
      })
    })

    describe('space backends', () => {
      it('renders the backends as a table', async () => {
        const calls = await setUpStub({
          backends: [
            {
              id: 'default',
              name: 'Filesystem',
              managedBy: 'server',
              storageMode: ['document', 'blob'],
              persistence: 'durable'
            }
          ]
        })
        await makeWasCommand().parseAsync(['space', 'backends', 'home'], {
          from: 'user'
        })
        assert.equal(exitCode, undefined)
        assert.equal(calls.backends.length, 1)
        const table = logs.join('\n')
        assert.match(table, /default/)
        assert.match(table, /Filesystem/)
        assert.match(table, /document, blob/)
      })

      it('outputs raw JSON with --json', async () => {
        await setUpStub({ backends: [{ id: 'default', managedBy: 'server' }] })
        await makeWasCommand().parseAsync(
          ['space', 'backends', 'home', '--json'],
          { from: 'user' }
        )
        assert.equal(exitCode, undefined)
        const output = JSON.parse(logs.join('\n'))
        assert.deepEqual(output, [{ id: 'default', managedBy: 'server' }])
      })

      it('reports an unsupported (null) backends list as an error', async () => {
        await setUpStub({ backends: null })
        await makeWasCommand().parseAsync(['space', 'backends', 'home'], {
          from: 'user'
        })
        assert.equal(exitCode, 1)
        assert.match(errors[0], /does not support listing backends/)
      })

      it('rejects a collection address', async () => {
        await setUpStub()
        await makeWasCommand().parseAsync(['space', 'backends', 'home/docs'], {
          from: 'user'
        })
        assert.equal(exitCode, 2)
        assert.match(errors[0], /space commands take a space address/)
      })
    })

    describe('space quotas', () => {
      it('renders the quota report as a table', async () => {
        const calls = await setUpStub({
          quotas: {
            respondedAt: '2026-06-13T00:00:00Z',
            backends: [
              {
                id: 'default',
                name: 'Filesystem',
                managedBy: 'server',
                state: 'ok',
                usageBytes: 2048,
                limit: { capacityBytes: 1048576, isUnlimited: false },
                restrictedActions: [],
                measuredAt: '2026-06-13T00:00:00Z'
              }
            ]
          }
        })
        await makeWasCommand().parseAsync(['space', 'quotas', 'home'], {
          from: 'user'
        })
        assert.equal(exitCode, undefined)
        assert.equal(calls.quotas.length, 1)
        const table = logs.join('\n')
        assert.match(table, /default \(Filesystem\)/)
        assert.match(table, /ok/)
        assert.match(table, /2048/)
        assert.match(table, /1048576/)
      })

      it('shows "unlimited" for an unlimited backend', async () => {
        await setUpStub({
          quotas: {
            respondedAt: '2026-06-13T00:00:00Z',
            backends: [
              {
                id: 'default',
                managedBy: 'server',
                state: 'ok',
                usageBytes: 0,
                limit: { isUnlimited: true },
                restrictedActions: [],
                measuredAt: '2026-06-13T00:00:00Z'
              }
            ]
          }
        })
        await makeWasCommand().parseAsync(['space', 'quotas', 'home'], {
          from: 'user'
        })
        assert.equal(exitCode, undefined)
        assert.match(logs.join('\n'), /unlimited/)
      })

      it('outputs the raw report with --json', async () => {
        const report = {
          respondedAt: '2026-06-13T00:00:00Z',
          backends: []
        }
        await setUpStub({ quotas: report })
        await makeWasCommand().parseAsync(
          ['space', 'quotas', 'home', '--json'],
          {
            from: 'user'
          }
        )
        assert.equal(exitCode, undefined)
        assert.deepEqual(JSON.parse(logs.join('\n')), report)
      })

      it('reports an unsupported (null) quota report as an error', async () => {
        await setUpStub({ quotas: null })
        await makeWasCommand().parseAsync(['space', 'quotas', 'home'], {
          from: 'user'
        })
        assert.equal(exitCode, 1)
        assert.match(errors[0], /does not support quota reports/)
      })
    })

    describe('space export/import', () => {
      it('export writes the tar to --output', async () => {
        const calls = await setUpStub({
          exportBytes: new Uint8Array([0x75, 0x73, 0x74, 0x61, 0x72])
        })
        const output = join(walletDir, 'space.tar')
        await makeWasCommand().parseAsync(
          ['space', 'export', 'home', '--output', output],
          { from: 'user' }
        )
        assert.equal(exitCode, undefined)
        assert.equal(calls.exportSpace.length, 1)
        assert.deepEqual(
          await readFile(output),
          Buffer.from([0x75, 0x73, 0x74, 0x61, 0x72])
        )
        assert.match(errors[0], /Wrote 5 bytes to /)
      })

      it('export writes the tar raw to stdout when no --output', async () => {
        const written: Uint8Array[] = []
        mock.method(process.stdout, 'write', (chunk: Uint8Array): boolean => {
          written.push(chunk)
          return true
        })
        await setUpStub({ exportBytes: new Uint8Array([1, 2]) })
        await makeWasCommand().parseAsync(['space', 'export', 'home'], {
          from: 'user'
        })
        assert.equal(exitCode, undefined)
        assert.deepEqual(Buffer.concat(written), Buffer.from([1, 2]))
      })

      it('import sends the tar bytes and prints the stats', async () => {
        const calls = await setUpStub()
        const filePath = join(walletDir, 'space.tar')
        await writeFile(filePath, Buffer.from([9, 8, 7]))
        await makeWasCommand().parseAsync(
          ['space', 'import', 'home', filePath],
          { from: 'user' }
        )
        assert.equal(exitCode, undefined)
        const [tar] = calls.importSpace[0]
        assert.ok(tar instanceof Uint8Array)
        assert.deepEqual(Buffer.from(tar as Uint8Array), Buffer.from([9, 8, 7]))
        const stats = JSON.parse(logs[0])
        assert.equal(stats.collectionsCreated, 1)
        assert.equal(stats.resourcesCreated, 2)
      })

      it('export rejects a collection address', async () => {
        await setUpStub()
        await makeWasCommand().parseAsync(['space', 'export', 'home/docs'], {
          from: 'user'
        })
        assert.equal(exitCode, 2)
        assert.match(errors[0], /space commands take a space address/)
      })
    })
  })
})
