import { describe, it, beforeEach, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, rm } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { driver } from '@interop/did-method-key'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'
import { saveDidMeta, saveToDids } from '../storage.js'
import { buildWasClient, loadWasSigner, resolveWasTarget } from './client.js'
import { saveSpaceRecord } from './registry.js'

/**
 * Generates a did:key DID with an Ed25519 key and saves its document and
 * keys file to the (temp) local DID storage, the way `did create --save`
 * does.
 */
async function saveTestDid({ handle }: { handle?: string } = {}): Promise<{
  did: string
}> {
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
  if (handle) {
    await saveDidMeta({ did, meta: { handle } })
  }
  return { did }
}

describe('was client factory', () => {
  let walletDir: string

  beforeEach(async () => {
    walletDir = await mkdtemp(join(tmpdir(), 'did-cli-test-wallet-'))
    process.env.WALLET_DIR = walletDir
    delete process.env.WAS_SERVER_URL
    delete process.env.WAS_DID
  })

  afterEach(async () => {
    delete process.env.WALLET_DIR
    delete process.env.WAS_SERVER_URL
    delete process.env.WAS_DID
    await rm(walletDir, { recursive: true, force: true })
  })

  describe('loadWasSigner', () => {
    it('loads a signer from a stored did:key DID', async () => {
      const { did } = await saveTestDid()
      const { did: resolved, signer } = await loadWasSigner({ did })
      assert.equal(resolved, did)
      assert.ok(signer.id?.startsWith(`${did}#`))
    })

    it('resolves a stored DID by handle', async () => {
      const { did } = await saveTestDid({ handle: 'signing' })
      const { did: resolved } = await loadWasSigner({ did: 'signing' })
      assert.equal(resolved, did)
    })

    it('rejects a non-did:key DID', async () => {
      await assert.rejects(
        loadWasSigner({ did: 'did:web:example.com' }),
        /supports only did:key/
      )
    })

    it('rejects a non-Ed25519 key', async () => {
      const did = 'did:key:zDnaeExample'
      await saveToDids({ method: 'key', did, data: { id: did } })
      await saveToDids({
        method: 'key',
        did,
        suffix: 'keys',
        data: {
          id: `${did}#zDnaeExample`,
          type: 'Multikey',
          publicKeyMultibase: 'zDnaeExample'
        }
      })
      await assert.rejects(loadWasSigner({ did }), /only Ed25519 keys/)
    })

    it('rejects an unknown handle', async () => {
      await assert.rejects(
        loadWasSigner({ did: 'nope' }),
        /No locally stored DID found/
      )
    })

    it('rejects a did:key DID that is not in local storage', async () => {
      await assert.rejects(
        loadWasSigner({ did: 'did:key:z6MkMissing' }),
        /not in local storage/
      )
    })
  })

  describe('buildWasClient', () => {
    it('requires a server URL', async () => {
      await assert.rejects(buildWasClient({}), /No WAS server URL/)
    })

    it('requires a signing DID', async () => {
      await assert.rejects(
        buildWasClient({ server: 'https://was.example' }),
        /No signing DID/
      )
    })

    it('builds a client from explicit flags', async () => {
      const { did } = await saveTestDid()
      const {
        client,
        server,
        did: resolved
      } = await buildWasClient({
        server: 'https://was.example',
        did
      })
      assert.equal(server, 'https://was.example')
      assert.equal(resolved, did)
      assert.equal(client.serverUrl, 'https://was.example')
      assert.equal(client.controllerDid, did)
    })

    it('falls back to WAS_SERVER_URL and WAS_DID', async () => {
      const { did } = await saveTestDid()
      process.env.WAS_SERVER_URL = 'https://env.example'
      process.env.WAS_DID = did
      const { client } = await buildWasClient()
      assert.equal(client.serverUrl, 'https://env.example')
      assert.equal(client.controllerDid, did)
    })
  })

  describe('resolveWasTarget', () => {
    it('resolves server and DID from a registry entry by handle', async () => {
      const { did } = await saveTestDid()
      await saveSpaceRecord({
        record: {
          id: 'urn:uuid:1234',
          server: 'https://was.example',
          controller: did
        },
        handle: 'home'
      })
      const target = await resolveWasTarget({
        address: 'home/credentials/vc-1'
      })
      assert.equal(target.spaceId, 'urn:uuid:1234')
      assert.equal(target.collectionId, 'credentials')
      assert.equal(target.resourceId, 'vc-1')
      assert.equal(target.server, 'https://was.example')
      assert.equal(target.did, did)
      assert.equal(target.entry?.meta?.handle, 'home')
      assert.equal(target.client.serverUrl, 'https://was.example')
    })

    it('takes the server from a full space URL address', async () => {
      const { did } = await saveTestDid()
      const target = await resolveWasTarget({
        address: 'https://other.example/space/abc/docs',
        did
      })
      assert.equal(target.server, 'https://other.example')
      assert.equal(target.spaceId, 'abc')
      assert.equal(target.collectionId, 'docs')
      assert.equal(target.entry, undefined)
    })

    it('requires a server URL for an unregistered bare space id', async () => {
      const { did } = await saveTestDid()
      await assert.rejects(
        resolveWasTarget({ address: 'abc/docs', did }),
        /No WAS server URL/
      )
    })

    it('requires a signing DID when none is recorded', async () => {
      await assert.rejects(
        resolveWasTarget({
          address: 'abc/docs',
          server: 'https://was.example'
        }),
        /No signing DID/
      )
    })
  })
})
