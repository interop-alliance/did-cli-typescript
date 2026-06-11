import { describe, it, beforeEach, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, rm } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import {
  findStoredKey,
  listCollection,
  listDids,
  loadDidMeta,
  loadMetaFromCollection,
  saveDidMeta,
  saveMetaToCollection,
  saveToCollection,
  saveToDids
} from './storage.js'

describe('storage', () => {
  let walletDir: string
  let didsDir: string

  beforeEach(async () => {
    walletDir = await mkdtemp(join(tmpdir(), 'did-cli-test-wallet-'))
    didsDir = await mkdtemp(join(tmpdir(), 'did-cli-test-dids-'))
    process.env.WALLET_DIR = walletDir
    process.env.DIDS_DIR = didsDir
  })

  afterEach(async () => {
    delete process.env.WALLET_DIR
    delete process.env.DIDS_DIR
    await rm(walletDir, { recursive: true, force: true })
    await rm(didsDir, { recursive: true, force: true })
  })

  describe('collection metadata sidecars', () => {
    it('round-trips metadata for a collection item', async () => {
      const meta = {
        created: '2026-06-10T00:00:00.000Z',
        handle: 'signing',
        description: 'A signing key',
        dids: ['did:key:z6MkExample']
      }
      const filePath = await saveMetaToCollection({
        collection: 'keys',
        storageId: 'some-key',
        meta
      })
      assert.ok(filePath.endsWith('some-key.meta.json'))
      const loaded = await loadMetaFromCollection({
        collection: 'keys',
        storageId: 'some-key'
      })
      assert.deepEqual(loaded, meta)
    })

    it('returns undefined when no sidecar exists', async () => {
      const loaded = await loadMetaFromCollection({
        collection: 'keys',
        storageId: 'missing'
      })
      assert.equal(loaded, undefined)
    })

    it('listCollection excludes .meta.json sidecars', async () => {
      await saveToCollection('keys', 'some-key', { type: 'Multikey' })
      await saveMetaToCollection({
        collection: 'keys',
        storageId: 'some-key',
        meta: { handle: 'signing' }
      })
      assert.deepEqual(await listCollection('keys'), ['some-key'])
    })
  })

  describe('DID metadata sidecars', () => {
    const did = 'did:key:z6MkExample'

    it('round-trips metadata for a DID', async () => {
      const meta = {
        created: '2026-06-10T00:00:00.000Z',
        handle: 'demo-issuer',
        description: 'Issuer DID for the demo'
      }
      const filePath = await saveDidMeta({ did, meta })
      assert.ok(filePath.endsWith(`${did}.meta.json`))
      assert.deepEqual(await loadDidMeta({ did }), meta)
    })

    it('returns undefined when no sidecar exists', async () => {
      assert.equal(await loadDidMeta({ did }), undefined)
    })

    it('listDids excludes .meta.json and .keys.json sidecars', async () => {
      await saveToDids({ method: 'key', did, data: { id: did } })
      await saveToDids({ method: 'key', did, suffix: 'keys', data: {} })
      await saveDidMeta({ did, meta: { handle: 'demo' } })
      assert.deepEqual(await listDids(), [did])
    })
  })

  describe('findStoredKey', () => {
    it('finds a stored key by fingerprint', async () => {
      await saveToCollection('keys', 'key-a', {
        publicKeyMultibase: 'z6MkAaa'
      })
      await saveToCollection('keys', 'key-b', {
        publicKeyMultibase: 'z6MkBbb'
      })
      const found = await findStoredKey({ fingerprint: 'z6MkBbb' })
      assert.equal(found?.storageId, 'key-b')
      assert.equal(found?.key.publicKeyMultibase, 'z6MkBbb')
    })

    it('returns undefined for an unknown fingerprint', async () => {
      assert.equal(await findStoredKey({ fingerprint: 'z6MkNope' }), undefined)
    })
  })
})
