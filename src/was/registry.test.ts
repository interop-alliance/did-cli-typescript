import { describe, it, beforeEach, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, rm } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import {
  listSpaceRecords,
  removeSpaceRecord,
  resolveSpaceRef,
  saveSpaceRecord,
  type SpaceRecord
} from './registry.js'

describe('was space registry', () => {
  let walletDir: string

  beforeEach(async () => {
    walletDir = await mkdtemp(join(tmpdir(), 'did-cli-test-wallet-'))
    process.env.WALLET_DIR = walletDir
  })

  afterEach(async () => {
    delete process.env.WALLET_DIR
    await rm(walletDir, { recursive: true, force: true })
  })

  const record: SpaceRecord = {
    id: '81246131-69a4-45ab-9bff-9c946b59cf2e',
    name: 'Home',
    server: 'https://was.example',
    controller: 'did:key:z6MkExample'
  }

  it('round-trips a space record with metadata', async () => {
    const filePath = await saveSpaceRecord({
      record,
      handle: 'home',
      description: 'Main storage space'
    })
    assert.ok(filePath.includes(join('was-spaces', record.id)))

    const entries = await listSpaceRecords()
    assert.equal(entries.length, 1)
    assert.deepEqual(entries[0].record, record)
    assert.equal(entries[0].meta?.handle, 'home')
    assert.equal(entries[0].meta?.description, 'Main storage space')
    assert.ok(entries[0].meta?.created)
  })

  it('resolves a space by id and by handle', async () => {
    await saveSpaceRecord({ record, handle: 'home' })

    const byId = await resolveSpaceRef({ ref: record.id })
    assert.deepEqual(byId?.record, record)

    const byHandle = await resolveSpaceRef({ ref: 'home' })
    assert.deepEqual(byHandle?.record, record)

    assert.equal(await resolveSpaceRef({ ref: 'nope' }), undefined)
  })

  it('throws when a handle matches more than one space', async () => {
    await saveSpaceRecord({ record, handle: 'home' })
    await saveSpaceRecord({
      record: { ...record, id: 'urn:uuid:other' },
      handle: 'home'
    })
    await assert.rejects(resolveSpaceRef({ ref: 'home' }), /matches 2 spaces/)
  })

  it('sanitizes urn space ids into file names', async () => {
    const urnRecord: SpaceRecord = {
      id: 'urn:uuid:1234',
      server: 'https://was.example'
    }
    const filePath = await saveSpaceRecord({ record: urnRecord })
    assert.ok(filePath.endsWith('urn_uuid_1234.json'))
    const resolved = await resolveSpaceRef({ ref: 'urn:uuid:1234' })
    assert.deepEqual(resolved?.record, urnRecord)
  })

  it('preserves created and merges handle on re-save', async () => {
    await saveSpaceRecord({ record, handle: 'home' })
    const [first] = await listSpaceRecords()
    await saveSpaceRecord({ record: { ...record, name: 'Renamed' } })
    const [second] = await listSpaceRecords()
    assert.equal(second.record.name, 'Renamed')
    assert.equal(second.meta?.created, first.meta?.created)
    assert.equal(second.meta?.handle, 'home')
  })

  it('removes a record and its sidecar', async () => {
    await saveSpaceRecord({ record, handle: 'home' })
    const [entry] = await listSpaceRecords()
    const removed = await removeSpaceRecord({ storageId: entry.storageId })
    assert.equal(removed.length, 2)
    assert.deepEqual(await listSpaceRecords(), [])
  })
})
