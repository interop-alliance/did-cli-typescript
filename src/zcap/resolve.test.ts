import { describe, it, beforeEach, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import type { IZcap } from '@interop/data-integrity-core/zcap'
import { saveMetaToCollection, saveToCollection } from '../storage.js'
import { encodeCapability } from './encoding.js'
import { resolveCapabilityInput } from './resolve.js'

/**
 * A minimal delegated-capability object for resolution round-trips.
 */
const zcap = {
  '@context': [
    'https://w3id.org/zcap/v1',
    'https://w3id.org/security/suites/ed25519-2020/v1'
  ],
  id: 'urn:zcap:delegated:zSampleCapability',
  controller: 'did:key:z6MkDelegatee',
  invocationTarget: 'https://was.example/space/space-1/docs',
  parentCapability:
    'urn:zcap:root:https%3A%2F%2Fwas.example%2Fspace%2Fspace-1%2Fdocs',
  expires: '2027-01-01T00:00:00Z'
} as IZcap

describe('resolveCapabilityInput', () => {
  let walletDir: string

  beforeEach(async () => {
    walletDir = await mkdtemp(join(tmpdir(), 'did-cli-test-wallet-'))
    process.env.WALLET_DIR = walletDir
  })

  afterEach(async () => {
    delete process.env.WALLET_DIR
    await rm(walletDir, { recursive: true, force: true })
  })

  it('decodes a multibase-encoded capability string', async () => {
    const resolved = await resolveCapabilityInput({
      ref: encodeCapability(zcap)
    })
    assert.deepEqual(resolved, zcap)
  })

  it('reads a capability JSON file', async () => {
    const filePath = join(walletDir, 'share.json')
    await writeFile(filePath, JSON.stringify(zcap))
    const resolved = await resolveCapabilityInput({ ref: filePath })
    assert.deepEqual(resolved, zcap)
  })

  it('rejects a file that is not capability JSON', async () => {
    const filePath = join(walletDir, 'share.json')
    await writeFile(filePath, 'not json')
    await assert.rejects(
      resolveCapabilityInput({ ref: filePath }),
      /does not contain capability JSON/
    )
  })

  it('resolves a stored zcap by metadata handle', async () => {
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
    const resolved = await resolveCapabilityInput({ ref: 'bob-share' })
    assert.deepEqual(resolved, zcap)
  })

  it('resolves a stored zcap by capability id', async () => {
    await saveToCollection({
      collection: 'zcaps',
      storageId: 'stored-share',
      data: zcap
    })
    const resolved = await resolveCapabilityInput({
      ref: 'urn:zcap:delegated:zSampleCapability'
    })
    assert.deepEqual(resolved, zcap)
  })

  it('rejects an unknown reference', async () => {
    await assert.rejects(
      resolveCapabilityInput({ ref: 'nope' }),
      /No capability found for "nope"/
    )
  })
})
