import { describe, it, beforeEach, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { driver } from '@interop/did-method-key'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'
import type { IZcap } from '@interop/was-client'
import { encodeCapability } from '../zcap/encoding.js'
import { saveToDids } from '../storage.js'
import { resolveCapabilityTarget } from './capability.js'

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
 * Builds a minimal delegated-capability object targeting the given URL.
 */
function makeZcap({
  target,
  controller = 'did:key:z6MkDelegatee'
}: {
  target: string
  controller?: string
}): IZcap {
  return {
    '@context': [
      'https://w3id.org/zcap/v1',
      'https://w3id.org/security/suites/ed25519-2020/v1'
    ],
    id: 'urn:zcap:delegated:zSampleCapability',
    controller,
    invocationTarget: target,
    parentCapability: `urn:zcap:root:${encodeURIComponent(target)}`,
    expires: '2027-01-01T00:00:00Z'
  } as IZcap
}

describe('was capability resolution', () => {
  let walletDir: string

  beforeEach(async () => {
    walletDir = await mkdtemp(join(tmpdir(), 'did-cli-test-wallet-'))
    process.env.WALLET_DIR = walletDir
    delete process.env.WAS_DID
  })

  afterEach(async () => {
    delete process.env.WALLET_DIR
    delete process.env.WAS_DID
    await rm(walletDir, { recursive: true, force: true })
  })

  describe('resolveCapabilityTarget', () => {
    it('derives the server, depth, and DID from the capability', async () => {
      const { did } = await saveTestDid()
      const zcap = makeZcap({
        target: 'https://was.example/space/space-1/docs/vc-1',
        controller: did
      })
      const target = await resolveCapabilityTarget({
        ref: encodeCapability(zcap)
      })
      assert.equal(target.server, 'https://was.example')
      assert.equal(target.depth, 'resource')
      assert.equal(target.did, did)
      assert.equal(target.url, 'https://was.example/space/space-1/docs/vc-1')
      assert.deepEqual(target.zcap, zcap)
    })

    it('dispatches collection and space depths', async () => {
      const { did } = await saveTestDid()
      const collectionTarget = await resolveCapabilityTarget({
        ref: encodeCapability(
          makeZcap({
            target: 'https://was.example/space/space-1/docs',
            controller: did
          })
        )
      })
      assert.equal(collectionTarget.depth, 'collection')
      const spaceTarget = await resolveCapabilityTarget({
        ref: encodeCapability(
          makeZcap({
            target: 'https://was.example/space/space-1',
            controller: did
          })
        )
      })
      assert.equal(spaceTarget.depth, 'space')
    })

    it('prefers --did over the capability controller', async () => {
      const { did } = await saveTestDid()
      const zcap = makeZcap({
        target: 'https://was.example/space/space-1',
        controller: 'did:key:z6MkSomeoneElse'
      })
      const target = await resolveCapabilityTarget({
        ref: encodeCapability(zcap),
        did
      })
      assert.equal(target.did, did)
    })

    it('rejects a capability without an invocationTarget', async () => {
      const zcap = { id: 'urn:zcap:delegated:zNoTarget' } as IZcap
      const filePath = join(walletDir, 'broken.json')
      await writeFile(filePath, JSON.stringify(zcap))
      await assert.rejects(
        resolveCapabilityTarget({ ref: filePath }),
        /has no invocationTarget/
      )
    })

    it('rejects a non-WAS invocation target', async () => {
      const { did } = await saveTestDid()
      const zcap = makeZcap({
        target: 'https://was.example/other/thing',
        controller: did
      })
      await assert.rejects(
        resolveCapabilityTarget({ ref: encodeCapability(zcap) }),
        /Cannot derive a handle/
      )
    })
  })
})
