import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import type { IZcap } from '@interop/data-integrity-core/zcap'
import {
  decodeCapability,
  encodeCapability,
  isEncodedCapability
} from './encoding.js'

describe('zcap encoding', () => {
  const rootCapability = {
    '@context': 'https://w3id.org/zcap/v1',
    id: 'urn:zcap:root:https%3A%2F%2Fexample.com%2Fapi',
    controller: 'did:key:z6MkExample',
    invocationTarget: 'https://example.com/api'
  } as IZcap

  it('encodes to a multibase base64url string (leading u)', () => {
    const encoded = encodeCapability(rootCapability)
    assert.match(encoded, /^ueyJ[A-Za-z0-9_-]+$/)
  })

  it('round-trips through encode/decode', () => {
    const encoded = encodeCapability(rootCapability)
    const decoded = decodeCapability(encoded)
    assert.deepEqual(decoded, rootCapability)
  })

  it('encodes a capability larger than base58 allows', () => {
    // A wallet-delegated capability embeds its chain and runs past the
    // 2048-byte input limit of @scure/base's base58.
    const large = {
      ...rootCapability,
      proof: { capabilityChain: [{ padding: 'x'.repeat(3000) }] }
    } as IZcap
    assert.deepEqual(decodeCapability(encodeCapability(large)), large)
  })

  it('rejects the base58btc form (leading z)', () => {
    assert.throws(() => decodeCapability('zAbc'), /multibase/)
  })

  it('rejects a non-multibase string', () => {
    assert.throws(() => decodeCapability('not-multibase'), /multibase/)
  })

  it('tells an encoded value from a urn id or a handle', () => {
    assert.ok(isEncodedCapability(encodeCapability(rootCapability)))
    assert.equal(isEncodedCapability('zAbc'), false)
    assert.equal(isEncodedCapability('urn:zcap:delegated:zSample'), false)
    assert.equal(isEncodedCapability('user-share'), false)
  })
})
