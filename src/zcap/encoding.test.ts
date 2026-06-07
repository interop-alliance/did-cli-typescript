import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import type { IZcap } from '@interop/data-integrity-core/zcap'
import { decodeCapability, encodeCapability } from './encoding.js'

describe('zcap encoding', () => {
  const rootCapability = {
    '@context': 'https://w3id.org/zcap/v1',
    id: 'urn:zcap:root:https%3A%2F%2Fexample.com%2Fapi',
    controller: 'did:key:z6MkExample',
    invocationTarget: 'https://example.com/api'
  } as IZcap

  it('encodes to a multibase base58btc string (leading z)', () => {
    const encoded = encodeCapability(rootCapability)
    assert.ok(encoded.startsWith('z'))
  })

  it('round-trips through encode/decode', () => {
    const encoded = encodeCapability(rootCapability)
    const decoded = decodeCapability(encoded)
    assert.deepEqual(decoded, rootCapability)
  })

  it('rejects a non-multibase string', () => {
    assert.throws(() => decodeCapability('not-multibase'), /multibase/)
  })
})
