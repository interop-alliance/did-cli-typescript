import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { makeWebvhDriver } from './webvh-driver.js'

describe('makeWebvhDriver', () => {
  it('registers under the webvh DID method', () => {
    assert.equal(makeWebvhDriver().method, 'webvh')
  })

  it('rejects a get() with neither did nor url', async () => {
    // Guards the input before any network fetch.
    await assert.rejects(makeWebvhDriver().get({}), {
      message: 'A DID or a URL is required to resolve.'
    })
  })
})
