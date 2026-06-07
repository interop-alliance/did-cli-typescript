import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { expiresFromTtl } from './ttl.js'

describe('expiresFromTtl', () => {
  it('parses days', () => {
    const before = Date.now()
    const expires = expiresFromTtl('30d').getTime()
    const expected = before + 30 * 24 * 60 * 60 * 1000
    // allow a small delta for execution time
    assert.ok(Math.abs(expires - expected) < 5000)
  })

  it('parses each supported unit', () => {
    for (const ttl of ['30s', '15m', '24h', '7d', '2w', '1y']) {
      assert.ok(expiresFromTtl(ttl).getTime() > Date.now())
    }
  })

  it('treats y as 365 days', () => {
    const now = Date.now()
    const year = expiresFromTtl('1y').getTime() - now
    assert.ok(Math.abs(year - 365 * 24 * 60 * 60 * 1000) < 5000)
  })

  it('throws on a malformed value', () => {
    for (const bad of ['', 'abc', '10', 'd', '1mo', '-1d', '1.5d']) {
      assert.throws(() => expiresFromTtl(bad), /Invalid --ttl/)
    }
  })
})
