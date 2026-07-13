/**
 * Unit tests for `tokenizeShellLine`: whitespace splitting, single/double
 * quoting, backslash escapes, and the unterminated-quote error.
 */
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { tokenizeShellLine } from './tokenize.js'

describe('tokenizeShellLine', () => {
  it('splits on runs of whitespace', () => {
    assert.deepEqual(tokenizeShellLine('get  demo/did/did.jsonl'), [
      'get',
      'demo/did/did.jsonl'
    ])
  })

  it('returns an empty array for a blank line', () => {
    assert.deepEqual(tokenizeShellLine('   '), [])
  })

  it('keeps whitespace inside double quotes', () => {
    assert.deepEqual(tokenizeShellLine('space create --name "My Space"'), [
      'space',
      'create',
      '--name',
      'My Space'
    ])
  })

  it('keeps whitespace inside single quotes', () => {
    assert.deepEqual(tokenizeShellLine("put a/b 'hello world'"), [
      'put',
      'a/b',
      'hello world'
    ])
  })

  it('treats backslash inside single quotes as literal', () => {
    assert.deepEqual(tokenizeShellLine("put x 'a\\b'"), ['put', 'x', 'a\\b'])
  })

  it('escapes the next character with a backslash inside double quotes', () => {
    assert.deepEqual(tokenizeShellLine('put x "a\\"b"'), ['put', 'x', 'a"b'])
  })

  it('escapes a space with a bare backslash', () => {
    assert.deepEqual(tokenizeShellLine('put my\\ file'), ['put', 'my file'])
  })

  it('produces an empty token for empty quotes', () => {
    assert.deepEqual(tokenizeShellLine('put x ""'), ['put', 'x', ''])
  })

  it('throws on an unterminated quote', () => {
    assert.throws(() => tokenizeShellLine('put "oops'), /Unterminated quote/)
    assert.throws(() => tokenizeShellLine("put 'oops"), /Unterminated quote/)
  })
})
