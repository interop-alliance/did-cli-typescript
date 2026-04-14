import { describe, it, beforeEach, mock } from 'node:test'
import assert from 'node:assert/strict'
import { makeKeyCommand } from './key.js'

describe('did key', () => {
  let logs: string[]
  let errors: string[]
  let exitCode: number | undefined

  beforeEach(() => {
    logs = []
    errors = []
    exitCode = undefined
    mock.method(console, 'log', (...args: unknown[]) => logs.push(args.join(' ')))
    mock.method(console, 'error', (...args: unknown[]) => errors.push(args.join(' ')))
    mock.method(process, 'exit', (code: number) => { exitCode = code })
  })

  describe('create', () => {
    it('routes ed25519', () => {
      makeKeyCommand().parse(['create', 'ed25519'], { from: 'user' })
      assert.ok(logs[0].includes('Ed25519'))
    })

    it('exits with error for unknown key type', () => {
      makeKeyCommand().parse(['create', 'rsa'], { from: 'user' })
      assert.equal(exitCode, 1)
      assert.ok(errors[0].includes('rsa'))
    })
  })

  describe('list', () => {
    it('routes list', () => {
      makeKeyCommand().parse(['list'], { from: 'user' })
      assert.ok(logs[0].includes('Listing keys'))
    })
  })

  describe('export', () => {
    it('routes export with default format', () => {
      makeKeyCommand().parse(['export', 'key-id-123'], { from: 'user' })
      assert.ok(logs[0].includes('key-id-123'))
      assert.ok(logs[0].includes('jwk'))
    })

    it('respects --format flag', () => {
      makeKeyCommand().parse(['export', 'key-id-123', '--format', 'multibase'], { from: 'user' })
      assert.ok(logs[0].includes('multibase'))
    })
  })
})
