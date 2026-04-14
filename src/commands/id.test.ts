import { describe, it, beforeEach, mock } from 'node:test'
import assert from 'node:assert/strict'
import { makeIdCommand } from './id.js'

describe('did id', () => {
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
    for (const method of ['key', 'web', 'webvh']) {
      it(`routes did:${method}`, () => {
        makeIdCommand().parse(['create', method], { from: 'user' })
        assert.ok(logs[0].includes(`did:${method}`))
      })
    }

    it('exits with error for unknown method', () => {
      makeIdCommand().parse(['create', 'unknown'], { from: 'user' })
      assert.equal(exitCode, 1)
      assert.ok(errors[0].includes('unknown'))
    })
  })

  describe('resolve', () => {
    it('routes resolve with default output format', () => {
      makeIdCommand().parse(['resolve', 'did:key:z123'], { from: 'user' })
      assert.ok(logs[0].includes('did:key:z123'))
      assert.ok(logs[0].includes('pretty'))
    })

    it('respects --output flag', () => {
      makeIdCommand().parse(['resolve', 'did:key:z123', '--output', 'json'], { from: 'user' })
      assert.ok(logs[0].includes('json'))
    })
  })

  describe('list', () => {
    it('routes list', () => {
      makeIdCommand().parse(['list'], { from: 'user' })
      assert.ok(logs[0].includes('Listing DIDs'))
    })
  })
})
