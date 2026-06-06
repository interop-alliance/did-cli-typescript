import { describe, it, beforeEach, mock } from 'node:test'
import assert from 'node:assert/strict'
import { makeZcapCommand } from './zcap.js'

describe('did zcap', () => {
  let logs: string[]

  beforeEach(() => {
    logs = []
    mock.method(console, 'log', (...args: unknown[]) =>
      logs.push(args.join(' '))
    )
  })

  it('routes create', () => {
    makeZcapCommand().parse(['create'], { from: 'user' })
    assert.ok(logs[0].includes('Creating zcap'))
  })

  it('routes delegate', () => {
    makeZcapCommand().parse(['delegate'], { from: 'user' })
    assert.ok(logs[0].includes('Delegating zcap'))
  })

  it('routes list', () => {
    makeZcapCommand().parse(['list'], { from: 'user' })
    assert.ok(logs[0].includes('Listing zcaps'))
  })

  it('routes revoke', () => {
    makeZcapCommand().parse(['revoke', 'zcap-id-123'], { from: 'user' })
    assert.ok(logs[0].includes('zcap-id-123'))
  })
})
