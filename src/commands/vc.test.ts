import { describe, it, beforeEach, afterEach, mock } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { Readable } from 'node:stream'
import { runVerify } from './vc.js'

describe('did vc verify', () => {
  let logs: string[]
  let errors: string[]

  beforeEach(() => {
    logs = []
    errors = []
    mock.method(console, 'log', (...args: unknown[]) =>
      logs.push(args.join(' '))
    )
    mock.method(console, 'error', (...args: unknown[]) =>
      errors.push(args.join(' '))
    )
  })

  afterEach(() => {
    mock.restoreAll()
  })

  it('returns exit code 2 on malformed JSON from a file', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'did-cli-vc-test-'))
    const file = join(dir, 'bad.json')
    await writeFile(file, 'not json', 'utf8')
    try {
      const code = await runVerify(file, {})
      assert.equal(code, 2)
      assert.ok(errors[0].startsWith('Could not read credential:'))
      assert.equal(logs.length, 0)
    } finally {
      await rm(dir, { recursive: true })
    }
  })

  it('returns exit code 2 when the file does not exist', async () => {
    const code = await runVerify(join(tmpdir(), 'does-not-exist-xyz.json'), {})
    assert.equal(code, 2)
    assert.ok(errors[0].startsWith('Could not read credential:'))
  })

  it('returns exit code 2 on malformed JSON from stdin', async () => {
    const originalStdin = process.stdin
    const fake = Readable.from([Buffer.from('not json')])
    Object.defineProperty(process, 'stdin', {
      value: fake,
      configurable: true
    })
    try {
      const code = await runVerify(undefined, {})
      assert.equal(code, 2)
      assert.ok(errors[0].startsWith('Could not read credential:'))
    } finally {
      Object.defineProperty(process, 'stdin', {
        value: originalStdin,
        configurable: true
      })
    }
  })
})
