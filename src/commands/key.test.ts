import { describe, it, beforeEach, afterEach, mock } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { makeKeyCommand } from './key.js'

describe('did key', () => {
  let logs: string[]
  let errors: string[]
  let exitCode: number | undefined

  beforeEach(() => {
    logs = []
    errors = []
    exitCode = undefined
    mock.method(console, 'log', (...args: unknown[]) =>
      logs.push(args.join(' '))
    )
    mock.method(console, 'error', (...args: unknown[]) =>
      errors.push(args.join(' '))
    )
    mock.method(process, 'exit', (code: number) => {
      exitCode = code
    })
  })

  afterEach(() => {
    mock.restoreAll()
    delete process.env.WALLET_DIR
  })

  describe('create', () => {
    it('generates an ed25519 key by default', async () => {
      await makeKeyCommand().parseAsync(['create'], { from: 'user' })
      const parsed = JSON.parse(logs[0])
      assert.equal(parsed.type, 'Multikey')
      assert.ok(parsed.publicKeyMultibase)
      assert.ok(parsed.secretKeyMultibase)
    })

    it('exits with error for unknown key type', async () => {
      await makeKeyCommand().parseAsync(['create', '--type', 'rsa'], {
        from: 'user'
      })
      assert.equal(exitCode, 1)
      assert.ok(errors[0].includes('rsa'))
    })

    it('does not print save message without --save', async () => {
      await makeKeyCommand().parseAsync(['create'], { from: 'user' })
      assert.equal(errors.length, 0)
    })

    it('--with-seed wraps output with secretKeySeed and keyPair', async () => {
      await makeKeyCommand().parseAsync(['create', '--with-seed'], {
        from: 'user'
      })
      const parsed = JSON.parse(logs[0])
      assert.ok(parsed.secretKeySeed, 'secretKeySeed should be present')
      assert.match(
        parsed.secretKeySeed,
        /^z1A/,
        'secretKeySeed should be base58btc-encoded'
      )
      assert.equal(parsed.keyPair.type, 'Multikey')
      assert.ok(parsed.keyPair.publicKeyMultibase)
      assert.ok(parsed.keyPair.secretKeyMultibase)
    })

    it('--with-seed uses SECRET_KEY_SEED env var when set', async () => {
      const seed = 'z1AjLxguobDw1Fy3sdaMQxztemkgUQPXXtU6jS9aSf5o7V5'
      process.env.SECRET_KEY_SEED = seed
      try {
        await makeKeyCommand().parseAsync(['create', '--with-seed'], {
          from: 'user'
        })
        const parsed = JSON.parse(logs[0])
        assert.equal(parsed.secretKeySeed, seed)
      } finally {
        delete process.env.SECRET_KEY_SEED
      }
    })

    it('--with-seed produces the same key for the same seed', async () => {
      const seed = 'z1AjLxguobDw1Fy3sdaMQxztemkgUQPXXtU6jS9aSf5o7V5'
      process.env.SECRET_KEY_SEED = seed
      try {
        await makeKeyCommand().parseAsync(['create', '--with-seed'], {
          from: 'user'
        })
        const first = JSON.parse(logs[0])
        logs.length = 0
        await makeKeyCommand().parseAsync(['create', '--with-seed'], {
          from: 'user'
        })
        const second = JSON.parse(logs[0])
        assert.equal(
          first.keyPair.publicKeyMultibase,
          second.keyPair.publicKeyMultibase
        )
      } finally {
        delete process.env.SECRET_KEY_SEED
      }
    })

    it('saves key to wallet with --save', async () => {
      const walletDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.WALLET_DIR = walletDir
      try {
        await makeKeyCommand().parseAsync(['create', '--save'], {
          from: 'user'
        })

        // stderr reports the saved path
        assert.equal(errors.length, 1)
        assert.ok(errors[0].startsWith('Key saved to '))
        const filePath = errors[0].slice('Key saved to '.length)
        assert.ok(filePath.startsWith(join(walletDir, 'keys')))

        // file exists and contains valid key JSON
        const content = JSON.parse(await readFile(filePath, 'utf8'))
        assert.equal(content.type, 'Multikey')
        assert.ok(content.publicKeyMultibase)
        assert.ok(content.secretKeyMultibase)

        // filename format: YYYY-MM-DD-ed25519-<publicKeyMultibase>.json
        const filename = filePath.slice(filePath.lastIndexOf('/') + 1)
        assert.match(filename, /^\d{4}-\d{2}-\d{2}-ed25519-z6Mk.*\.json$/)

        // stdout still outputs the key JSON
        const stdoutParsed = JSON.parse(logs[0])
        assert.deepEqual(stdoutParsed, content)
      } finally {
        await rm(walletDir, { recursive: true })
      }
    })
  })

  describe('list', () => {
    it('routes list', () => {
      makeKeyCommand().parse(['list'], { from: 'user' })
      assert.ok(errors[0].includes('Listing keys'))
    })
  })

  describe('export', () => {
    it('routes export with default format', () => {
      makeKeyCommand().parse(['export', 'key-id-123'], { from: 'user' })
      assert.ok(errors[0].includes('key-id-123'))
      assert.ok(errors[0].includes('jwk'))
    })

    it('respects --format flag', () => {
      makeKeyCommand().parse(
        ['export', 'key-id-123', '--format', 'multibase'],
        { from: 'user' }
      )
      assert.ok(errors[0].includes('multibase'))
    })
  })
})
