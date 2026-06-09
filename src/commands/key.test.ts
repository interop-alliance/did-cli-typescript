import { describe, it, beforeEach, afterEach, mock } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, readdir, readFile, rm } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { makeKeyCommand } from './key.js'

async function storedFingerprints(walletDir: string): Promise<string[]> {
  const keysDir = join(walletDir, 'keys')
  const fileNames = await readdir(keysDir)
  const fingerprints = await Promise.all(
    fileNames.map(async name => {
      const key = JSON.parse(await readFile(join(keysDir, name), 'utf8'))
      return key.publicKeyMultibase as string
    })
  )
  return fingerprints.sort()
}

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

    it('generates an ecdsa p256 key by default curve', async () => {
      await makeKeyCommand().parseAsync(['create', '--type', 'ecdsa'], {
        from: 'user'
      })
      const parsed = JSON.parse(logs[0])
      assert.equal(parsed.type, 'Multikey')
      // p256 did:key public keys carry the zDna multibase-multikey prefix
      assert.match(parsed.publicKeyMultibase, /^zDna/)
      assert.ok(parsed.secretKeyMultibase)
    })

    it('accepts ecdsa curve aliases (case-insensitive)', async () => {
      for (const curve of ['p384', 'P-384', 'secp384r1']) {
        logs.length = 0
        await makeKeyCommand().parseAsync(
          ['create', '--type', 'ecdsa', '--curve', curve],
          { from: 'user' }
        )
        const parsed = JSON.parse(logs[0])
        // p384 did:key public keys carry the z82L prefix
        assert.match(parsed.publicKeyMultibase, /^z82L/, `curve: ${curve}`)
      }
    })

    it('exits with error for unknown ecdsa curve', async () => {
      await makeKeyCommand().parseAsync(
        ['create', '--type', 'ecdsa', '--curve', 'p999'],
        { from: 'user' }
      )
      assert.equal(exitCode, 1)
      assert.ok(errors[0].includes('p999'))
    })

    it('exits with error for ecdsa --with-seed', async () => {
      await makeKeyCommand().parseAsync(
        ['create', '--type', 'ecdsa', '--with-seed'],
        { from: 'user' }
      )
      assert.equal(exitCode, 1)
      assert.ok(errors[0].includes('--with-seed'))
    })

    it('saves an ecdsa key with a curve-tagged filename', async () => {
      const walletDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.WALLET_DIR = walletDir
      try {
        await makeKeyCommand().parseAsync(
          ['create', '--type', 'ecdsa', '--curve', 'p256', '--save'],
          { from: 'user' }
        )
        const filePath = errors[0].slice('Key saved to '.length)
        const filename = filePath.slice(filePath.lastIndexOf('/') + 1)
        // filename format: YYYY-MM-DD-ecdsa-p256-<publicKeyMultibase>.json
        assert.match(filename, /^\d{4}-\d{2}-\d{2}-ecdsa-p256-zDna.*\.json$/)
      } finally {
        await rm(walletDir, { recursive: true })
      }
    })
  })

  describe('list', () => {
    it('prints nothing when no keys are stored', async () => {
      const walletDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.WALLET_DIR = walletDir
      try {
        await makeKeyCommand().parseAsync(['list'], { from: 'user' })
        assert.equal(logs.length, 0)
      } finally {
        await rm(walletDir, { recursive: true })
      }
    })

    it('prints nothing when the wallet has never been created', async () => {
      const walletDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      await rm(walletDir, { recursive: true })
      process.env.WALLET_DIR = walletDir
      await makeKeyCommand().parseAsync(['list'], { from: 'user' })
      assert.equal(logs.length, 0)
    })

    it('prints key fingerprints, one per line, sorted', async () => {
      const walletDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.WALLET_DIR = walletDir
      try {
        await makeKeyCommand().parseAsync(['create', '--save'], {
          from: 'user'
        })
        await makeKeyCommand().parseAsync(['create', '--save'], {
          from: 'user'
        })
        logs.length = 0
        errors.length = 0

        await makeKeyCommand().parseAsync(['list'], { from: 'user' })

        const expected = await storedFingerprints(walletDir)
        assert.equal(logs.length, 2)
        assert.deepEqual(logs, expected)
        for (const keyId of logs) {
          assert.match(keyId, /^z6Mk/)
        }
      } finally {
        await rm(walletDir, { recursive: true })
      }
    })

    it('--json outputs the key fingerprints as a JSON array', async () => {
      const walletDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.WALLET_DIR = walletDir
      try {
        await makeKeyCommand().parseAsync(['create', '--save'], {
          from: 'user'
        })
        logs.length = 0
        errors.length = 0

        await makeKeyCommand().parseAsync(['list', '--json'], { from: 'user' })

        const parsed = JSON.parse(logs[0])
        const expected = await storedFingerprints(walletDir)
        assert.deepEqual(parsed, expected)
      } finally {
        await rm(walletDir, { recursive: true })
      }
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
