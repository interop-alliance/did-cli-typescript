import { describe, it, beforeEach, afterEach, mock } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, readdir, readFile, rm, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { makeKeyCommand } from './key.js'
import { makeDidCommand } from './did.js'

async function storedFingerprints(walletDir: string): Promise<string[]> {
  const keysDir = join(walletDir, 'keys')
  const fileNames = await readdir(keysDir)
  const fingerprints = await Promise.all(
    fileNames
      .filter(name => !name.endsWith('.meta.json'))
      .map(async name => {
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

    it('generates an x25519 key agreement key', async () => {
      await makeKeyCommand().parseAsync(['create', '--type', 'x25519'], {
        from: 'user'
      })
      const parsed = JSON.parse(logs[0])
      assert.equal(parsed.type, 'X25519KeyAgreementKey2020')
      // x25519 public keys carry the z6LS multibase-multicodec prefix
      assert.match(parsed.publicKeyMultibase, /^z6LS/)
      assert.ok(parsed.privateKeyMultibase)
    })

    it('exits with error for x25519 --with-seed', async () => {
      await makeKeyCommand().parseAsync(
        ['create', '--type', 'x25519', '--with-seed'],
        { from: 'user' }
      )
      assert.equal(exitCode, 1)
      assert.ok(errors[0].includes('--with-seed'))
    })

    it('saves an x25519 key with an x25519-tagged filename', async () => {
      const walletDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.WALLET_DIR = walletDir
      try {
        await makeKeyCommand().parseAsync(
          ['create', '--type', 'x25519', '--save'],
          { from: 'user' }
        )
        const filePath = errors[0].slice('Key saved to '.length)
        const filename = filePath.slice(filePath.lastIndexOf('/') + 1)
        // filename format: YYYY-MM-DD-x25519-<publicKeyMultibase>.json
        assert.match(filename, /^\d{4}-\d{2}-\d{2}-x25519-z6LS.*\.json$/)
      } finally {
        await rm(walletDir, { recursive: true })
      }
    })

    it('--save writes a .meta.json sidecar with created/handle/description', async () => {
      const walletDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.WALLET_DIR = walletDir
      try {
        await makeKeyCommand().parseAsync(
          [
            'create',
            '--save',
            '--handle',
            'signing',
            '--description',
            'demo key'
          ],
          { from: 'user' }
        )
        const filePath = errors[0].slice('Key saved to '.length)
        const metaPath = filePath.replace(/\.json$/, '.meta.json')
        const meta = JSON.parse(await readFile(metaPath, 'utf8'))
        assert.match(meta.created, /^\d{4}-\d{2}-\d{2}T/)
        assert.equal(meta.handle, 'signing')
        assert.equal(meta.description, 'demo key')
      } finally {
        await rm(walletDir, { recursive: true })
      }
    })

    it('exits with error for --handle without --save', async () => {
      await makeKeyCommand().parseAsync(['create', '--handle', 'x'], {
        from: 'user'
      })
      assert.equal(exitCode, 1)
      assert.ok(errors[0].includes('--save'))
    })

    it('exits with error for --description without --save', async () => {
      await makeKeyCommand().parseAsync(['create', '--description', 'x'], {
        from: 'user'
      })
      assert.equal(exitCode, 1)
      assert.ok(errors[0].includes('--save'))
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

    it('--plain prints key fingerprints, one per line, sorted', async () => {
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

        await makeKeyCommand().parseAsync(['list', '--plain'], {
          from: 'user'
        })

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

    it('prints a metadata table by default', async () => {
      const walletDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.WALLET_DIR = walletDir
      try {
        await makeKeyCommand().parseAsync(
          ['create', '--save', '--handle', 'signing', '--description', 'demo'],
          { from: 'user' }
        )
        logs.length = 0
        errors.length = 0

        await makeKeyCommand().parseAsync(['list'], { from: 'user' })

        assert.equal(logs.length, 1)
        const [header, separator, row] = logs[0].split('\n')
        assert.match(
          header,
          /^HANDLE\s+TYPE\s+CREATED\s+FINGERPRINT\s+DIDS\s+DESCRIPTION$/
        )
        assert.match(separator, /^-+(\s+-+)+$/)
        assert.match(row, /^signing\s+ed25519\s+\d{4}-\d{2}-\d{2}\s+z6Mk/)
        assert.match(row, /demo$/)
      } finally {
        await rm(walletDir, { recursive: true })
      }
    })

    it('--json outputs an array of objects with metadata', async () => {
      const walletDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.WALLET_DIR = walletDir
      try {
        await makeKeyCommand().parseAsync(
          ['create', '--save', '--handle', 'signing'],
          { from: 'user' }
        )
        logs.length = 0
        errors.length = 0

        await makeKeyCommand().parseAsync(['list', '--json'], { from: 'user' })

        const parsed = JSON.parse(logs[0])
        const expected = await storedFingerprints(walletDir)
        assert.equal(parsed.length, 1)
        assert.equal(parsed[0].fingerprint, expected[0])
        assert.equal(parsed[0].type, 'ed25519')
        assert.equal(parsed[0].handle, 'signing')
        assert.match(parsed[0].created, /^\d{4}-\d{2}-\d{2}T/)
        assert.deepEqual(parsed[0].dids, [])
        assert.ok(parsed[0].storageId)
        assert.equal(parsed[0].description, undefined)
      } finally {
        await rm(walletDir, { recursive: true })
      }
    })

    it('tolerates an orphaned .meta.json sidecar', async () => {
      const walletDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.WALLET_DIR = walletDir
      try {
        await makeKeyCommand().parseAsync(['create', '--save'], {
          from: 'user'
        })
        await writeFile(
          join(walletDir, 'keys', 'orphan.meta.json'),
          JSON.stringify({ handle: 'ghost' }),
          'utf8'
        )
        logs.length = 0
        errors.length = 0

        await makeKeyCommand().parseAsync(['list'], { from: 'user' })

        assert.equal(logs.length, 1)
        assert.ok(!logs[0].includes('ghost'))
      } finally {
        await rm(walletDir, { recursive: true })
      }
    })
  })

  describe('show', () => {
    it('prints the public key object for a stored key', async () => {
      const walletDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.WALLET_DIR = walletDir
      try {
        await makeKeyCommand().parseAsync(['create', '--save'], {
          from: 'user'
        })
        const created = JSON.parse(logs[0])
        logs.length = 0
        errors.length = 0

        await makeKeyCommand().parseAsync(
          ['show', created.publicKeyMultibase],
          { from: 'user' }
        )

        const shown = JSON.parse(logs[0])
        assert.equal(shown.type, 'Multikey')
        assert.equal(shown.publicKeyMultibase, created.publicKeyMultibase)
      } finally {
        await rm(walletDir, { recursive: true })
      }
    })

    it('omits the secret key material', async () => {
      const walletDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.WALLET_DIR = walletDir
      try {
        await makeKeyCommand().parseAsync(['create', '--save'], {
          from: 'user'
        })
        const created = JSON.parse(logs[0])
        assert.ok(created.secretKeyMultibase, 'stored key has a secret half')
        logs.length = 0

        await makeKeyCommand().parseAsync(
          ['show', created.publicKeyMultibase],
          { from: 'user' }
        )

        const shown = JSON.parse(logs[0])
        assert.equal(shown.secretKeyMultibase, undefined)
        assert.ok(!logs[0].includes('secretKeyMultibase'))
      } finally {
        await rm(walletDir, { recursive: true })
      }
    })

    it('shows a stored ecdsa key', async () => {
      const walletDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.WALLET_DIR = walletDir
      try {
        await makeKeyCommand().parseAsync(
          ['create', '--type', 'ecdsa', '--curve', 'p256', '--save'],
          { from: 'user' }
        )
        const created = JSON.parse(logs[0])
        logs.length = 0
        errors.length = 0

        await makeKeyCommand().parseAsync(
          ['show', created.publicKeyMultibase],
          { from: 'user' }
        )

        const shown = JSON.parse(logs[0])
        assert.equal(shown.publicKeyMultibase, created.publicKeyMultibase)
        assert.equal(shown.secretKeyMultibase, undefined)
      } finally {
        await rm(walletDir, { recursive: true })
      }
    })

    it('shows a stored x25519 key without private key material', async () => {
      const walletDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.WALLET_DIR = walletDir
      try {
        await makeKeyCommand().parseAsync(
          ['create', '--type', 'x25519', '--save'],
          { from: 'user' }
        )
        const created = JSON.parse(logs[0])
        logs.length = 0
        errors.length = 0

        await makeKeyCommand().parseAsync(
          ['show', created.publicKeyMultibase],
          { from: 'user' }
        )

        const shown = JSON.parse(logs[0])
        assert.equal(shown.type, 'X25519KeyAgreementKey2020')
        assert.equal(shown.publicKeyMultibase, created.publicKeyMultibase)
        assert.equal(shown.privateKeyMultibase, undefined)
      } finally {
        await rm(walletDir, { recursive: true })
      }
    })

    it('is aliased as view and cat', async () => {
      const walletDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.WALLET_DIR = walletDir
      try {
        await makeKeyCommand().parseAsync(['create', '--save'], {
          from: 'user'
        })
        const fingerprint = JSON.parse(logs[0]).publicKeyMultibase

        for (const verb of ['view', 'cat']) {
          logs.length = 0
          await makeKeyCommand().parseAsync([verb, fingerprint], {
            from: 'user'
          })
          assert.equal(JSON.parse(logs[0]).publicKeyMultibase, fingerprint)
        }
      } finally {
        await rm(walletDir, { recursive: true })
      }
    })

    it('exits with error for an unknown key', async () => {
      const walletDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.WALLET_DIR = walletDir
      try {
        await makeKeyCommand().parseAsync(['show', 'z6MkUnknown'], {
          from: 'user'
        })
        assert.equal(exitCode, 1)
        assert.ok(errors[0].includes('z6MkUnknown'))
      } finally {
        await rm(walletDir, { recursive: true })
      }
    })

    it('looks up a key by handle', async () => {
      const walletDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.WALLET_DIR = walletDir
      try {
        await makeKeyCommand().parseAsync(
          ['create', '--save', '--handle', 'signing'],
          { from: 'user' }
        )
        const fingerprint = JSON.parse(logs[0]).publicKeyMultibase
        logs.length = 0

        await makeKeyCommand().parseAsync(['show', 'signing'], {
          from: 'user'
        })

        assert.equal(JSON.parse(logs[0]).publicKeyMultibase, fingerprint)
      } finally {
        await rm(walletDir, { recursive: true })
      }
    })

    it('exits with error for an ambiguous handle', async () => {
      const walletDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.WALLET_DIR = walletDir
      try {
        for (let i = 0; i < 2; i++) {
          await makeKeyCommand().parseAsync(
            ['create', '--save', '--handle', 'dupe'],
            { from: 'user' }
          )
        }
        logs.length = 0
        errors.length = 0

        await makeKeyCommand().parseAsync(['show', 'dupe'], { from: 'user' })

        assert.equal(exitCode, 1)
        assert.ok(errors[0].includes('dupe'))
        assert.ok(errors[0].includes('2 keys'))
      } finally {
        await rm(walletDir, { recursive: true })
      }
    })

    it('--meta prints a vertical metadata table', async () => {
      const walletDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.WALLET_DIR = walletDir
      try {
        await makeKeyCommand().parseAsync(
          ['create', '--save', '--handle', 'signing', '--description', 'demo'],
          { from: 'user' }
        )
        const fingerprint = JSON.parse(logs[0]).publicKeyMultibase
        logs.length = 0

        await makeKeyCommand().parseAsync(['show', fingerprint, '--meta'], {
          from: 'user'
        })

        const lines = logs[0].split('\n')
        assert.match(lines[0], /^FIELD\s+VALUE$/)
        assert.ok(logs[0].includes(fingerprint))
        assert.match(logs[0], /Handle\s+signing/)
        assert.match(logs[0], /Description\s+demo/)
        assert.match(logs[0], /Type\s+ed25519/)
      } finally {
        await rm(walletDir, { recursive: true })
      }
    })

    it('--meta --json prints the metadata object', async () => {
      const walletDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.WALLET_DIR = walletDir
      try {
        await makeKeyCommand().parseAsync(
          ['create', '--save', '--handle', 'signing'],
          { from: 'user' }
        )
        const fingerprint = JSON.parse(logs[0]).publicKeyMultibase
        logs.length = 0

        await makeKeyCommand().parseAsync(
          ['show', fingerprint, '--meta', '--json'],
          { from: 'user' }
        )

        const parsed = JSON.parse(logs[0])
        assert.equal(parsed.fingerprint, fingerprint)
        assert.equal(parsed.handle, 'signing')
        assert.equal(parsed.type, 'ed25519')
        assert.deepEqual(parsed.dids, [])
      } finally {
        await rm(walletDir, { recursive: true })
      }
    })
  })

  describe('meta', () => {
    it('prints {} for a key without a sidecar', async () => {
      const walletDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.WALLET_DIR = walletDir
      try {
        await makeKeyCommand().parseAsync(['create', '--save'], {
          from: 'user'
        })
        const fingerprint = JSON.parse(logs[0]).publicKeyMultibase
        // Remove the sidecar written by create to simulate a legacy key.
        const filePath = errors[0].slice('Key saved to '.length)
        await rm(filePath.replace(/\.json$/, '.meta.json'))
        logs.length = 0
        errors.length = 0

        await makeKeyCommand().parseAsync(['meta', fingerprint], {
          from: 'user'
        })

        assert.deepEqual(JSON.parse(logs[0]), {})
      } finally {
        await rm(walletDir, { recursive: true })
      }
    })

    it('sets handle and description', async () => {
      const walletDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.WALLET_DIR = walletDir
      try {
        await makeKeyCommand().parseAsync(['create', '--save'], {
          from: 'user'
        })
        const fingerprint = JSON.parse(logs[0]).publicKeyMultibase
        logs.length = 0
        errors.length = 0

        await makeKeyCommand().parseAsync(
          ['meta', fingerprint, '--handle', 'h1', '--description', 'd1'],
          { from: 'user' }
        )

        assert.ok(errors[0].startsWith('Metadata saved to '))
        const saved = JSON.parse(logs[0])
        assert.equal(saved.handle, 'h1')
        assert.equal(saved.description, 'd1')
        assert.match(saved.created, /^\d{4}-\d{2}-\d{2}/)
      } finally {
        await rm(walletDir, { recursive: true })
      }
    })

    it('clears a field with an empty string', async () => {
      const walletDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.WALLET_DIR = walletDir
      try {
        await makeKeyCommand().parseAsync(
          ['create', '--save', '--handle', 'h1'],
          { from: 'user' }
        )
        const fingerprint = JSON.parse(logs[0]).publicKeyMultibase
        logs.length = 0
        errors.length = 0

        await makeKeyCommand().parseAsync(
          ['meta', fingerprint, '--handle', ''],
          { from: 'user' }
        )

        const saved = JSON.parse(logs[0])
        assert.equal(saved.handle, undefined)
      } finally {
        await rm(walletDir, { recursive: true })
      }
    })

    it('backfills created from the storage ID date for legacy keys', async () => {
      const walletDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.WALLET_DIR = walletDir
      try {
        await makeKeyCommand().parseAsync(['create', '--save'], {
          from: 'user'
        })
        const fingerprint = JSON.parse(logs[0]).publicKeyMultibase
        const filePath = errors[0].slice('Key saved to '.length)
        // Remove the sidecar to simulate a key saved before metadata existed.
        await rm(filePath.replace(/\.json$/, '.meta.json'))
        logs.length = 0
        errors.length = 0

        await makeKeyCommand().parseAsync(
          ['meta', fingerprint, '--handle', 'legacy'],
          { from: 'user' }
        )

        const saved = JSON.parse(logs[0])
        // Date-only created, derived from the YYYY-MM-DD filename prefix.
        assert.match(saved.created, /^\d{4}-\d{2}-\d{2}$/)
      } finally {
        await rm(walletDir, { recursive: true })
      }
    })

    it('exits with error for an unknown key', async () => {
      const walletDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.WALLET_DIR = walletDir
      try {
        await makeKeyCommand().parseAsync(['meta', 'z6MkUnknown'], {
          from: 'user'
        })
        assert.equal(exitCode, 1)
        assert.ok(errors[0].includes('z6MkUnknown'))
      } finally {
        await rm(walletDir, { recursive: true })
      }
    })
  })

  describe('remove', () => {
    it('removes the key file and its metadata sidecar', async () => {
      const walletDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.WALLET_DIR = walletDir
      try {
        await makeKeyCommand().parseAsync(
          ['create', '--save', '--handle', 'doomed'],
          { from: 'user' }
        )
        const fingerprint = JSON.parse(logs[0]).publicKeyMultibase
        logs.length = 0
        errors.length = 0

        await makeKeyCommand().parseAsync(['remove', fingerprint], {
          from: 'user'
        })

        assert.equal(exitCode, undefined)
        assert.equal(errors.length, 2)
        assert.ok(errors[0].startsWith('Removed '))
        assert.ok(errors[1].startsWith('Removed '))
        assert.ok(errors[1].endsWith('.meta.json'))
        const remaining = await readdir(join(walletDir, 'keys'))
        assert.deepEqual(remaining, [])
      } finally {
        await rm(walletDir, { recursive: true })
      }
    })

    it('removes a key without a metadata sidecar', async () => {
      const walletDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.WALLET_DIR = walletDir
      try {
        await makeKeyCommand().parseAsync(['create', '--save'], {
          from: 'user'
        })
        const fingerprint = JSON.parse(logs[0]).publicKeyMultibase
        // Remove the sidecar written by create to simulate a legacy key.
        const filePath = errors[0].slice('Key saved to '.length)
        await rm(filePath.replace(/\.json$/, '.meta.json'))
        logs.length = 0
        errors.length = 0

        await makeKeyCommand().parseAsync(['remove', fingerprint], {
          from: 'user'
        })

        assert.equal(exitCode, undefined)
        assert.equal(errors.length, 1)
        const remaining = await readdir(join(walletDir, 'keys'))
        assert.deepEqual(remaining, [])
      } finally {
        await rm(walletDir, { recursive: true })
      }
    })

    it('looks up a key by handle', async () => {
      const walletDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.WALLET_DIR = walletDir
      try {
        await makeKeyCommand().parseAsync(
          ['create', '--save', '--handle', 'doomed'],
          { from: 'user' }
        )
        logs.length = 0
        errors.length = 0

        await makeKeyCommand().parseAsync(['remove', 'doomed'], {
          from: 'user'
        })

        assert.equal(exitCode, undefined)
        const remaining = await readdir(join(walletDir, 'keys'))
        assert.deepEqual(remaining, [])
      } finally {
        await rm(walletDir, { recursive: true })
      }
    })

    it('is aliased as delete and rm', async () => {
      const walletDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.WALLET_DIR = walletDir
      try {
        for (const verb of ['delete', 'rm']) {
          await makeKeyCommand().parseAsync(['create', '--save'], {
            from: 'user'
          })
          const fingerprint = JSON.parse(logs[0]).publicKeyMultibase
          logs.length = 0
          errors.length = 0

          await makeKeyCommand().parseAsync([verb, fingerprint], {
            from: 'user'
          })

          assert.equal(exitCode, undefined, `verb: ${verb}`)
          const remaining = await readdir(join(walletDir, 'keys'))
          assert.deepEqual(remaining, [], `verb: ${verb}`)
        }
      } finally {
        await rm(walletDir, { recursive: true })
      }
    })

    it('exits with error for an unknown key', async () => {
      const walletDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.WALLET_DIR = walletDir
      try {
        await makeKeyCommand().parseAsync(['remove', 'z6MkUnknown'], {
          from: 'user'
        })
        assert.equal(exitCode, 1)
        assert.ok(errors[0].includes('z6MkUnknown'))
      } finally {
        await rm(walletDir, { recursive: true })
      }
    })

    it('exits with error for an ambiguous handle', async () => {
      const walletDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.WALLET_DIR = walletDir
      try {
        for (let i = 0; i < 2; i++) {
          await makeKeyCommand().parseAsync(
            ['create', '--save', '--handle', 'dupe'],
            { from: 'user' }
          )
        }
        logs.length = 0
        errors.length = 0

        await makeKeyCommand().parseAsync(['remove', 'dupe'], { from: 'user' })

        assert.equal(exitCode, 1)
        assert.ok(errors[0].includes('dupe'))
        // Nothing was removed.
        const remaining = await readdir(join(walletDir, 'keys'))
        assert.equal(remaining.length, 4)
      } finally {
        await rm(walletDir, { recursive: true })
      }
    })
  })

  describe('key-to-DID association', () => {
    it('derives the DIDs a stored key participates in', async () => {
      const walletDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      const didsDir = await mkdtemp(join(tmpdir(), 'did-cli-test-dids-'))
      process.env.WALLET_DIR = walletDir
      process.env.DIDS_DIR = didsDir
      // ed25519 keys are seed-deterministic, so the wallet key and the DID's
      // verification key coincide when created from the same seed.
      process.env.SECRET_KEY_SEED =
        'z1AjLxguobDw1Fy3sdaMQxztemkgUQPXXtU6jS9aSf5o7V5'
      try {
        await makeKeyCommand().parseAsync(['create', '--save'], {
          from: 'user'
        })
        const fingerprint = JSON.parse(logs[0]).publicKeyMultibase
        logs.length = 0
        errors.length = 0

        await makeDidCommand().parseAsync(['create', '--save'], {
          from: 'user'
        })
        const did = JSON.parse(logs[0]).id
        logs.length = 0
        errors.length = 0

        // show --meta --json reports the derived association
        await makeKeyCommand().parseAsync(
          ['show', fingerprint, '--meta', '--json'],
          { from: 'user' }
        )
        assert.deepEqual(JSON.parse(logs[0]).dids, [did])
        logs.length = 0

        // list --json reports it as well
        await makeKeyCommand().parseAsync(['list', '--json'], { from: 'user' })
        assert.deepEqual(JSON.parse(logs[0])[0].dids, [did])
        logs.length = 0

        // did create --save also cached the association in the sidecar
        const keysDir = join(walletDir, 'keys')
        const metaName = (await readdir(keysDir)).find(name =>
          name.endsWith('.meta.json')
        ) as string
        const meta = JSON.parse(await readFile(join(keysDir, metaName), 'utf8'))
        assert.deepEqual(meta.dids, [did])
      } finally {
        delete process.env.DIDS_DIR
        delete process.env.SECRET_KEY_SEED
        await rm(walletDir, { recursive: true })
        await rm(didsDir, { recursive: true })
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
