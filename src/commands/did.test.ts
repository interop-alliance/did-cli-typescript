import { describe, it, beforeEach, afterEach, mock } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, readdir, readFile, rm } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { makeDidCommand } from './did.js'

async function storedDids(didsDir: string): Promise<string[]> {
  const methodEntries = await readdir(didsDir, { withFileTypes: true })
  const dids: string[] = []
  for (const methodEntry of methodEntries) {
    if (!methodEntry.isDirectory()) {
      continue
    }
    const fileNames = await readdir(join(didsDir, methodEntry.name))
    for (const fileName of fileNames) {
      if (!fileName.endsWith('.json') || fileName.endsWith('.keys.json')) {
        continue
      }
      dids.push(fileName.slice(0, -'.json'.length))
    }
  }
  return dids.sort()
}

describe('di did', () => {
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
    delete process.env.DIDS_DIR
    delete process.env.SECRET_KEY_SEED
  })

  describe('create', () => {
    it('defaults to did:key when no method is given', async () => {
      await makeDidCommand().parseAsync(['create'], { from: 'user' })
      const parsed = JSON.parse(logs[0])
      assert.ok(
        parsed.id.startsWith('did:key:'),
        `expected did:key: prefix, got: ${parsed.id}`
      )
    })

    it('creates a did:key with explicit method arg', async () => {
      await makeDidCommand().parseAsync(['create', 'key'], { from: 'user' })
      const parsed = JSON.parse(logs[0])
      assert.ok(parsed.id.startsWith('did:key:'))
    })

    it('output includes id and didDocument with matching id', async () => {
      await makeDidCommand().parseAsync(['create'], { from: 'user' })
      const parsed = JSON.parse(logs[0])
      assert.ok(parsed.id)
      assert.ok(parsed.didDocument)
      assert.equal(parsed.didDocument.id, parsed.id)
    })

    it('does not include secretKeySeed by default', async () => {
      await makeDidCommand().parseAsync(['create'], { from: 'user' })
      const parsed = JSON.parse(logs[0])
      assert.equal(parsed.secretKeySeed, undefined)
    })

    it('--with-seed includes secretKeySeed in output', async () => {
      await makeDidCommand().parseAsync(['create', '--with-seed'], {
        from: 'user'
      })
      const parsed = JSON.parse(logs[0])
      assert.ok(parsed.secretKeySeed)
      assert.match(
        parsed.secretKeySeed,
        /^z/,
        'secretKeySeed should be base58btc-encoded'
      )
    })

    it('--with-seed uses SECRET_KEY_SEED env var when set', async () => {
      const seed = 'z1AjLxguobDw1Fy3sdaMQxztemkgUQPXXtU6jS9aSf5o7V5'
      process.env.SECRET_KEY_SEED = seed
      await makeDidCommand().parseAsync(['create', '--with-seed'], {
        from: 'user'
      })
      const parsed = JSON.parse(logs[0])
      assert.equal(parsed.secretKeySeed, seed)
    })

    it('--with-seed produces the same DID for the same seed', async () => {
      process.env.SECRET_KEY_SEED =
        'z1AjLxguobDw1Fy3sdaMQxztemkgUQPXXtU6jS9aSf5o7V5'
      await makeDidCommand().parseAsync(['create', '--with-seed'], {
        from: 'user'
      })
      const first = JSON.parse(logs[0])
      logs.length = 0
      await makeDidCommand().parseAsync(['create', '--with-seed'], {
        from: 'user'
      })
      const second = JSON.parse(logs[0])
      assert.equal(first.id, second.id)
    })

    it('--save writes DID document and keys to DIDS_DIR', async () => {
      const didsDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.DIDS_DIR = didsDir
      try {
        await makeDidCommand().parseAsync(['create', '--save'], {
          from: 'user'
        })

        assert.equal(errors.length, 1)
        assert.ok(errors[0].startsWith('DID saved to '))
        const docPath = errors[0].slice('DID saved to '.length)
        assert.ok(docPath.startsWith(join(didsDir, 'key')))

        const stdout = JSON.parse(logs[0])
        const docContent = JSON.parse(await readFile(docPath, 'utf8'))
        assert.equal(docContent.id, stdout.id)

        const keysPath = docPath.replace('.json', '.keys.json')
        const keysContent = JSON.parse(await readFile(keysPath, 'utf8'))
        assert.ok(keysContent.publicKeyMultibase)
        assert.ok(keysContent.secretKeyMultibase)
      } finally {
        await rm(didsDir, { recursive: true })
      }
    })

    it('creates an ecdsa did:key (p256 default curve)', async () => {
      await makeDidCommand().parseAsync(['create', 'key', '--type', 'ecdsa'], {
        from: 'user'
      })
      const parsed = JSON.parse(logs[0])
      // p256 did:key identifiers carry the zDna multibase-multikey prefix
      assert.ok(parsed.id.startsWith('did:key:zDna'), parsed.id)
      assert.equal(parsed.didDocument.id, parsed.id)
    })

    it('creates an ecdsa did:key with an explicit curve', async () => {
      await makeDidCommand().parseAsync(
        ['create', 'key', '--type', 'ecdsa', '--curve', 'secp521r1'],
        { from: 'user' }
      )
      const parsed = JSON.parse(logs[0])
      // p521 did:key identifiers carry the z2J9 multibase-multikey prefix
      assert.ok(parsed.id.startsWith('did:key:z2J9'), parsed.id)
    })

    it('exits with error for ecdsa --with-seed', async () => {
      await makeDidCommand().parseAsync(
        ['create', 'key', '--type', 'ecdsa', '--with-seed'],
        { from: 'user' }
      )
      assert.equal(exitCode, 1)
      assert.ok(errors[0].includes('--with-seed'))
    })

    it('exits with error for unknown ecdsa curve', async () => {
      await makeDidCommand().parseAsync(
        ['create', 'key', '--type', 'ecdsa', '--curve', 'p999'],
        { from: 'user' }
      )
      assert.equal(exitCode, 1)
      assert.ok(errors[0].includes('p999'))
    })

    it('saves an ecdsa did:key with its key file', async () => {
      const didsDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.DIDS_DIR = didsDir
      try {
        await makeDidCommand().parseAsync(
          ['create', 'key', '--type', 'ecdsa', '--save'],
          { from: 'user' }
        )
        const docPath = errors[0].slice('DID saved to '.length)
        const keysPath = docPath.replace('.json', '.keys.json')
        const keysContent = JSON.parse(await readFile(keysPath, 'utf8'))
        assert.equal(keysContent.type, 'Multikey')
        assert.match(keysContent.publicKeyMultibase, /^zDna/)
        assert.ok(keysContent.secretKeyMultibase)
      } finally {
        await rm(didsDir, { recursive: true })
      }
    })

    it('creates an ecdsa did:web from --url', async () => {
      await makeDidCommand().parseAsync(
        ['create', 'web', '--type', 'ecdsa', '--url', 'https://example.com'],
        { from: 'user' }
      )
      const parsed = JSON.parse(logs[0])
      assert.equal(parsed.id, 'did:web:example.com')
      const vm = parsed.didDocument.verificationMethod[0]
      assert.equal(vm.type, 'Multikey')
      // p256 verification methods carry the zDna multibase-multikey prefix
      assert.match(vm.publicKeyMultibase, /^zDna/)
    })

    it('did:web ecdsa rejects --with-seed', async () => {
      await makeDidCommand().parseAsync(
        [
          'create',
          'web',
          '--type',
          'ecdsa',
          '--url',
          'https://example.com',
          '--with-seed'
        ],
        { from: 'user' }
      )
      assert.equal(exitCode, 1)
      assert.ok(errors[0].includes('--with-seed'))
    })

    it('creates a did:web from --url', async () => {
      await makeDidCommand().parseAsync(
        ['create', 'web', '--url', 'https://example.com'],
        { from: 'user' }
      )
      const parsed = JSON.parse(logs[0])
      assert.equal(parsed.id, 'did:web:example.com')
      assert.equal(parsed.didDocument.id, 'did:web:example.com')
    })

    it('exits with error when did:web is missing --url', async () => {
      await makeDidCommand().parseAsync(['create', 'web'], { from: 'user' })
      assert.equal(exitCode, 1)
      assert.ok(errors[0].includes('did:web requires --url'))
    })

    it('routes did:webvh (not yet implemented)', async () => {
      await makeDidCommand().parseAsync(['create', 'webvh'], { from: 'user' })
      assert.ok(logs[0].includes('did:webvh'))
    })

    it('exits with error for unknown method', async () => {
      await makeDidCommand().parseAsync(['create', 'unknown'], { from: 'user' })
      assert.equal(exitCode, 1)
      assert.ok(errors[0].includes('unknown'))
    })
  })

  describe('resolve', () => {
    it('routes resolve with default output format', () => {
      makeDidCommand().parse(['resolve', 'did:key:z123'], { from: 'user' })
      assert.ok(logs[0].includes('did:key:z123'))
      assert.ok(logs[0].includes('pretty'))
    })

    it('respects --output flag', () => {
      makeDidCommand().parse(['resolve', 'did:key:z123', '--output', 'json'], {
        from: 'user'
      })
      assert.ok(logs[0].includes('json'))
    })
  })

  describe('list', () => {
    it('prints nothing when no DIDs are stored', async () => {
      const didsDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.DIDS_DIR = didsDir
      try {
        await makeDidCommand().parseAsync(['list'], { from: 'user' })
        assert.equal(logs.length, 0)
      } finally {
        await rm(didsDir, { recursive: true })
      }
    })

    it('prints nothing when DID storage has never been created', async () => {
      const didsDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      await rm(didsDir, { recursive: true })
      process.env.DIDS_DIR = didsDir
      await makeDidCommand().parseAsync(['list'], { from: 'user' })
      assert.equal(logs.length, 0)
    })

    it('prints stored DIDs, one per line, sorted', async () => {
      const didsDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.DIDS_DIR = didsDir
      try {
        await makeDidCommand().parseAsync(['create', '--save'], {
          from: 'user'
        })
        await makeDidCommand().parseAsync(['create', '--save'], {
          from: 'user'
        })
        logs.length = 0
        errors.length = 0

        await makeDidCommand().parseAsync(['list'], { from: 'user' })

        const expected = await storedDids(didsDir)
        assert.equal(logs.length, 2)
        assert.deepEqual(logs, expected)
        for (const did of logs) {
          assert.match(did, /^did:key:z6Mk/)
        }
      } finally {
        await rm(didsDir, { recursive: true })
      }
    })

    it('omits the .keys.json sidecar files', async () => {
      const didsDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.DIDS_DIR = didsDir
      try {
        await makeDidCommand().parseAsync(['create', '--save'], {
          from: 'user'
        })
        logs.length = 0
        errors.length = 0

        await makeDidCommand().parseAsync(['list'], { from: 'user' })

        assert.equal(logs.length, 1)
        assert.ok(!logs[0].includes('.keys'))
      } finally {
        await rm(didsDir, { recursive: true })
      }
    })

    it('--json outputs the DIDs as a JSON array', async () => {
      const didsDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.DIDS_DIR = didsDir
      try {
        await makeDidCommand().parseAsync(['create', '--save'], {
          from: 'user'
        })
        logs.length = 0
        errors.length = 0

        await makeDidCommand().parseAsync(['list', '--json'], { from: 'user' })

        const parsed = JSON.parse(logs[0])
        const expected = await storedDids(didsDir)
        assert.deepEqual(parsed, expected)
      } finally {
        await rm(didsDir, { recursive: true })
      }
    })
  })
})
