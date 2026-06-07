import { describe, it, beforeEach, afterEach, mock } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, readdir, readFile, rm } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { makeIdCommand } from './id.js'

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

describe('did id', () => {
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
      await makeIdCommand().parseAsync(['create'], { from: 'user' })
      const parsed = JSON.parse(logs[0])
      assert.ok(
        parsed.id.startsWith('did:key:'),
        `expected did:key: prefix, got: ${parsed.id}`
      )
    })

    it('creates a did:key with explicit method arg', async () => {
      await makeIdCommand().parseAsync(['create', 'key'], { from: 'user' })
      const parsed = JSON.parse(logs[0])
      assert.ok(parsed.id.startsWith('did:key:'))
    })

    it('output includes id and didDocument with matching id', async () => {
      await makeIdCommand().parseAsync(['create'], { from: 'user' })
      const parsed = JSON.parse(logs[0])
      assert.ok(parsed.id)
      assert.ok(parsed.didDocument)
      assert.equal(parsed.didDocument.id, parsed.id)
    })

    it('does not include secretKeySeed by default', async () => {
      await makeIdCommand().parseAsync(['create'], { from: 'user' })
      const parsed = JSON.parse(logs[0])
      assert.equal(parsed.secretKeySeed, undefined)
    })

    it('--with-seed includes secretKeySeed in output', async () => {
      await makeIdCommand().parseAsync(['create', '--with-seed'], {
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
      await makeIdCommand().parseAsync(['create', '--with-seed'], {
        from: 'user'
      })
      const parsed = JSON.parse(logs[0])
      assert.equal(parsed.secretKeySeed, seed)
    })

    it('--with-seed produces the same DID for the same seed', async () => {
      process.env.SECRET_KEY_SEED =
        'z1AjLxguobDw1Fy3sdaMQxztemkgUQPXXtU6jS9aSf5o7V5'
      await makeIdCommand().parseAsync(['create', '--with-seed'], {
        from: 'user'
      })
      const first = JSON.parse(logs[0])
      logs.length = 0
      await makeIdCommand().parseAsync(['create', '--with-seed'], {
        from: 'user'
      })
      const second = JSON.parse(logs[0])
      assert.equal(first.id, second.id)
    })

    it('--save writes DID document and keys to DIDS_DIR', async () => {
      const didsDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.DIDS_DIR = didsDir
      try {
        await makeIdCommand().parseAsync(['create', '--save'], { from: 'user' })

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

    it('routes did:web (not yet implemented)', async () => {
      await makeIdCommand().parseAsync(['create', 'web'], { from: 'user' })
      assert.ok(logs[0].includes('did:web'))
    })

    it('routes did:webvh (not yet implemented)', async () => {
      await makeIdCommand().parseAsync(['create', 'webvh'], { from: 'user' })
      assert.ok(logs[0].includes('did:webvh'))
    })

    it('exits with error for unknown method', async () => {
      await makeIdCommand().parseAsync(['create', 'unknown'], { from: 'user' })
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
      makeIdCommand().parse(['resolve', 'did:key:z123', '--output', 'json'], {
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
        await makeIdCommand().parseAsync(['list'], { from: 'user' })
        assert.equal(logs.length, 0)
      } finally {
        await rm(didsDir, { recursive: true })
      }
    })

    it('prints nothing when DID storage has never been created', async () => {
      const didsDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      await rm(didsDir, { recursive: true })
      process.env.DIDS_DIR = didsDir
      await makeIdCommand().parseAsync(['list'], { from: 'user' })
      assert.equal(logs.length, 0)
    })

    it('prints stored DIDs, one per line, sorted', async () => {
      const didsDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.DIDS_DIR = didsDir
      try {
        await makeIdCommand().parseAsync(['create', '--save'], { from: 'user' })
        await makeIdCommand().parseAsync(['create', '--save'], { from: 'user' })
        logs.length = 0
        errors.length = 0

        await makeIdCommand().parseAsync(['list'], { from: 'user' })

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
        await makeIdCommand().parseAsync(['create', '--save'], { from: 'user' })
        logs.length = 0
        errors.length = 0

        await makeIdCommand().parseAsync(['list'], { from: 'user' })

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
        await makeIdCommand().parseAsync(['create', '--save'], { from: 'user' })
        logs.length = 0
        errors.length = 0

        await makeIdCommand().parseAsync(['list', '--json'], { from: 'user' })

        const parsed = JSON.parse(logs[0])
        const expected = await storedDids(didsDir)
        assert.deepEqual(parsed, expected)
      } finally {
        await rm(didsDir, { recursive: true })
      }
    })
  })
})
