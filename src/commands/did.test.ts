import { describe, it, beforeEach, afterEach, mock } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, readdir, readFile, rm } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { makeDidCommand } from './did.js'
import { makeKeyCommand } from './key.js'

async function storedDids(didsDir: string): Promise<string[]> {
  const methodEntries = await readdir(didsDir, { withFileTypes: true })
  const dids: string[] = []
  for (const methodEntry of methodEntries) {
    if (!methodEntry.isDirectory()) {
      continue
    }
    const fileNames = await readdir(join(didsDir, methodEntry.name))
    for (const fileName of fileNames) {
      if (
        !fileName.endsWith('.json') ||
        fileName.endsWith('.keys.json') ||
        fileName.endsWith('.meta.json')
      ) {
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

    it('--save writes a .meta.json sidecar with created/handle/description', async () => {
      const didsDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.DIDS_DIR = didsDir
      try {
        await makeDidCommand().parseAsync(
          [
            'create',
            '--save',
            '--handle',
            'issuer',
            '--description',
            'demo DID'
          ],
          { from: 'user' }
        )
        const docPath = errors[0].slice('DID saved to '.length)
        const metaPath = docPath.replace(/\.json$/, '.meta.json')
        const meta = JSON.parse(await readFile(metaPath, 'utf8'))
        assert.match(meta.created, /^\d{4}-\d{2}-\d{2}T/)
        assert.equal(meta.handle, 'issuer')
        assert.equal(meta.description, 'demo DID')
      } finally {
        await rm(didsDir, { recursive: true })
      }
    })

    it('exits with error for --handle without --save', async () => {
      await makeDidCommand().parseAsync(['create', '--handle', 'x'], {
        from: 'user'
      })
      assert.equal(exitCode, 1)
      assert.ok(errors[0].includes('--save'))
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

  describe('get', () => {
    it('resolves a did:key to its DID document', async () => {
      // Create a did:key first, then resolve it (did:key is offline).
      await makeDidCommand().parseAsync(['create'], { from: 'user' })
      const did = JSON.parse(logs[0]).id
      logs.length = 0

      await makeDidCommand().parseAsync(['get', did], { from: 'user' })
      const document = JSON.parse(logs.join('\n'))
      assert.equal(document.id, did)
      assert.ok(Array.isArray(document.verificationMethod))
    })

    it('dereferences a did:key URL to its verification method', async () => {
      await makeDidCommand().parseAsync(['create'], { from: 'user' })
      const document = JSON.parse(logs[0]).didDocument
      const keyId = document.verificationMethod[0].id
      logs.length = 0

      await makeDidCommand().parseAsync(['get', keyId], { from: 'user' })
      const method = JSON.parse(logs.join('\n'))
      assert.equal(method.id, keyId)
      assert.equal(method.type, document.verificationMethod[0].type)
    })

    it('is aliased as resolve', async () => {
      await makeDidCommand().parseAsync(['create'], { from: 'user' })
      const did = JSON.parse(logs[0]).id
      logs.length = 0

      await makeDidCommand().parseAsync(['resolve', did], { from: 'user' })
      assert.equal(JSON.parse(logs.join('\n')).id, did)
    })

    it('exits with error when the DID cannot be resolved', async () => {
      await makeDidCommand().parseAsync(['get', 'did:key:zNotAValidKey'], {
        from: 'user'
      })
      assert.equal(exitCode, 1)
      assert.ok(errors[0].includes('Could not resolve'))
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

    it('--plain prints stored DIDs, one per line, sorted', async () => {
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

        await makeDidCommand().parseAsync(['list', '--plain'], {
          from: 'user'
        })

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

    it('omits the .keys.json and .meta.json sidecar files', async () => {
      const didsDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.DIDS_DIR = didsDir
      try {
        await makeDidCommand().parseAsync(['create', '--save'], {
          from: 'user'
        })
        logs.length = 0
        errors.length = 0

        await makeDidCommand().parseAsync(['list', '--plain'], {
          from: 'user'
        })

        assert.equal(logs.length, 1)
        assert.ok(!logs[0].includes('.keys'))
        assert.ok(!logs[0].includes('.meta'))
      } finally {
        await rm(didsDir, { recursive: true })
      }
    })

    it('prints a metadata table by default', async () => {
      const didsDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.DIDS_DIR = didsDir
      try {
        await makeDidCommand().parseAsync(
          [
            'create',
            '--save',
            '--handle',
            'issuer',
            '--description',
            'demo DID'
          ],
          { from: 'user' }
        )
        logs.length = 0
        errors.length = 0

        await makeDidCommand().parseAsync(['list'], { from: 'user' })

        assert.equal(logs.length, 1)
        const [header, separator, row] = logs[0].split('\n')
        assert.match(header, /^HANDLE\s+METHOD\s+CREATED\s+DID\s+DESCRIPTION$/)
        assert.match(separator, /^-+(\s+-+)+$/)
        assert.match(row, /^issuer\s+key\s+\d{4}-\d{2}-\d{2}\s+did:key:/)
        assert.match(row, /demo DID$/)
      } finally {
        await rm(didsDir, { recursive: true })
      }
    })

    it('--json outputs an array of objects with metadata', async () => {
      const didsDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.DIDS_DIR = didsDir
      try {
        await makeDidCommand().parseAsync(
          ['create', '--save', '--handle', 'issuer'],
          { from: 'user' }
        )
        logs.length = 0
        errors.length = 0

        await makeDidCommand().parseAsync(['list', '--json'], { from: 'user' })

        const parsed = JSON.parse(logs[0])
        const expected = await storedDids(didsDir)
        assert.equal(parsed.length, 1)
        assert.equal(parsed[0].did, expected[0])
        assert.equal(parsed[0].method, 'key')
        assert.equal(parsed[0].handle, 'issuer')
        assert.match(parsed[0].created, /^\d{4}-\d{2}-\d{2}T/)
        assert.equal(parsed[0].description, undefined)
      } finally {
        await rm(didsDir, { recursive: true })
      }
    })
  })

  describe('show', () => {
    it('prints the stored DID document', async () => {
      const didsDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.DIDS_DIR = didsDir
      try {
        await makeDidCommand().parseAsync(['create', '--save'], {
          from: 'user'
        })
        const created = JSON.parse(logs[0])
        const did = created.id as string
        logs.length = 0
        errors.length = 0

        await makeDidCommand().parseAsync(['show', did], { from: 'user' })

        const shown = JSON.parse(logs[0])
        assert.equal(shown.id, did)
        assert.deepEqual(shown, created.didDocument)
      } finally {
        await rm(didsDir, { recursive: true })
      }
    })

    it('contains no secret key material', async () => {
      const didsDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.DIDS_DIR = didsDir
      try {
        await makeDidCommand().parseAsync(['create', '--save'], {
          from: 'user'
        })
        const did = JSON.parse(logs[0]).id as string
        logs.length = 0

        await makeDidCommand().parseAsync(['show', did], { from: 'user' })

        assert.ok(!logs[0].includes('secretKeyMultibase'))
      } finally {
        await rm(didsDir, { recursive: true })
      }
    })

    it('is aliased as view and cat', async () => {
      const didsDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.DIDS_DIR = didsDir
      try {
        await makeDidCommand().parseAsync(['create', '--save'], {
          from: 'user'
        })
        const did = JSON.parse(logs[0]).id as string

        for (const verb of ['view', 'cat']) {
          logs.length = 0
          await makeDidCommand().parseAsync([verb, did], { from: 'user' })
          assert.equal(JSON.parse(logs[0]).id, did)
        }
      } finally {
        await rm(didsDir, { recursive: true })
      }
    })

    it('exits with error for an unknown DID', async () => {
      const didsDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.DIDS_DIR = didsDir
      try {
        await makeDidCommand().parseAsync(['show', 'did:key:z6MkUnknown'], {
          from: 'user'
        })
        assert.equal(exitCode, 1)
        assert.ok(errors[0].includes('did:key:z6MkUnknown'))
      } finally {
        await rm(didsDir, { recursive: true })
      }
    })

    it('looks up a DID by handle', async () => {
      const didsDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.DIDS_DIR = didsDir
      try {
        await makeDidCommand().parseAsync(
          ['create', '--save', '--handle', 'issuer'],
          { from: 'user' }
        )
        const did = JSON.parse(logs[0]).id
        logs.length = 0

        await makeDidCommand().parseAsync(['show', 'issuer'], { from: 'user' })

        assert.equal(JSON.parse(logs[0]).id, did)
      } finally {
        await rm(didsDir, { recursive: true })
      }
    })

    it('exits with error for an ambiguous handle', async () => {
      const didsDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.DIDS_DIR = didsDir
      try {
        for (let i = 0; i < 2; i++) {
          await makeDidCommand().parseAsync(
            ['create', '--save', '--handle', 'dupe'],
            { from: 'user' }
          )
        }
        logs.length = 0
        errors.length = 0

        await makeDidCommand().parseAsync(['show', 'dupe'], { from: 'user' })

        assert.equal(exitCode, 1)
        assert.ok(errors[0].includes('dupe'))
        assert.ok(errors[0].includes('2 DIDs'))
      } finally {
        await rm(didsDir, { recursive: true })
      }
    })

    it('--meta prints a vertical metadata table', async () => {
      const didsDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.DIDS_DIR = didsDir
      try {
        await makeDidCommand().parseAsync(
          [
            'create',
            '--save',
            '--handle',
            'issuer',
            '--description',
            'demo DID'
          ],
          { from: 'user' }
        )
        const did = JSON.parse(logs[0]).id
        logs.length = 0

        await makeDidCommand().parseAsync(['show', did, '--meta'], {
          from: 'user'
        })

        const lines = logs[0].split('\n')
        assert.match(lines[0], /^FIELD\s+VALUE$/)
        assert.ok(logs[0].includes(did))
        assert.match(logs[0], /Method\s+key/)
        assert.match(logs[0], /Handle\s+issuer/)
        assert.match(logs[0], /Description\s+demo DID/)
        assert.match(logs[0], /Keys\s+1/)
      } finally {
        await rm(didsDir, { recursive: true })
      }
    })

    it('--meta --json prints the metadata object', async () => {
      const didsDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.DIDS_DIR = didsDir
      try {
        await makeDidCommand().parseAsync(
          ['create', '--save', '--handle', 'issuer'],
          { from: 'user' }
        )
        const did = JSON.parse(logs[0]).id
        logs.length = 0

        await makeDidCommand().parseAsync(['show', did, '--meta', '--json'], {
          from: 'user'
        })

        const parsed = JSON.parse(logs[0])
        assert.equal(parsed.did, did)
        assert.equal(parsed.method, 'key')
        assert.equal(parsed.handle, 'issuer')
        assert.equal(parsed.keys, 1)
      } finally {
        await rm(didsDir, { recursive: true })
      }
    })
  })

  describe('meta', () => {
    it('prints the current metadata with no options', async () => {
      const didsDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.DIDS_DIR = didsDir
      try {
        await makeDidCommand().parseAsync(
          ['create', '--save', '--handle', 'issuer'],
          { from: 'user' }
        )
        const did = JSON.parse(logs[0]).id
        logs.length = 0

        await makeDidCommand().parseAsync(['meta', did], { from: 'user' })

        const parsed = JSON.parse(logs[0])
        assert.equal(parsed.handle, 'issuer')
        assert.match(parsed.created, /^\d{4}-\d{2}-\d{2}T/)
      } finally {
        await rm(didsDir, { recursive: true })
      }
    })

    it('sets and clears handle and description', async () => {
      const didsDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.DIDS_DIR = didsDir
      try {
        await makeDidCommand().parseAsync(['create', '--save'], {
          from: 'user'
        })
        const did = JSON.parse(logs[0]).id
        logs.length = 0
        errors.length = 0

        await makeDidCommand().parseAsync(
          ['meta', did, '--handle', 'h1', '--description', 'd1'],
          { from: 'user' }
        )
        assert.ok(errors[0].startsWith('Metadata saved to '))
        let saved = JSON.parse(logs[0])
        assert.equal(saved.handle, 'h1')
        assert.equal(saved.description, 'd1')
        logs.length = 0

        await makeDidCommand().parseAsync(['meta', did, '--handle', ''], {
          from: 'user'
        })
        saved = JSON.parse(logs[0])
        assert.equal(saved.handle, undefined)
        assert.equal(saved.description, 'd1')
      } finally {
        await rm(didsDir, { recursive: true })
      }
    })

    it('looks up a DID by handle', async () => {
      const didsDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.DIDS_DIR = didsDir
      try {
        await makeDidCommand().parseAsync(
          ['create', '--save', '--handle', 'issuer'],
          { from: 'user' }
        )
        logs.length = 0

        await makeDidCommand().parseAsync(
          ['meta', 'issuer', '--description', 'updated'],
          { from: 'user' }
        )

        const saved = JSON.parse(logs[0])
        assert.equal(saved.handle, 'issuer')
        assert.equal(saved.description, 'updated')
      } finally {
        await rm(didsDir, { recursive: true })
      }
    })

    it('refuses to create metadata for an unsaved DID', async () => {
      const didsDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.DIDS_DIR = didsDir
      try {
        await makeDidCommand().parseAsync(
          ['meta', 'did:key:z6MkUnknown', '--handle', 'x'],
          { from: 'user' }
        )
        assert.equal(exitCode, 1)
        assert.ok(errors[0].includes('did:key:z6MkUnknown'))
      } finally {
        await rm(didsDir, { recursive: true })
      }
    })
  })

  describe('remove', () => {
    it('removes the DID document, keys file, and metadata sidecar', async () => {
      const didsDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.DIDS_DIR = didsDir
      try {
        await makeDidCommand().parseAsync(
          ['create', '--save', '--handle', 'doomed'],
          { from: 'user' }
        )
        const did = JSON.parse(logs[0]).id
        logs.length = 0
        errors.length = 0

        await makeDidCommand().parseAsync(['remove', did], { from: 'user' })

        assert.equal(exitCode, undefined)
        assert.equal(errors.length, 3)
        for (const line of errors) {
          assert.ok(line.startsWith('Removed '))
        }
        assert.deepEqual(await storedDids(didsDir), [])
        const remaining = await readdir(join(didsDir, 'key'))
        assert.deepEqual(remaining, [])
      } finally {
        await rm(didsDir, { recursive: true })
      }
    })

    it('looks up a DID by handle', async () => {
      const didsDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.DIDS_DIR = didsDir
      try {
        await makeDidCommand().parseAsync(
          ['create', '--save', '--handle', 'doomed'],
          { from: 'user' }
        )
        logs.length = 0
        errors.length = 0

        await makeDidCommand().parseAsync(['remove', 'doomed'], {
          from: 'user'
        })

        assert.equal(exitCode, undefined)
        assert.deepEqual(await storedDids(didsDir), [])
      } finally {
        await rm(didsDir, { recursive: true })
      }
    })

    it('is aliased as delete and rm', async () => {
      const didsDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.DIDS_DIR = didsDir
      try {
        for (const verb of ['delete', 'rm']) {
          await makeDidCommand().parseAsync(['create', '--save'], {
            from: 'user'
          })
          const did = JSON.parse(logs[0]).id
          logs.length = 0
          errors.length = 0

          await makeDidCommand().parseAsync([verb, did], { from: 'user' })

          assert.equal(exitCode, undefined, `verb: ${verb}`)
          assert.deepEqual(await storedDids(didsDir), [], `verb: ${verb}`)
        }
      } finally {
        await rm(didsDir, { recursive: true })
      }
    })

    it('exits with error for an unknown DID', async () => {
      const didsDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.DIDS_DIR = didsDir
      try {
        await makeDidCommand().parseAsync(['remove', 'did:key:z6MkUnknown'], {
          from: 'user'
        })
        assert.equal(exitCode, 1)
        assert.ok(errors[0].includes('did:key:z6MkUnknown'))
      } finally {
        await rm(didsDir, { recursive: true })
      }
    })

    it('scrubs the cached association from matching wallet keys', async () => {
      const didsDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      const walletDir = await mkdtemp(join(tmpdir(), 'did-cli-test-wallet-'))
      process.env.DIDS_DIR = didsDir
      process.env.WALLET_DIR = walletDir
      // ed25519 keys are seed-deterministic, so the wallet key and the DID's
      // verification key coincide when created from the same seed.
      process.env.SECRET_KEY_SEED =
        'z1AjLxguobDw1Fy3sdaMQxztemkgUQPXXtU6jS9aSf5o7V5'
      try {
        await makeKeyCommand().parseAsync(['create', '--save'], {
          from: 'user'
        })
        logs.length = 0
        errors.length = 0

        await makeDidCommand().parseAsync(['create', '--save'], {
          from: 'user'
        })
        const did = JSON.parse(logs[0]).id
        logs.length = 0
        errors.length = 0

        const keysDir = join(walletDir, 'keys')
        const metaName = (await readdir(keysDir)).find(name =>
          name.endsWith('.meta.json')
        ) as string
        let meta = JSON.parse(await readFile(join(keysDir, metaName), 'utf8'))
        assert.deepEqual(meta.dids, [did])

        await makeDidCommand().parseAsync(['remove', did], { from: 'user' })

        meta = JSON.parse(await readFile(join(keysDir, metaName), 'utf8'))
        assert.equal(meta.dids, undefined)
      } finally {
        delete process.env.WALLET_DIR
        await rm(didsDir, { recursive: true })
        await rm(walletDir, { recursive: true })
      }
    })
  })

  describe('add-key', () => {
    it('updates the key-to-DID cache of a matching wallet key', async () => {
      const didsDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      const walletDir = await mkdtemp(join(tmpdir(), 'did-cli-test-wallet-'))
      process.env.DIDS_DIR = didsDir
      process.env.WALLET_DIR = walletDir
      const seed = 'z1AjLxguobDw1Fy3sdaMQxztemkgUQPXXtU6jS9aSf5o7V5'
      try {
        // Save a wallet key derived from a known seed.
        process.env.SECRET_KEY_SEED = seed
        await makeKeyCommand().parseAsync(['create', '--save'], {
          from: 'user'
        })
        delete process.env.SECRET_KEY_SEED
        logs.length = 0
        errors.length = 0

        // Create a did:web with a random (non-matching) key...
        await makeDidCommand().parseAsync(
          ['create', 'web', '--url', 'https://example.com', '--save'],
          { from: 'user' }
        )
        const did = JSON.parse(logs[0]).id
        logs.length = 0
        errors.length = 0

        // ...then add a key derived from the wallet key's seed.
        process.env.SECRET_KEY_SEED = seed
        await makeDidCommand().parseAsync(['add-key', did], { from: 'user' })

        const keysDir = join(walletDir, 'keys')
        const metaName = (await readdir(keysDir)).find(name =>
          name.endsWith('.meta.json')
        ) as string
        const meta = JSON.parse(await readFile(join(keysDir, metaName), 'utf8'))
        assert.deepEqual(meta.dids, [did])
      } finally {
        delete process.env.WALLET_DIR
        await rm(didsDir, { recursive: true })
        await rm(walletDir, { recursive: true })
      }
    })

    it('wires an x25519 key into keyAgreement only', async () => {
      const didsDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.DIDS_DIR = didsDir
      try {
        await makeDidCommand().parseAsync(
          ['create', 'web', '--url', 'https://example.com', '--save'],
          { from: 'user' }
        )
        const did = JSON.parse(logs[0]).id
        logs.length = 0
        errors.length = 0

        await makeDidCommand().parseAsync(
          ['add-key', did, '--type', 'x25519'],
          {
            from: 'user'
          }
        )
        const didDocument = JSON.parse(logs[0]).didDocument

        // The key lands in keyAgreement, with the X25519 verification type...
        assert.equal(didDocument.keyAgreement.length, 1)
        assert.equal(
          didDocument.keyAgreement[0].type,
          'X25519KeyAgreementKey2020'
        )
        // ...and in none of the signing/invocation relationships.
        for (const purpose of [
          'authentication',
          'assertionMethod',
          'capabilityDelegation',
          'capabilityInvocation'
        ]) {
          const entries = didDocument[purpose] ?? []
          assert.equal(
            entries.some(
              (entry: { type?: string }) =>
                entry?.type === 'X25519KeyAgreementKey2020'
            ),
            false,
            `x25519 key should not appear in ${purpose}`
          )
        }

        // The stored keys file keeps the private half as privateKeyMultibase.
        const keysFile = JSON.parse(
          await readFile(join(didsDir, 'web', `${did}.keys.json`), 'utf8')
        )
        const x25519Key = Object.values(keysFile).find(
          (key): key is { type?: string; privateKeyMultibase?: string } =>
            (key as { type?: string }).type === 'X25519KeyAgreementKey2020'
        )
        assert.ok(x25519Key?.privateKeyMultibase)
      } finally {
        await rm(didsDir, { recursive: true })
      }
    })

    it('rejects an x25519 key with a non-keyAgreement purpose', async () => {
      const didsDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.DIDS_DIR = didsDir
      try {
        await makeDidCommand().parseAsync(
          ['create', 'web', '--url', 'https://example.com', '--save'],
          { from: 'user' }
        )
        const did = JSON.parse(logs[0]).id
        logs.length = 0
        errors.length = 0

        await makeDidCommand().parseAsync(
          ['add-key', did, '--type', 'x25519', '--purpose', 'authentication'],
          { from: 'user' }
        )
        assert.equal(exitCode, 1)
        assert.ok(errors[0].includes('keyAgreement'))
      } finally {
        await rm(didsDir, { recursive: true })
      }
    })

    it('exits with error for x25519 --with-seed', async () => {
      const didsDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.DIDS_DIR = didsDir
      try {
        await makeDidCommand().parseAsync(
          ['create', 'web', '--url', 'https://example.com', '--save'],
          { from: 'user' }
        )
        const did = JSON.parse(logs[0]).id
        logs.length = 0
        errors.length = 0

        await makeDidCommand().parseAsync(
          ['add-key', did, '--type', 'x25519', '--with-seed'],
          { from: 'user' }
        )
        assert.equal(exitCode, 1)
        assert.ok(errors[0].includes('--with-seed'))
      } finally {
        await rm(didsDir, { recursive: true })
      }
    })
  })
})
