import { describe, it, beforeEach, afterEach, mock } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, readdir, readFile, rm, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { resolveDIDFromLog } from '@interop/did-method-webvh'
import { makeDidCommand, parseDidLog } from './did.js'
import { makeKeyCommand } from './key.js'
import { webvhLogVerifier } from '../documentLoader.js'

/**
 * Resolve a locally-stored did:webvh history log to its accumulated metadata,
 * verifying the whole proof chain -- so tests can assert that a rotation
 * produced a valid log.
 */
async function resolveStoredWebvhMeta(
  didsDir: string,
  did: string
): Promise<{
  versionId: string
  updateKeys: string[]
  nextKeyHashes: string[]
  prerotation: boolean
  deactivated: boolean
}> {
  const logText = await readFile(join(didsDir, 'webvh', `${did}.jsonl`), 'utf8')
  const log = parseDidLog(logText)
  const { meta } = await resolveDIDFromLog(log, { verifier: webvhLogVerifier })
  return meta
}

async function readJson<T = Record<string, unknown>>(path: string): Promise<T> {
  return JSON.parse(await readFile(path, 'utf8')) as T
}

/**
 * Read the `parameters` of the first (creation) entry of a stored did:webvh
 * history log -- where create-time options like portable / witness / watchers
 * land.
 */
async function firstLogParameters(
  didsDir: string,
  did: string
): Promise<Record<string, unknown>> {
  const logText = await readFile(join(didsDir, 'webvh', `${did}.jsonl`), 'utf8')
  return JSON.parse(logText.split('\n')[0]).parameters
}

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

    it('creates a did:webvh from --url', async () => {
      await makeDidCommand().parseAsync(
        ['create', 'webvh', '--url', 'https://example.com'],
        { from: 'user' }
      )
      const parsed = JSON.parse(logs[0])
      assert.ok(
        parsed.id.startsWith('did:webvh:'),
        `expected did:webvh: prefix, got: ${parsed.id}`
      )
      assert.ok(parsed.id.endsWith(':example.com'))
      assert.equal(parsed.didDocument.id, parsed.id)
    })

    it('wires the webvh key into the same relationships as did:web', async () => {
      await makeDidCommand().parseAsync(
        ['create', 'webvh', '--url', 'https://example.com'],
        { from: 'user' }
      )
      const doc = JSON.parse(logs[0]).didDocument
      assert.equal(doc.verificationMethod.length, 1)
      const vmId = doc.verificationMethod[0].id
      // `purpose` is a creation directive and must not leak into the document.
      assert.ok(!('purpose' in doc.verificationMethod[0]))
      for (const relationship of [
        'authentication',
        'assertionMethod',
        'capabilityDelegation',
        'capabilityInvocation'
      ]) {
        assert.deepEqual(doc[relationship], [vmId], relationship)
      }
      // keyAgreement needs an X25519 key, so the signing key is not wired in.
      assert.deepEqual(doc.keyAgreement ?? [], [])
    })

    it('exits with error when did:webvh is missing --url', async () => {
      await makeDidCommand().parseAsync(['create', 'webvh'], { from: 'user' })
      assert.equal(exitCode, 1)
      assert.ok(errors[0].includes('did:webvh requires --url'))
    })

    it('did:webvh rejects --type ecdsa', async () => {
      await makeDidCommand().parseAsync(
        ['create', 'webvh', '--type', 'ecdsa', '--url', 'https://example.com'],
        { from: 'user' }
      )
      assert.equal(exitCode, 1)
      assert.ok(errors[0].includes('ed25519'))
    })

    it('--save writes the webvh doc, log, keys, update-keys, and meta files', async () => {
      const didsDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.DIDS_DIR = didsDir
      try {
        await makeDidCommand().parseAsync(
          ['create', 'webvh', '--url', 'https://example.com', '--save'],
          { from: 'user' }
        )
        const did = JSON.parse(logs[0]).id
        const webvhDir = join(didsDir, 'webvh')
        const files = (await readdir(webvhDir)).sort()
        assert.deepEqual(files, [
          `${did}.json`,
          `${did}.jsonl`,
          `${did}.keys.json`,
          `${did}.meta.json`,
          `${did}.update-keys.json`
        ])

        // The first log line parses as an entry whose state is the DID document.
        const logText = await readFile(join(webvhDir, `${did}.jsonl`), 'utf8')
        const firstEntry = JSON.parse(logText.split('\n')[0])
        assert.equal(firstEntry.state.id, did)

        // The keys file holds the document verification key V, keyed by its
        // document verification-method id (so it can be selected for signing).
        const keysContent = await readJson(join(webvhDir, `${did}.keys.json`))
        const docVmId = firstEntry.state.verificationMethod[0].id
        const docKey = keysContent[docVmId] as {
          id: string
          publicKeyMultibase: string
          secretKeyMultibase: string
        }
        assert.ok(docKey, 'document key keyed by its VM id')
        assert.equal(docKey.id, docVmId)
        assert.equal(
          docKey.publicKeyMultibase,
          firstEntry.state.verificationMethod[0].publicKeyMultibase
        )

        // The update keys live in their own sidecar: active A (the authorization
        // key in the log) plus staged B, whose hash is committed in nextKeyHashes.
        const updateKeys = await readJson<{
          active: { publicKeyMultibase: string; secretKeyMultibase: string }
          staged?: {
            publicKeyMultibase: string
            secretKeyMultibase: string
            nextKeyHash: string
          }
        }>(join(webvhDir, `${did}.update-keys.json`))
        assert.ok(updateKeys.active.secretKeyMultibase)
        assert.deepEqual(firstEntry.parameters.updateKeys, [
          updateKeys.active.publicKeyMultibase
        ])
        // The update key A is decoupled from the document key V.
        assert.notEqual(
          updateKeys.active.publicKeyMultibase,
          docKey.publicKeyMultibase
        )
        // Pre-rotation is armed by default: B is staged and its hash committed.
        assert.ok(updateKeys.staged)
        assert.ok(updateKeys.staged.secretKeyMultibase)
        assert.deepEqual(firstEntry.parameters.nextKeyHashes, [
          updateKeys.staged.nextKeyHash
        ])

        const meta = await resolveStoredWebvhMeta(didsDir, did)
        assert.equal(meta.prerotation, true)
      } finally {
        await rm(didsDir, { recursive: true })
      }
    })

    it('--no-prerotation creates without a staged key or nextKeyHashes', async () => {
      const didsDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.DIDS_DIR = didsDir
      try {
        await makeDidCommand().parseAsync(
          [
            'create',
            'webvh',
            '--url',
            'https://example.com',
            '--no-prerotation',
            '--save'
          ],
          { from: 'user' }
        )
        const did = JSON.parse(logs[0]).id
        const webvhDir = join(didsDir, 'webvh')

        const updateKeys = await readJson<{
          active: { publicKeyMultibase: string }
          staged?: unknown
        }>(join(webvhDir, `${did}.update-keys.json`))
        assert.equal(updateKeys.staged, undefined)

        const logText = await readFile(join(webvhDir, `${did}.jsonl`), 'utf8')
        const firstEntry = JSON.parse(logText.split('\n')[0])
        assert.deepEqual(firstEntry.parameters.nextKeyHashes ?? [], [])

        const meta = await resolveStoredWebvhMeta(didsDir, did)
        assert.equal(meta.prerotation, false)
      } finally {
        await rm(didsDir, { recursive: true })
      }
    })

    it('did:webvh is portable by default', async () => {
      const didsDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.DIDS_DIR = didsDir
      try {
        await makeDidCommand().parseAsync(
          ['create', 'webvh', '--url', 'https://example.com', '--save'],
          { from: 'user' }
        )
        const did = JSON.parse(logs[0]).id
        const params = await firstLogParameters(didsDir, did)
        assert.equal(params.portable, true)
      } finally {
        await rm(didsDir, { recursive: true })
      }
    })

    it('--no-portable creates a non-portable did:webvh', async () => {
      const didsDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.DIDS_DIR = didsDir
      try {
        await makeDidCommand().parseAsync(
          [
            'create',
            'webvh',
            '--url',
            'https://example.com',
            '--no-portable',
            '--save'
          ],
          { from: 'user' }
        )
        const did = JSON.parse(logs[0]).id
        const params = await firstLogParameters(didsDir, did)
        assert.equal(params.portable, false)
      } finally {
        await rm(didsDir, { recursive: true })
      }
    })

    it('--witness declares witnesses, defaulting threshold to their count', async () => {
      const didsDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.DIDS_DIR = didsDir
      const witnessA =
        'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'
      const witnessB =
        'did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRqHCt3UkyrxX'
      try {
        await makeDidCommand().parseAsync(
          [
            'create',
            'webvh',
            '--url',
            'https://example.com',
            '--witness',
            witnessA,
            '--witness',
            witnessB,
            '--save'
          ],
          { from: 'user' }
        )
        const did = JSON.parse(logs[0]).id
        const params = await firstLogParameters(didsDir, did)
        assert.deepEqual(params.witness, {
          threshold: 2,
          witnesses: [{ id: witnessA }, { id: witnessB }]
        })
      } finally {
        await rm(didsDir, { recursive: true })
      }
    })

    it('--witness-threshold sets the witness threshold', async () => {
      const didsDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.DIDS_DIR = didsDir
      const witnessA =
        'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'
      const witnessB =
        'did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRqHCt3UkyrxX'
      try {
        await makeDidCommand().parseAsync(
          [
            'create',
            'webvh',
            '--url',
            'https://example.com',
            '--witness',
            witnessA,
            '--witness',
            witnessB,
            '--witness-threshold',
            '1',
            '--save'
          ],
          { from: 'user' }
        )
        const did = JSON.parse(logs[0]).id
        const params = await firstLogParameters(didsDir, did)
        assert.equal((params.witness as { threshold: number }).threshold, 1)
      } finally {
        await rm(didsDir, { recursive: true })
      }
    })

    it('--witness-threshold without --witness errors', async () => {
      await makeDidCommand().parseAsync(
        [
          'create',
          'webvh',
          '--url',
          'https://example.com',
          '--witness-threshold',
          '1'
        ],
        { from: 'user' }
      )
      assert.equal(exitCode, 1)
      assert.ok(errors[0].includes('--witness-threshold requires'))
    })

    it('--witness rejects a non-did:key value', async () => {
      await makeDidCommand().parseAsync(
        [
          'create',
          'webvh',
          '--url',
          'https://example.com',
          '--witness',
          'did:web:example.com'
        ],
        { from: 'user' }
      )
      assert.equal(exitCode, 1)
      assert.ok(errors[0].includes('did:key'))
    })

    it('--witness-threshold out of range errors', async () => {
      await makeDidCommand().parseAsync(
        [
          'create',
          'webvh',
          '--url',
          'https://example.com',
          '--witness',
          'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
          '--witness-threshold',
          '2'
        ],
        { from: 'user' }
      )
      assert.equal(exitCode, 1)
      assert.ok(errors[0].includes('--witness-threshold'))
    })

    it('--watcher declares watcher URLs', async () => {
      const didsDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.DIDS_DIR = didsDir
      try {
        await makeDidCommand().parseAsync(
          [
            'create',
            'webvh',
            '--url',
            'https://example.com',
            '--watcher',
            'https://watcher.example.com',
            '--save'
          ],
          { from: 'user' }
        )
        const did = JSON.parse(logs[0]).id
        const params = await firstLogParameters(didsDir, did)
        assert.deepEqual(params.watchers, ['https://watcher.example.com'])
      } finally {
        await rm(didsDir, { recursive: true })
      }
    })

    it('--watcher rejects a non-https URL', async () => {
      await makeDidCommand().parseAsync(
        [
          'create',
          'webvh',
          '--url',
          'https://example.com',
          '--watcher',
          'ftp://watcher.example.com'
        ],
        { from: 'user' }
      )
      assert.equal(exitCode, 1)
      assert.ok(errors[0].includes('watcher URL'))
    })

    it('exits with error for unknown method', async () => {
      await makeDidCommand().parseAsync(['create', 'unknown'], { from: 'user' })
      assert.equal(exitCode, 1)
      assert.ok(errors[0].includes('unknown'))
    })
  })

  describe('webvh rotate-keys', () => {
    /**
     * Create a saved did:webvh DID under a fresh temp DIDS_DIR, returning the
     * dir, the DID, and the path of its update-keys sidecar.
     */
    async function createSavedWebvh(
      extraArgs: string[] = []
    ): Promise<{ didsDir: string; did: string; updateKeysPath: string }> {
      const didsDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.DIDS_DIR = didsDir
      await makeDidCommand().parseAsync(
        [
          'create',
          'webvh',
          '--url',
          'https://example.com',
          '--save',
          ...extraArgs
        ],
        { from: 'user' }
      )
      const did = JSON.parse(logs[0]).id
      logs.length = 0
      return {
        didsDir,
        did,
        updateKeysPath: join(didsDir, 'webvh', `${did}.update-keys.json`)
      }
    }

    it('advances the ratchet by default: reveals the staged key and re-stages', async () => {
      const { didsDir, did, updateKeysPath } = await createSavedWebvh()
      try {
        const before = await readJson<{
          active: { publicKeyMultibase: string }
          staged: { publicKeyMultibase: string }
        }>(updateKeysPath)

        await makeDidCommand().parseAsync(
          ['webvh', 'rotate-keys', did, '--yes'],
          { from: 'user' }
        )

        const after = await readJson<{
          active: { publicKeyMultibase: string; secretKeyMultibase: string }
          staged: { publicKeyMultibase: string; nextKeyHash: string }
        }>(updateKeysPath)
        // The previously staged key is now active, and a fresh key is staged.
        assert.equal(
          after.active.publicKeyMultibase,
          before.staged.publicKeyMultibase
        )
        assert.notEqual(
          after.staged.publicKeyMultibase,
          before.staged.publicKeyMultibase
        )

        const meta = await resolveStoredWebvhMeta(didsDir, did)
        assert.equal(meta.versionId.split('-')[0], '2')
        assert.equal(meta.prerotation, true)
        assert.deepEqual(meta.updateKeys, [after.active.publicKeyMultibase])
        assert.deepEqual(meta.nextKeyHashes, [after.staged.nextKeyHash])
      } finally {
        await rm(didsDir, { recursive: true })
      }
    })

    it('leaves the document verification methods untouched', async () => {
      const { didsDir, did } = await createSavedWebvh()
      try {
        const docPath = join(didsDir, 'webvh', `${did}.json`)
        const before = await readJson<{ verificationMethod: unknown }>(docPath)

        await makeDidCommand().parseAsync(
          ['webvh', 'rotate-keys', did, '--yes'],
          { from: 'user' }
        )

        const after = await readJson<{ verificationMethod: unknown }>(docPath)
        assert.deepEqual(after.verificationMethod, before.verificationMethod)
      } finally {
        await rm(didsDir, { recursive: true })
      }
    })

    it('leaves the relationship arrays and services untouched', async () => {
      const { didsDir, did } = await createSavedWebvh()
      try {
        const docPath = join(didsDir, 'webvh', `${did}.json`)
        const before = await readJson<Record<string, unknown>>(docPath)

        await makeDidCommand().parseAsync(
          ['webvh', 'rotate-keys', did, '--yes'],
          { from: 'user' }
        )

        const after = await readJson<Record<string, unknown>>(docPath)
        // A key-only rotation supplies no document directives, so the sparse
        // updateDID() must carry every relationship array and the service set
        // forward unchanged (and inject no implicit services).
        for (const relationship of [
          'authentication',
          'assertionMethod',
          'keyAgreement',
          'capabilityDelegation',
          'capabilityInvocation'
        ]) {
          assert.deepEqual(after[relationship], before[relationship])
        }
        assert.deepEqual(after.service, before.service)
        // The whole document is preserved, byte for byte.
        assert.deepEqual(after, before)
      } finally {
        await rm(didsDir, { recursive: true })
      }
    })

    it('--stop-prerotation turns pre-rotation off', async () => {
      const { didsDir, did, updateKeysPath } = await createSavedWebvh()
      try {
        await makeDidCommand().parseAsync(
          ['webvh', 'rotate-keys', did, '--stop-prerotation', '--yes'],
          { from: 'user' }
        )
        const after = await readJson<{ staged?: unknown }>(updateKeysPath)
        assert.equal(after.staged, undefined)
        const meta = await resolveStoredWebvhMeta(didsDir, did)
        assert.equal(meta.prerotation, false)
        assert.deepEqual(meta.nextKeyHashes, [])
      } finally {
        await rm(didsDir, { recursive: true })
      }
    })

    it('--enable-prerotation re-arms a DID with pre-rotation off (stage only)', async () => {
      const { didsDir, did, updateKeysPath } = await createSavedWebvh([
        '--no-prerotation'
      ])
      try {
        const before = await readJson<{
          active: { publicKeyMultibase: string }
        }>(updateKeysPath)

        await makeDidCommand().parseAsync(
          ['webvh', 'rotate-keys', did, '--enable-prerotation', '--yes'],
          { from: 'user' }
        )

        const after = await readJson<{
          active: { publicKeyMultibase: string }
          staged?: { publicKeyMultibase: string }
        }>(updateKeysPath)
        // Stage-only: the active key is unchanged, but a next key is now staged.
        assert.equal(
          after.active.publicKeyMultibase,
          before.active.publicKeyMultibase
        )
        assert.ok(after.staged)
        const meta = await resolveStoredWebvhMeta(didsDir, did)
        assert.equal(meta.prerotation, true)
      } finally {
        await rm(didsDir, { recursive: true })
      }
    })

    it('errors when the staged secret is missing in pre-rotation mode', async () => {
      const { didsDir, did, updateKeysPath } = await createSavedWebvh()
      try {
        // Simulate a lost sidecar: without the staged secret, the DID can never
        // be rotated again (the security point of pre-rotation).
        await rm(updateKeysPath)
        await makeDidCommand().parseAsync(
          ['webvh', 'rotate-keys', did, '--yes'],
          { from: 'user' }
        )
        assert.equal(exitCode, 1)
        assert.ok(
          errors.some(line => line.includes('pre-committed next-key secret'))
        )
      } finally {
        await rm(didsDir, { recursive: true })
      }
    })

    it('rejects --update-key while pre-rotation is armed', async () => {
      const { didsDir, did } = await createSavedWebvh()
      try {
        await makeDidCommand().parseAsync(
          [
            'webvh',
            'rotate-keys',
            did,
            '--update-key',
            'z6MkfakeKeyValue',
            '--yes'
          ],
          { from: 'user' }
        )
        assert.equal(exitCode, 1)
        assert.ok(
          errors.some(line => line.includes('--update-key is not allowed'))
        )
      } finally {
        await rm(didsDir, { recursive: true })
      }
    })

    it('rejects a non-webvh DID', async () => {
      await makeDidCommand().parseAsync(
        ['webvh', 'rotate-keys', 'did:key:z6MkfakeKey', '--yes'],
        { from: 'user' }
      )
      assert.equal(exitCode, 1)
      assert.ok(
        errors.some(line => line.includes('only supported for did:webvh'))
      )
    })

    it('errors when the DID is not locally stored', async () => {
      const didsDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.DIDS_DIR = didsDir
      try {
        await makeDidCommand().parseAsync(
          ['webvh', 'rotate-keys', 'did:webvh:QmFake:example.com', '--yes'],
          { from: 'user' }
        )
        assert.equal(exitCode, 1)
        assert.ok(
          errors.some(line => line.includes('No locally stored did:webvh'))
        )
      } finally {
        await rm(didsDir, { recursive: true })
      }
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

    it('resolves a did:webvh document from its stored log', async () => {
      const didsDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.DIDS_DIR = didsDir
      try {
        await makeDidCommand().parseAsync(
          ['create', 'webvh', '--url', 'https://example.com', '--save'],
          { from: 'user' }
        )
        const created = JSON.parse(logs[0])
        const did = created.id as string
        logs.length = 0
        errors.length = 0

        await makeDidCommand().parseAsync(['show', did], { from: 'user' })

        const shown = JSON.parse(logs[0])
        assert.equal(shown.id, did)
        assert.deepEqual(
          shown.verificationMethod,
          created.didDocument.verificationMethod
        )
        assert.ok(!logs[0].includes('secretKeyMultibase'))
      } finally {
        await rm(didsDir, { recursive: true })
      }
    })

    it('--meta --json includes did:webvh log parameters', async () => {
      const didsDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.DIDS_DIR = didsDir
      try {
        await makeDidCommand().parseAsync(
          ['create', 'webvh', '--url', 'https://example.com', '--save'],
          { from: 'user' }
        )
        const did = JSON.parse(logs[0]).id
        logs.length = 0

        await makeDidCommand().parseAsync(['show', did, '--meta', '--json'], {
          from: 'user'
        })

        const parsed = JSON.parse(logs[0])
        assert.equal(parsed.did, did)
        assert.equal(parsed.method, 'webvh')
        // Pre-rotation and portability are on by default for did:webvh.
        assert.equal(parsed.prerotation, true)
        assert.equal(parsed.portable, true)
        assert.equal(parsed.deactivated, false)
        assert.equal(parsed.updateKeys, 1)
        assert.match(parsed.versionId, /^1-/)
        assert.match(parsed.updated, /^\d{4}-\d{2}-\d{2}T/)
      } finally {
        await rm(didsDir, { recursive: true })
      }
    })

    it('--meta table includes did:webvh log parameters', async () => {
      const didsDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.DIDS_DIR = didsDir
      try {
        await makeDidCommand().parseAsync(
          ['create', 'webvh', '--url', 'https://example.com', '--save'],
          { from: 'user' }
        )
        const did = JSON.parse(logs[0]).id
        logs.length = 0

        await makeDidCommand().parseAsync(['show', did, '--meta'], {
          from: 'user'
        })

        assert.match(logs[0], /Method\s+webvh/)
        assert.match(logs[0], /Prerotation\s+yes/)
        assert.match(logs[0], /Portable\s+yes/)
        assert.match(logs[0], /Deactivated\s+no/)
        assert.match(logs[0], /Version\s+1-/)
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

    it('removes a did:webvh history log too', async () => {
      const didsDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.DIDS_DIR = didsDir
      try {
        await makeDidCommand().parseAsync(
          ['create', 'webvh', '--url', 'https://example.com', '--save'],
          { from: 'user' }
        )
        const did = JSON.parse(logs[0]).id
        logs.length = 0
        errors.length = 0

        await makeDidCommand().parseAsync(['remove', did], { from: 'user' })

        assert.equal(exitCode, undefined)
        // doc + keys + update-keys + meta + jsonl == 5 removed files
        assert.equal(errors.length, 5)
        assert.ok(errors.some(line => line.endsWith('.jsonl')))
        assert.ok(errors.some(line => line.endsWith('.update-keys.json')))
        const remaining = await readdir(join(didsDir, 'webvh'))
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

  describe('add-service / remove-service', () => {
    /**
     * Create a saved did:web DID under a fresh temp DIDS_DIR, returning the
     * dir, the DID, and the path of its stored DID document.
     */
    async function createSavedWeb(): Promise<{
      didsDir: string
      did: string
      docPath: string
    }> {
      const didsDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.DIDS_DIR = didsDir
      await makeDidCommand().parseAsync(
        ['create', 'web', '--url', 'https://example.com', '--save'],
        { from: 'user' }
      )
      const did = JSON.parse(logs[0]).id
      logs.length = 0
      errors.length = 0
      return { didsDir, did, docPath: join(didsDir, 'web', `${did}.json`) }
    }

    /**
     * Create a saved did:webvh DID under a fresh temp DIDS_DIR, returning the
     * dir, the DID, and the paths of its document and update-keys sidecar.
     */
    async function createSavedWebvh(extraArgs: string[] = []): Promise<{
      didsDir: string
      did: string
      docPath: string
      updateKeysPath: string
    }> {
      const didsDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.DIDS_DIR = didsDir
      await makeDidCommand().parseAsync(
        [
          'create',
          'webvh',
          '--url',
          'https://example.com',
          '--save',
          ...extraArgs
        ],
        { from: 'user' }
      )
      const did = JSON.parse(logs[0]).id
      logs.length = 0
      errors.length = 0
      return {
        didsDir,
        did,
        docPath: join(didsDir, 'webvh', `${did}.json`),
        updateKeysPath: join(didsDir, 'webvh', `${did}.update-keys.json`)
      }
    }

    it('did:web add-service appends an entry (bare fragment id expanded)', async () => {
      const { didsDir, did, docPath } = await createSavedWeb()
      try {
        await makeDidCommand().parseAsync(
          [
            'add-service',
            did,
            '--id',
            'dwn',
            '--type',
            'LinkedDomains',
            '--endpoint',
            'https://example.com'
          ],
          { from: 'user' }
        )
        assert.equal(exitCode, undefined)
        const doc = await readJson<{
          service: { id: string; type: string; serviceEndpoint: string }[]
        }>(docPath)
        const entry = doc.service.find(service => service.id === `${did}#dwn`)
        assert.ok(entry, 'service entry was added')
        assert.equal(entry?.type, 'LinkedDomains')
        assert.equal(entry?.serviceEndpoint, 'https://example.com')
      } finally {
        await rm(didsDir, { recursive: true })
      }
    })

    it('did:web add-service --endpoint-json stores a JSON serviceEndpoint', async () => {
      const { didsDir, did, docPath } = await createSavedWeb()
      try {
        await makeDidCommand().parseAsync(
          [
            'add-service',
            did,
            '--id',
            'dwn',
            '--type',
            'DecentralizedWebNode',
            '--endpoint-json',
            '{"nodes":["https://dwn.example"]}'
          ],
          { from: 'user' }
        )
        const doc = await readJson<{
          service: { serviceEndpoint: { nodes: string[] } }[]
        }>(docPath)
        assert.deepEqual(doc.service[0].serviceEndpoint, {
          nodes: ['https://dwn.example']
        })
      } finally {
        await rm(didsDir, { recursive: true })
      }
    })

    it('did:web multiple --type / --endpoint values become arrays', async () => {
      const { didsDir, did, docPath } = await createSavedWeb()
      try {
        await makeDidCommand().parseAsync(
          [
            'add-service',
            did,
            '--id',
            'multi',
            '--type',
            'A',
            'B',
            '--endpoint',
            'https://one.example',
            'https://two.example'
          ],
          { from: 'user' }
        )
        const doc = await readJson<{
          service: { type: string[]; serviceEndpoint: string[] }[]
        }>(docPath)
        assert.deepEqual(doc.service[0].type, ['A', 'B'])
        assert.deepEqual(doc.service[0].serviceEndpoint, [
          'https://one.example',
          'https://two.example'
        ])
      } finally {
        await rm(didsDir, { recursive: true })
      }
    })

    it('add-service rejects a duplicate id', async () => {
      const { didsDir, did } = await createSavedWeb()
      try {
        const args = [
          'add-service',
          did,
          '--id',
          'dwn',
          '--type',
          'LinkedDomains',
          '--endpoint',
          'https://example.com'
        ]
        await makeDidCommand().parseAsync(args, { from: 'user' })
        logs.length = 0
        errors.length = 0
        await makeDidCommand().parseAsync(args, { from: 'user' })
        assert.equal(exitCode, 1)
        assert.ok(errors.join('\n').includes('already exists'))
      } finally {
        await rm(didsDir, { recursive: true })
      }
    })

    it('add-service rejects both --endpoint and --endpoint-json', async () => {
      const { didsDir, did } = await createSavedWeb()
      try {
        await makeDidCommand().parseAsync(
          [
            'add-service',
            did,
            '--id',
            'dwn',
            '--type',
            'LinkedDomains',
            '--endpoint',
            'https://example.com',
            '--endpoint-json',
            '{}'
          ],
          { from: 'user' }
        )
        assert.equal(exitCode, 1)
        assert.ok(errors.join('\n').includes('exactly one'))
      } finally {
        await rm(didsDir, { recursive: true })
      }
    })

    it('add-service rejects neither --endpoint nor --endpoint-json', async () => {
      const { didsDir, did } = await createSavedWeb()
      try {
        await makeDidCommand().parseAsync(
          ['add-service', did, '--id', 'dwn', '--type', 'LinkedDomains'],
          { from: 'user' }
        )
        assert.equal(exitCode, 1)
        assert.ok(errors.join('\n').includes('exactly one'))
      } finally {
        await rm(didsDir, { recursive: true })
      }
    })

    it('did:web remove-service drops the entry (and the empty service array)', async () => {
      const { didsDir, did, docPath } = await createSavedWeb()
      try {
        await makeDidCommand().parseAsync(
          [
            'add-service',
            did,
            '--id',
            'dwn',
            '--type',
            'LinkedDomains',
            '--endpoint',
            'https://example.com'
          ],
          { from: 'user' }
        )
        logs.length = 0
        errors.length = 0
        await makeDidCommand().parseAsync(
          ['remove-service', did, '--id', 'dwn'],
          { from: 'user' }
        )
        assert.equal(exitCode, undefined)
        const doc = await readJson<Record<string, unknown>>(docPath)
        // The last service was removed, so the property is dropped entirely.
        assert.equal(doc.service, undefined)
      } finally {
        await rm(didsDir, { recursive: true })
      }
    })

    it('remove-service rejects a missing id', async () => {
      const { didsDir, did } = await createSavedWeb()
      try {
        await makeDidCommand().parseAsync(
          ['remove-service', did, '--id', 'nope'],
          { from: 'user' }
        )
        assert.equal(exitCode, 1)
        assert.ok(errors.join('\n').includes('No service with id'))
      } finally {
        await rm(didsDir, { recursive: true })
      }
    })

    it('rejects an unsupported method (did:key)', async () => {
      const didsDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.DIDS_DIR = didsDir
      try {
        await makeDidCommand().parseAsync(['create', 'key', '--save'], {
          from: 'user'
        })
        const did = JSON.parse(logs[0]).id
        logs.length = 0
        errors.length = 0
        await makeDidCommand().parseAsync(
          [
            'add-service',
            did,
            '--id',
            'dwn',
            '--type',
            'LinkedDomains',
            '--endpoint',
            'https://example.com'
          ],
          { from: 'user' }
        )
        assert.equal(exitCode, 1)
        assert.ok(errors.join('\n').includes('only supported for'))
      } finally {
        await rm(didsDir, { recursive: true })
      }
    })

    it('did:webvh add-service appends a log entry, leaving keys unchanged (no pre-rotation)', async () => {
      const { didsDir, did, docPath, updateKeysPath } = await createSavedWebvh([
        '--no-prerotation'
      ])
      try {
        const beforeKeys =
          await readJson<Record<string, unknown>>(updateKeysPath)
        const beforeMeta = await resolveStoredWebvhMeta(didsDir, did)

        await makeDidCommand().parseAsync(
          [
            'add-service',
            did,
            '--id',
            'dwn',
            '--type',
            'LinkedDomains',
            '--endpoint',
            'https://dwn.example',
            '--yes'
          ],
          { from: 'user' }
        )
        assert.equal(exitCode, undefined)

        const doc = await readJson<{ service: { id: string }[] }>(docPath)
        assert.ok(doc.service.some(service => service.id === `${did}#dwn`))

        // An ordinary (non-pre-rotation) service update carries the update
        // keys forward and leaves the sidecar untouched.
        const afterKeys =
          await readJson<Record<string, unknown>>(updateKeysPath)
        assert.deepEqual(afterKeys, beforeKeys)

        const afterMeta = await resolveStoredWebvhMeta(didsDir, did)
        assert.equal(afterMeta.versionId.split('-')[0], '2')
        assert.deepEqual(afterMeta.updateKeys, beforeMeta.updateKeys)
      } finally {
        await rm(didsDir, { recursive: true })
      }
    })

    it('did:webvh remove-service appends a log entry removing the service', async () => {
      const { didsDir, did, docPath } = await createSavedWebvh([
        '--no-prerotation'
      ])
      try {
        await makeDidCommand().parseAsync(
          [
            'add-service',
            did,
            '--id',
            'dwn',
            '--type',
            'LinkedDomains',
            '--endpoint',
            'https://dwn.example',
            '--yes'
          ],
          { from: 'user' }
        )
        logs.length = 0
        errors.length = 0
        await makeDidCommand().parseAsync(
          ['remove-service', did, '--id', 'dwn', '--yes'],
          { from: 'user' }
        )
        assert.equal(exitCode, undefined)
        const doc = await readJson<{ service?: { id: string }[] }>(docPath)
        assert.ok(!doc.service?.some(service => service.id === `${did}#dwn`))
        const meta = await resolveStoredWebvhMeta(didsDir, did)
        assert.equal(meta.versionId.split('-')[0], '3')
      } finally {
        await rm(didsDir, { recursive: true })
      }
    })

    it('add-service detects a stored relative-id service as a duplicate', async () => {
      const { didsDir, did, docPath } = await createSavedWeb()
      try {
        // Seed a stored doc whose service id is relative (`#files`), as an
        // externally-authored DID document may be. Adding `files` must be
        // caught as a duplicate even though the new id normalizes to an
        // absolute DID URL.
        const seeded = await readJson<Record<string, unknown>>(docPath)
        seeded.service = [
          {
            id: '#files',
            type: 'relativeRef',
            serviceEndpoint: 'https://example.com/'
          }
        ]
        await writeFile(docPath, JSON.stringify(seeded, null, 2), 'utf8')

        await makeDidCommand().parseAsync(
          [
            'add-service',
            did,
            '--id',
            'files',
            '--type',
            'LinkedDomains',
            '--endpoint',
            'https://example.com'
          ],
          { from: 'user' }
        )
        assert.equal(exitCode, 1)
        assert.ok(errors.join('\n').includes('already exists'))
      } finally {
        await rm(didsDir, { recursive: true })
      }
    })

    it('remove-service removes a stored relative-id service', async () => {
      const { didsDir, did, docPath } = await createSavedWeb()
      try {
        // A relative-id (`#whois`) stored service is matched and removed even
        // though `--id whois` normalizes to an absolute DID URL.
        const seeded = await readJson<Record<string, unknown>>(docPath)
        seeded.service = [
          {
            id: '#whois',
            type: 'LinkedVerifiablePresentation',
            serviceEndpoint: 'https://example.com/whois.vp'
          }
        ]
        await writeFile(docPath, JSON.stringify(seeded, null, 2), 'utf8')

        await makeDidCommand().parseAsync(
          ['remove-service', did, '--id', 'whois'],
          { from: 'user' }
        )
        assert.equal(exitCode, undefined)
        const doc = await readJson<{ service?: { id: string }[] }>(docPath)
        assert.ok(!doc.service?.some(service => service.id === '#whois'))
      } finally {
        await rm(didsDir, { recursive: true })
      }
    })

    it('did:webvh add-service advances the ratchet under pre-rotation', async () => {
      const { didsDir, did, docPath, updateKeysPath } = await createSavedWebvh()
      try {
        const before = await readJson<{
          active: { publicKeyMultibase: string }
          staged: { publicKeyMultibase: string }
        }>(updateKeysPath)

        await makeDidCommand().parseAsync(
          [
            'add-service',
            did,
            '--id',
            'dwn',
            '--type',
            'LinkedDomains',
            '--endpoint',
            'https://dwn.example',
            '--yes'
          ],
          { from: 'user' }
        )
        assert.equal(exitCode, undefined)

        const after = await readJson<{
          active: { publicKeyMultibase: string }
          staged: { publicKeyMultibase: string }
        }>(updateKeysPath)
        // The staged key was revealed (now active) and a fresh one staged.
        assert.equal(
          after.active.publicKeyMultibase,
          before.staged.publicKeyMultibase
        )
        assert.notEqual(
          after.staged.publicKeyMultibase,
          before.staged.publicKeyMultibase
        )

        const doc = await readJson<{ service: { id: string }[] }>(docPath)
        assert.ok(doc.service.some(service => service.id === `${did}#dwn`))

        const meta = await resolveStoredWebvhMeta(didsDir, did)
        assert.equal(meta.prerotation, true)
        assert.deepEqual(meta.updateKeys, [after.active.publicKeyMultibase])
        assert.ok(errors.join('\n').includes('Pre-rotation'))
      } finally {
        await rm(didsDir, { recursive: true })
      }
    })
  })
})
