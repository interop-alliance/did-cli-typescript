import { describe, it, beforeEach, afterEach, mock } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { makeDidCommand } from './did.js'
import { makeZcapCommand } from './zcap.js'
import { decodeCapability } from '../zcap/encoding.js'

/**
 * Creates a stored did:key in `didsDir` (with its seed) and returns the DID and
 * the multibase secret key seed.
 */
async function createStoredDid(
  didsDir: string
): Promise<{ did: string; seed: string }> {
  const logs: string[] = []
  const restore = console.log
  console.log = (...args: unknown[]) => logs.push(args.join(' '))
  const prevDids = process.env.DIDS_DIR
  process.env.DIDS_DIR = didsDir
  try {
    await makeDidCommand().parseAsync(['create', '--save', '--with-seed'], {
      from: 'user'
    })
  } finally {
    console.log = restore
    if (prevDids === undefined) {
      delete process.env.DIDS_DIR
    } else {
      process.env.DIDS_DIR = prevDids
    }
  }
  const parsed = JSON.parse(logs.at(-1) as string)
  return { did: parsed.id as string, seed: parsed.secretKeySeed as string }
}

/**
 * Creates a saved root zcap in the current WALLET_DIR (controller
 * did:key:z6MkController) and returns its capability id.
 */
async function createSavedRootZcap({
  url,
  handle,
  description
}: {
  url: string
  handle?: string
  description?: string
}): Promise<string> {
  const args = [
    'create',
    '--controller',
    'did:key:z6MkController',
    '--url',
    url,
    '--save'
  ]
  if (handle) {
    args.push('--handle', handle)
  }
  if (description) {
    args.push('--description', description)
  }
  await makeZcapCommand().parseAsync(args, { from: 'user' })
  return `urn:zcap:root:${encodeURIComponent(url)}`
}

describe('did zcap', () => {
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
    delete process.env.WALLET_DIR
    delete process.env.SECRET_KEY_SEED
    delete process.env.ZCAP_CONTROLLER_KEY_SEED
  })

  describe('create', () => {
    it('builds a root capability for the controller and url', async () => {
      await makeZcapCommand().parseAsync(
        [
          'create',
          '--controller',
          'did:key:z6MkController',
          '--url',
          'https://example.com/api'
        ],
        { from: 'user' }
      )
      const { rootCapability, encoded } = JSON.parse(logs[0])
      assert.equal(
        rootCapability.id,
        'urn:zcap:root:https%3A%2F%2Fexample.com%2Fapi'
      )
      assert.equal(rootCapability.controller, 'did:key:z6MkController')
      assert.equal(rootCapability.invocationTarget, 'https://example.com/api')
      assert.ok(encoded.startsWith('z'))
      assert.deepEqual(decodeCapability(encoded), rootCapability)
    })

    it('--save writes the capability to WALLET_DIR/zcaps', async () => {
      const walletDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.WALLET_DIR = walletDir
      try {
        await makeZcapCommand().parseAsync(
          [
            'create',
            '--controller',
            'did:key:z6MkController',
            '--url',
            'https://example.com/api',
            '--save'
          ],
          { from: 'user' }
        )
        assert.equal(errors.length, 1)
        assert.ok(errors[0].startsWith('Capability saved to '))
        const filePath = errors[0].slice('Capability saved to '.length)
        assert.ok(filePath.startsWith(join(walletDir, 'zcaps')))
        const saved = JSON.parse(await readFile(filePath, 'utf8'))
        assert.equal(saved.invocationTarget, 'https://example.com/api')
      } finally {
        await rm(walletDir, { recursive: true })
      }
    })

    it('--save --handle/--description writes a metadata sidecar', async () => {
      const walletDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.WALLET_DIR = walletDir
      try {
        await makeZcapCommand().parseAsync(
          [
            'create',
            '--controller',
            'did:key:z6MkController',
            '--url',
            'https://example.com/api',
            '--save',
            '--handle',
            'api-root',
            '--description',
            'Root capability for the demo API'
          ],
          { from: 'user' }
        )
        const filePath = errors[0].slice('Capability saved to '.length)
        const metaPath = filePath.replace(/\.json$/, '.meta.json')
        const meta = JSON.parse(await readFile(metaPath, 'utf8'))
        assert.match(meta.created, /^\d{4}-\d{2}-\d{2}T/)
        assert.equal(meta.handle, 'api-root')
        assert.equal(meta.description, 'Root capability for the demo API')
      } finally {
        await rm(walletDir, { recursive: true })
      }
    })

    it('--handle and --description require --save', async () => {
      await makeZcapCommand().parseAsync(
        [
          'create',
          '--controller',
          'did:key:z6MkController',
          '--url',
          'https://example.com/api',
          '--handle',
          'api-root'
        ],
        { from: 'user' }
      )
      assert.equal(exitCode, 1)
      assert.ok(errors.some(line => line.includes('require --save')))
    })
  })

  describe('delegate', () => {
    it('delegates from a stored DID (--did) with allowed actions', async () => {
      const didsDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.DIDS_DIR = didsDir
      try {
        const { did } = await createStoredDid(didsDir)
        const { did: delegatee } = await createStoredDid(didsDir)

        await makeZcapCommand().parseAsync(
          [
            'delegate',
            '--did',
            did,
            '--delegatee',
            delegatee,
            '--url',
            'https://example.com/documents',
            '--allow',
            'read'
          ],
          { from: 'user' }
        )

        assert.equal(exitCode, undefined, errors.join('\n'))
        const { delegatedCapability, encoded } = JSON.parse(logs[0])
        assert.equal(delegatedCapability.controller, delegatee)
        assert.equal(
          delegatedCapability.invocationTarget,
          'https://example.com/documents'
        )
        assert.deepEqual(delegatedCapability.allowedAction, ['read'])
        assert.equal(
          delegatedCapability.proof.proofPurpose,
          'capabilityDelegation'
        )
        assert.ok(Date.parse(delegatedCapability.expires) > Date.now())
        assert.deepEqual(decodeCapability(encoded), delegatedCapability)
      } finally {
        await rm(didsDir, { recursive: true })
      }
    })

    it('delegates via ZCAP_CONTROLLER_KEY_SEED + --controller', async () => {
      const didsDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.DIDS_DIR = didsDir
      try {
        const { did, seed } = await createStoredDid(didsDir)
        const { did: delegatee } = await createStoredDid(didsDir)
        process.env.ZCAP_CONTROLLER_KEY_SEED = seed

        await makeZcapCommand().parseAsync(
          [
            'delegate',
            '--controller',
            did,
            '--delegatee',
            delegatee,
            '--url',
            'https://example.com/documents',
            '--allow',
            'read'
          ],
          { from: 'user' }
        )

        assert.equal(exitCode, undefined, errors.join('\n'))
        const { delegatedCapability } = JSON.parse(logs[0])
        assert.equal(delegatedCapability.controller, delegatee)
        assert.equal(
          delegatedCapability.proof.proofPurpose,
          'capabilityDelegation'
        )
      } finally {
        await rm(didsDir, { recursive: true })
      }
    })

    it('errors when --controller does not match the seed-derived DID', async () => {
      const didsDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.DIDS_DIR = didsDir
      try {
        const { seed } = await createStoredDid(didsDir)
        const { did: delegatee } = await createStoredDid(didsDir)
        process.env.ZCAP_CONTROLLER_KEY_SEED = seed

        await makeZcapCommand().parseAsync(
          [
            'delegate',
            '--controller',
            'did:key:z6MkWrongController',
            '--delegatee',
            delegatee,
            '--url',
            'https://example.com/documents'
          ],
          { from: 'user' }
        )

        assert.equal(exitCode, 1)
        assert.ok(errors.some(line => line.includes('does not match')))
      } finally {
        await rm(didsDir, { recursive: true })
      }
    })

    it('--save --handle writes a metadata sidecar (type delegated)', async () => {
      const didsDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      const walletDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.DIDS_DIR = didsDir
      process.env.WALLET_DIR = walletDir
      try {
        const { did } = await createStoredDid(didsDir)
        const { did: delegatee } = await createStoredDid(didsDir)

        await makeZcapCommand().parseAsync(
          [
            'delegate',
            '--did',
            did,
            '--delegatee',
            delegatee,
            '--url',
            'https://example.com/documents',
            '--save',
            '--handle',
            'docs-read'
          ],
          { from: 'user' }
        )

        assert.equal(exitCode, undefined, errors.join('\n'))
        const saveLine = errors.find(line =>
          line.startsWith('Capability saved to ')
        ) as string
        const filePath = saveLine.slice('Capability saved to '.length)
        const metaPath = filePath.replace(/\.json$/, '.meta.json')
        const meta = JSON.parse(await readFile(metaPath, 'utf8'))
        assert.equal(meta.handle, 'docs-read')
        logs.length = 0

        await makeZcapCommand().parseAsync(['list', '--json'], { from: 'user' })
        const parsed = JSON.parse(logs[0])
        assert.equal(parsed.length, 1)
        assert.equal(parsed[0].type, 'delegated')
        assert.equal(parsed[0].handle, 'docs-read')
      } finally {
        await rm(didsDir, { recursive: true })
        await rm(walletDir, { recursive: true })
      }
    })
  })

  describe('list', () => {
    it('prints nothing when no zcaps are stored', async () => {
      const walletDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.WALLET_DIR = walletDir
      try {
        await makeZcapCommand().parseAsync(['list'], { from: 'user' })
        assert.equal(logs.length, 0)
      } finally {
        await rm(walletDir, { recursive: true })
      }
    })

    it('prints nothing when the wallet has never been created', async () => {
      const walletDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      await rm(walletDir, { recursive: true })
      process.env.WALLET_DIR = walletDir
      await makeZcapCommand().parseAsync(['list'], { from: 'user' })
      assert.equal(logs.length, 0)
    })

    it('--plain prints capability ids, one per line, sorted', async () => {
      const walletDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.WALLET_DIR = walletDir
      try {
        for (const url of ['https://example.com/b', 'https://example.com/a']) {
          await makeZcapCommand().parseAsync(
            [
              'create',
              '--controller',
              'did:key:z6MkController',
              '--url',
              url,
              '--save'
            ],
            { from: 'user' }
          )
        }
        logs.length = 0
        errors.length = 0

        await makeZcapCommand().parseAsync(['list', '--plain'], {
          from: 'user'
        })

        assert.deepEqual(logs, [
          'urn:zcap:root:https%3A%2F%2Fexample.com%2Fa',
          'urn:zcap:root:https%3A%2F%2Fexample.com%2Fb'
        ])
      } finally {
        await rm(walletDir, { recursive: true })
      }
    })

    it('prints a metadata table by default', async () => {
      const walletDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.WALLET_DIR = walletDir
      try {
        await makeZcapCommand().parseAsync(
          [
            'create',
            '--controller',
            'did:key:z6MkController',
            '--url',
            'https://example.com/api',
            '--save',
            '--handle',
            'api-root',
            '--description',
            'Demo API root'
          ],
          { from: 'user' }
        )
        logs.length = 0
        errors.length = 0

        await makeZcapCommand().parseAsync(['list'], { from: 'user' })

        assert.equal(logs.length, 1)
        const [header, separator, row] = logs[0].split('\n')
        assert.match(header, /^HANDLE\s+TYPE\s+CREATED\s+ID\s+DESCRIPTION$/)
        assert.match(separator, /^-+(\s+-+)+$/)
        assert.match(
          row,
          /^api-root\s+root\s+\d{4}-\d{2}-\d{2}\s+urn:zcap:root:/
        )
        assert.match(row, /Demo API root$/)
      } finally {
        await rm(walletDir, { recursive: true })
      }
    })

    it('--json outputs an array of objects with metadata', async () => {
      const walletDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.WALLET_DIR = walletDir
      try {
        await makeZcapCommand().parseAsync(
          [
            'create',
            '--controller',
            'did:key:z6MkController',
            '--url',
            'https://example.com/api',
            '--save',
            '--handle',
            'api-root'
          ],
          { from: 'user' }
        )
        logs.length = 0
        errors.length = 0

        await makeZcapCommand().parseAsync(['list', '--json'], { from: 'user' })

        const parsed = JSON.parse(logs[0])
        assert.equal(parsed.length, 1)
        assert.equal(
          parsed[0].id,
          'urn:zcap:root:https%3A%2F%2Fexample.com%2Fapi'
        )
        assert.equal(parsed[0].type, 'root')
        assert.equal(parsed[0].handle, 'api-root')
        assert.match(parsed[0].created, /^\d{4}-\d{2}-\d{2}T/)
        assert.equal(parsed[0].description, undefined)
      } finally {
        await rm(walletDir, { recursive: true })
      }
    })
  })

  describe('show', () => {
    it('prints the stored zcap by capability id', async () => {
      const walletDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.WALLET_DIR = walletDir
      try {
        const zcapId = await createSavedRootZcap({
          url: 'https://example.com/api'
        })
        logs.length = 0
        errors.length = 0

        await makeZcapCommand().parseAsync(['show', zcapId], { from: 'user' })

        const parsed = JSON.parse(logs[0])
        assert.equal(parsed.id, zcapId)
        assert.equal(parsed.controller, 'did:key:z6MkController')
        assert.equal(parsed.invocationTarget, 'https://example.com/api')
      } finally {
        await rm(walletDir, { recursive: true })
      }
    })

    it('accepts a metadata handle', async () => {
      const walletDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.WALLET_DIR = walletDir
      try {
        const zcapId = await createSavedRootZcap({
          url: 'https://example.com/api',
          handle: 'api-root'
        })
        logs.length = 0
        errors.length = 0

        await makeZcapCommand().parseAsync(['show', 'api-root'], {
          from: 'user'
        })

        assert.equal(JSON.parse(logs[0]).id, zcapId)
      } finally {
        await rm(walletDir, { recursive: true })
      }
    })

    it('--meta prints a field/value table of the metadata', async () => {
      const walletDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.WALLET_DIR = walletDir
      try {
        await createSavedRootZcap({
          url: 'https://example.com/api',
          handle: 'api-root',
          description: 'Demo API root'
        })
        logs.length = 0
        errors.length = 0

        await makeZcapCommand().parseAsync(['show', 'api-root', '--meta'], {
          from: 'user'
        })

        assert.equal(logs.length, 1)
        const [header, , ...rows] = logs[0].split('\n')
        assert.match(header, /^FIELD\s+VALUE$/)
        const fields = Object.fromEntries(
          rows.map(row => {
            const [field, ...value] = row.split(/\s{2,}/)
            return [field, value.join('  ')]
          })
        )
        assert.equal(fields.ID, 'urn:zcap:root:https%3A%2F%2Fexample.com%2Fapi')
        assert.equal(fields.Type, 'root')
        assert.equal(fields.Handle, 'api-root')
        assert.match(fields.Created, /^\d{4}-\d{2}-\d{2}T/)
        assert.equal(fields.Description, 'Demo API root')
        assert.equal(fields.Controller, 'did:key:z6MkController')
        assert.equal(fields.Target, 'https://example.com/api')
      } finally {
        await rm(walletDir, { recursive: true })
      }
    })

    it('--meta --json prints the metadata as JSON', async () => {
      const walletDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.WALLET_DIR = walletDir
      try {
        const zcapId = await createSavedRootZcap({
          url: 'https://example.com/api',
          handle: 'api-root'
        })
        logs.length = 0
        errors.length = 0

        await makeZcapCommand().parseAsync(
          ['show', 'api-root', '--meta', '--json'],
          { from: 'user' }
        )

        const parsed = JSON.parse(logs[0])
        assert.equal(parsed.id, zcapId)
        assert.equal(parsed.type, 'root')
        assert.equal(parsed.handle, 'api-root')
        assert.match(parsed.created, /^\d{4}-\d{2}-\d{2}T/)
        assert.equal(parsed.controller, 'did:key:z6MkController')
        assert.equal(parsed.invocationTarget, 'https://example.com/api')
        assert.equal(parsed.description, undefined)
      } finally {
        await rm(walletDir, { recursive: true })
      }
    })

    it('exits 1 when no stored zcap matches', async () => {
      const walletDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.WALLET_DIR = walletDir
      try {
        await makeZcapCommand().parseAsync(['show', 'nope'], { from: 'user' })

        assert.equal(exitCode, 1)
        assert.ok(
          errors.some(line =>
            line.includes('No locally stored zcap found for nope')
          )
        )
      } finally {
        await rm(walletDir, { recursive: true })
      }
    })
  })

  describe('meta', () => {
    it('prints the current metadata with no options', async () => {
      const walletDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.WALLET_DIR = walletDir
      try {
        const zcapId = await createSavedRootZcap({
          url: 'https://example.com/api',
          handle: 'api-root'
        })
        logs.length = 0
        errors.length = 0

        await makeZcapCommand().parseAsync(['meta', zcapId], { from: 'user' })

        const parsed = JSON.parse(logs[0])
        assert.equal(parsed.handle, 'api-root')
        assert.match(parsed.created, /^\d{4}-\d{2}-\d{2}T/)
      } finally {
        await rm(walletDir, { recursive: true })
      }
    })

    it('--handle / --description update the metadata sidecar', async () => {
      const walletDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.WALLET_DIR = walletDir
      try {
        const zcapId = await createSavedRootZcap({
          url: 'https://example.com/api'
        })
        logs.length = 0
        errors.length = 0

        await makeZcapCommand().parseAsync(
          ['meta', zcapId, '--handle', 'api-root', '--description', 'Demo'],
          { from: 'user' }
        )

        assert.ok(errors[0].startsWith('Metadata saved to '))
        const metaPath = errors[0].slice('Metadata saved to '.length)
        const saved = JSON.parse(await readFile(metaPath, 'utf8'))
        assert.equal(saved.handle, 'api-root')
        assert.equal(saved.description, 'Demo')
        assert.match(saved.created, /^\d{4}-\d{2}-\d{2}T/)
        assert.deepEqual(JSON.parse(logs[0]), saved)
      } finally {
        await rm(walletDir, { recursive: true })
      }
    })

    it('an empty string clears a field', async () => {
      const walletDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.WALLET_DIR = walletDir
      try {
        const zcapId = await createSavedRootZcap({
          url: 'https://example.com/api',
          handle: 'api-root',
          description: 'Demo'
        })
        logs.length = 0
        errors.length = 0

        await makeZcapCommand().parseAsync(['meta', zcapId, '--handle', ''], {
          from: 'user'
        })

        const saved = JSON.parse(logs[0])
        assert.equal(saved.handle, undefined)
        assert.equal(saved.description, 'Demo')
      } finally {
        await rm(walletDir, { recursive: true })
      }
    })

    it('exits 1 when no stored zcap matches', async () => {
      const walletDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.WALLET_DIR = walletDir
      try {
        await makeZcapCommand().parseAsync(['meta', 'nope'], { from: 'user' })

        assert.equal(exitCode, 1)
        assert.ok(
          errors.some(line =>
            line.includes('No locally stored zcap found for nope')
          )
        )
      } finally {
        await rm(walletDir, { recursive: true })
      }
    })
  })

  describe('remove', () => {
    it('removes the zcap file and its metadata sidecar', async () => {
      const walletDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.WALLET_DIR = walletDir
      try {
        await createSavedRootZcap({
          url: 'https://example.com/api',
          handle: 'api-root'
        })
        const filePath = errors[0].slice('Capability saved to '.length)
        const metaPath = filePath.replace(/\.json$/, '.meta.json')
        logs.length = 0
        errors.length = 0

        await makeZcapCommand().parseAsync(['remove', 'api-root'], {
          from: 'user'
        })

        assert.equal(exitCode, undefined, errors.join('\n'))
        assert.deepEqual(errors, [`Removed ${filePath}`, `Removed ${metaPath}`])
        await assert.rejects(readFile(filePath))
        await assert.rejects(readFile(metaPath))

        errors.length = 0
        await makeZcapCommand().parseAsync(['list', '--plain'], {
          from: 'user'
        })
        assert.equal(logs.length, 0)
      } finally {
        await rm(walletDir, { recursive: true })
      }
    })

    it('also accepts the capability id and the delete/rm aliases', async () => {
      const walletDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.WALLET_DIR = walletDir
      try {
        const zcapId = await createSavedRootZcap({
          url: 'https://example.com/api'
        })
        logs.length = 0
        errors.length = 0

        await makeZcapCommand().parseAsync(['delete', zcapId], {
          from: 'user'
        })

        assert.equal(exitCode, undefined, errors.join('\n'))
        assert.ok(errors[0].startsWith('Removed '))
      } finally {
        await rm(walletDir, { recursive: true })
      }
    })

    it('exits 1 when no stored zcap matches', async () => {
      const walletDir = await mkdtemp(join(tmpdir(), 'did-cli-test-'))
      process.env.WALLET_DIR = walletDir
      try {
        await makeZcapCommand().parseAsync(['remove', 'nope'], { from: 'user' })

        assert.equal(exitCode, 1)
        assert.ok(
          errors.some(line =>
            line.includes('No locally stored zcap found for nope')
          )
        )
      } finally {
        await rm(walletDir, { recursive: true })
      }
    })
  })

  describe('stubs', () => {
    it('routes revoke', () => {
      makeZcapCommand().parse(['revoke', 'zcap-id-123'], { from: 'user' })
      assert.ok(logs[0].includes('zcap-id-123'))
    })
  })
})
