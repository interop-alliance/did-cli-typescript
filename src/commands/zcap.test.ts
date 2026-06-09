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

    it('prints capability ids, one per line, sorted', async () => {
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

        await makeZcapCommand().parseAsync(['list'], { from: 'user' })

        assert.deepEqual(logs, [
          'urn:zcap:root:https%3A%2F%2Fexample.com%2Fa',
          'urn:zcap:root:https%3A%2F%2Fexample.com%2Fb'
        ])
      } finally {
        await rm(walletDir, { recursive: true })
      }
    })

    it('--json outputs the capability ids as a JSON array', async () => {
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
        logs.length = 0
        errors.length = 0

        await makeZcapCommand().parseAsync(['list', '--json'], { from: 'user' })

        assert.deepEqual(JSON.parse(logs[0]), [
          'urn:zcap:root:https%3A%2F%2Fexample.com%2Fapi'
        ])
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
