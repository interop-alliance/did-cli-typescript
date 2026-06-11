import { describe, it, beforeEach, afterEach, mock } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { makeWalletCommand } from './wallet.js'

describe('wallet ls', () => {
  let logs: string[]
  let walletDir: string

  beforeEach(async () => {
    logs = []
    mock.method(console, 'log', (...args: unknown[]) =>
      logs.push(args.join(' '))
    )
    walletDir = await mkdtemp(join(tmpdir(), 'did-cli-wallet-test-'))
    process.env.WALLET_DIR = walletDir
  })

  afterEach(async () => {
    mock.restoreAll()
    delete process.env.WALLET_DIR
    await rm(walletDir, { recursive: true })
  })

  /**
   * Seeds the temp wallet dir with one key (plus its metadata sidecar,
   * which must not be counted), two DIDs, and one credential.
   */
  async function seedWallet(): Promise<void> {
    const keysDir = join(walletDir, 'keys')
    await mkdir(keysDir, { recursive: true })
    await writeFile(join(keysDir, 'key-1.json'), '{}', 'utf8')
    await writeFile(join(keysDir, 'key-1.meta.json'), '{}', 'utf8')
    const didsDir = join(walletDir, 'dids', 'key')
    await mkdir(didsDir, { recursive: true })
    await writeFile(join(didsDir, 'did_key_z6MkOne.json'), '{}', 'utf8')
    await writeFile(join(didsDir, 'did_key_z6MkOne.keys.json'), '{}', 'utf8')
    await writeFile(join(didsDir, 'did_key_z6MkTwo.json'), '{}', 'utf8')
    const credentialsDir = join(walletDir, 'credentials')
    await mkdir(credentialsDir, { recursive: true })
    await writeFile(join(credentialsDir, 'vc-1.json'), '{}', 'utf8')
  }

  it('prints zero counts for an empty wallet', async () => {
    await makeWalletCommand().parseAsync(['ls'], { from: 'user' })
    assert.deepEqual(logs, [
      'keys: 0',
      'dids: 0',
      'zcaps: 0',
      'vcs: 0',
      'spaces: 0'
    ])
  })

  it('counts items per collection, excluding sidecar files', async () => {
    await seedWallet()
    await makeWalletCommand().parseAsync(['ls'], { from: 'user' })
    assert.deepEqual(logs, [
      'keys: 1',
      'dids: 2',
      'zcaps: 0',
      'vcs: 1',
      'spaces: 0'
    ])
  })

  it('--json outputs the counts as a JSON object', async () => {
    await seedWallet()
    await makeWalletCommand().parseAsync(['ls', '--json'], { from: 'user' })
    assert.deepEqual(JSON.parse(logs.join('\n')), {
      keys: 1,
      dids: 2,
      zcaps: 0,
      vcs: 1,
      spaces: 0
    })
  })

  it('supports the list alias', async () => {
    await makeWalletCommand().parseAsync(['list'], { from: 'user' })
    assert.equal(logs[0], 'keys: 0')
  })
})
