import { describe, it, beforeEach, afterEach, mock } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { makeEdvCommand } from './edv.js'
import { makeKeyCommand } from './key.js'
import { makeDidCommand } from './did.js'

describe('edv', () => {
  let logs: string[]
  let errors: string[]
  let exitCode: number | undefined
  let walletDir: string
  let didsDir: string

  beforeEach(async () => {
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
    walletDir = await mkdtemp(join(tmpdir(), 'edv-wallet-'))
    didsDir = await mkdtemp(join(tmpdir(), 'edv-dids-'))
    process.env.WALLET_DIR = walletDir
    process.env.DIDS_DIR = didsDir
  })

  afterEach(async () => {
    mock.restoreAll()
    delete process.env.WALLET_DIR
    delete process.env.DIDS_DIR
    await rm(walletDir, { recursive: true, force: true })
    await rm(didsDir, { recursive: true, force: true })
  })

  /**
   * Create a saved x25519 wallet key and return its exported key object
   * (including publicKeyMultibase). Clears the captured output arrays first so
   * the key JSON is `logs[0]`.
   */
  async function createX25519Key(): Promise<{
    type: string
    publicKeyMultibase: string
    privateKeyMultibase: string
  }> {
    logs.length = 0
    errors.length = 0
    await makeKeyCommand().parseAsync(
      ['create', '--type', 'x25519', '--save'],
      { from: 'user' }
    )
    return JSON.parse(logs[0])
  }

  it('round-trips a JSON object encrypted to a wallet key', async () => {
    const key = await createX25519Key()
    const inputPath = join(walletDir, 'in.json')
    const jwePath = join(walletDir, 'out.jwe.json')
    await writeFile(inputPath, JSON.stringify({ hello: 'world', n: 42 }))

    await makeEdvCommand().parseAsync(
      [
        'encrypt',
        inputPath,
        '--json',
        '-r',
        key.publicKeyMultibase,
        '-o',
        jwePath
      ],
      { from: 'user' }
    )
    assert.equal(exitCode, undefined)

    logs.length = 0
    await makeEdvCommand().parseAsync(['decrypt', jwePath, '--json'], {
      from: 'user'
    })
    assert.equal(exitCode, undefined)
    assert.deepEqual(JSON.parse(logs.join('\n')), { hello: 'world', n: 42 })
  })

  it('produces a JWE with the expected shape and recipient header', async () => {
    const key = await createX25519Key()
    const inputPath = join(walletDir, 'in.json')
    await writeFile(inputPath, JSON.stringify({ a: 1 }))

    logs.length = 0
    await makeEdvCommand().parseAsync(
      ['encrypt', inputPath, '--json', '-r', key.publicKeyMultibase],
      { from: 'user' }
    )
    const jwe = JSON.parse(logs.join('\n'))
    for (const field of [
      'protected',
      'recipients',
      'iv',
      'ciphertext',
      'tag'
    ]) {
      assert.ok(jwe[field] !== undefined, `JWE is missing "${field}"`)
    }
    assert.equal(jwe.recipients.length, 1)
    assert.equal(jwe.recipients[0].header.alg, 'ECDH-ES+A256KW')
    assert.equal(
      jwe.recipients[0].header.kid,
      `did:key:${key.publicKeyMultibase}#${key.publicKeyMultibase}`
    )
  })

  it('encrypts to multiple recipients and each can decrypt', async () => {
    const keyA = await createX25519Key()
    const keyB = await createX25519Key()
    const inputPath = join(walletDir, 'in.json')
    const jwePath = join(walletDir, 'out.jwe.json')
    await writeFile(inputPath, JSON.stringify({ shared: true }))

    await makeEdvCommand().parseAsync(
      [
        'encrypt',
        inputPath,
        '--json',
        '-r',
        keyA.publicKeyMultibase,
        '-r',
        keyB.publicKeyMultibase,
        '-o',
        jwePath
      ],
      { from: 'user' }
    )
    const jwe = JSON.parse(await readFile(jwePath, 'utf8'))
    assert.equal(jwe.recipients.length, 2)

    for (const key of [keyA, keyB]) {
      logs.length = 0
      exitCode = undefined
      await makeEdvCommand().parseAsync(
        ['decrypt', jwePath, '--json', '--key', key.publicKeyMultibase],
        { from: 'user' }
      )
      assert.equal(exitCode, undefined)
      assert.deepEqual(JSON.parse(logs.join('\n')), { shared: true })
    }
  })

  it('round-trips raw bytes without --json', async () => {
    const key = await createX25519Key()
    const inputPath = join(walletDir, 'in.bin')
    const jwePath = join(walletDir, 'out.jwe.json')
    const plaintextPath = join(walletDir, 'plain.out')
    const bytes = Buffer.from([0x00, 0x01, 0xff, 0xfe, 0x7f, 0x80])
    await writeFile(inputPath, bytes)

    await makeEdvCommand().parseAsync(
      ['encrypt', inputPath, '-r', key.publicKeyMultibase, '-o', jwePath],
      { from: 'user' }
    )
    await makeEdvCommand().parseAsync(
      ['decrypt', jwePath, '-o', plaintextPath],
      { from: 'user' }
    )
    assert.deepEqual(await readFile(plaintextPath), bytes)
  })

  it('accepts a recipient from a key-document file', async () => {
    const key = await createX25519Key()
    const keyDocPath = join(walletDir, 'recipient.json')
    await writeFile(
      keyDocPath,
      JSON.stringify({
        type: key.type,
        publicKeyMultibase: key.publicKeyMultibase
      })
    )
    const inputPath = join(walletDir, 'in.json')
    const jwePath = join(walletDir, 'out.jwe.json')
    await writeFile(inputPath, JSON.stringify({ via: 'file' }))

    await makeEdvCommand().parseAsync(
      [
        'encrypt',
        inputPath,
        '--json',
        '--recipient-file',
        keyDocPath,
        '-o',
        jwePath
      ],
      { from: 'user' }
    )
    logs.length = 0
    await makeEdvCommand().parseAsync(['decrypt', jwePath, '--json'], {
      from: 'user'
    })
    assert.deepEqual(JSON.parse(logs.join('\n')), { via: 'file' })
  })

  it('resolves a DID-URL recipient through the document loader', async () => {
    // Create an ed25519 did:key and reference its verification method by URL.
    // The signing key is not a key-agreement key, so resolution (via the
    // security document loader) must dereference the fragment and reject it.
    logs.length = 0
    await makeDidCommand().parseAsync(['create', '--save'], { from: 'user' })
    const vmId = JSON.parse(logs[0]).didDocument.verificationMethod[0].id
    const inputPath = join(walletDir, 'in.json')
    await writeFile(inputPath, JSON.stringify({ a: 1 }))

    await makeEdvCommand().parseAsync(
      ['encrypt', inputPath, '--json', '-r', vmId],
      { from: 'user' }
    )
    assert.equal(exitCode, 2)
    assert.ok(errors.join('\n').includes('X25519KeyAgreementKey2020'))
  })

  it('fails with a clear error when no recipient is given', async () => {
    const inputPath = join(walletDir, 'in.json')
    await writeFile(inputPath, JSON.stringify({ a: 1 }))
    await makeEdvCommand().parseAsync(['encrypt', inputPath, '--json'], {
      from: 'user'
    })
    assert.equal(exitCode, 2)
    assert.ok(errors.join('\n').includes('recipient'))
  })

  it('round-trips an EDV Document envelope with --document', async () => {
    const key = await createX25519Key()
    const inputPath = join(walletDir, 'in.json')
    const docPath = join(walletDir, 'out.edvdoc.json')
    await writeFile(inputPath, JSON.stringify({ name: 'alice', age: 30 }))

    await makeEdvCommand().parseAsync(
      [
        'encrypt',
        inputPath,
        '--document',
        '-r',
        key.publicKeyMultibase,
        '--meta',
        JSON.stringify({ tag: 'demo' }),
        '-o',
        docPath
      ],
      { from: 'user' }
    )
    assert.equal(exitCode, undefined)

    const envelope = JSON.parse(await readFile(docPath, 'utf8'))
    assert.match(envelope.id, /^z[1-9A-HJ-NP-Za-km-z]+$/)
    assert.equal(envelope.sequence, 0)
    assert.deepEqual(envelope.indexed, [])
    assert.ok(envelope.jwe?.recipients?.length === 1)
    // content and meta are encrypted inside the jwe, not in the envelope.
    assert.equal(envelope.content, undefined)
    assert.equal(envelope.meta, undefined)

    logs.length = 0
    errors.length = 0
    // No --document flag on decrypt: the envelope is detected automatically.
    await makeEdvCommand().parseAsync(['decrypt', docPath], { from: 'user' })
    assert.equal(exitCode, undefined)
    assert.deepEqual(JSON.parse(logs.join('\n')), { name: 'alice', age: 30 })
    // meta is reported as a diagnostic on stderr.
    assert.ok(errors.join('\n').includes('"tag":"demo"'))
  })

  it('--update reuses the id, increments sequence, and merges recipients', async () => {
    const keyA = await createX25519Key()
    const keyB = await createX25519Key()
    const inputPath = join(walletDir, 'in.json')
    const v0Path = join(walletDir, 'v0.edvdoc.json')
    const v1Path = join(walletDir, 'v1.edvdoc.json')
    await writeFile(inputPath, JSON.stringify({ v: 0 }))

    await makeEdvCommand().parseAsync(
      [
        'encrypt',
        inputPath,
        '--document',
        '-r',
        keyA.publicKeyMultibase,
        '-o',
        v0Path
      ],
      { from: 'user' }
    )
    const v0 = JSON.parse(await readFile(v0Path, 'utf8'))

    await writeFile(inputPath, JSON.stringify({ v: 1 }))
    await makeEdvCommand().parseAsync(
      [
        'encrypt',
        inputPath,
        '--document',
        '-r',
        keyB.publicKeyMultibase,
        '--update',
        v0Path,
        '-o',
        v1Path
      ],
      { from: 'user' }
    )
    assert.equal(exitCode, undefined)

    const v1 = JSON.parse(await readFile(v1Path, 'utf8'))
    assert.equal(v1.id, v0.id)
    assert.equal(v1.sequence, 1)
    assert.equal(v1.jwe.recipients.length, 2)

    // The original recipient (keyA) and the added one (keyB) can both decrypt.
    for (const key of [keyA, keyB]) {
      logs.length = 0
      exitCode = undefined
      await makeEdvCommand().parseAsync(
        ['decrypt', v1Path, '--key', key.publicKeyMultibase],
        { from: 'user' }
      )
      assert.equal(exitCode, undefined)
      assert.deepEqual(JSON.parse(logs.join('\n')), { v: 1 })
    }
  })

  it('rejects --meta and --update without --document', async () => {
    const inputPath = join(walletDir, 'in.json')
    await writeFile(inputPath, JSON.stringify({ a: 1 }))
    await makeEdvCommand().parseAsync(
      ['encrypt', inputPath, '-r', 'z6LSdummy', '--meta', '{}'],
      { from: 'user' }
    )
    assert.equal(exitCode, 2)
    assert.ok(errors.join('\n').includes('--document'))
  })

  it('rejects --document decrypt on a bare JWE', async () => {
    const key = await createX25519Key()
    const inputPath = join(walletDir, 'in.json')
    const jwePath = join(walletDir, 'out.jwe.json')
    await writeFile(inputPath, JSON.stringify({ a: 1 }))
    await makeEdvCommand().parseAsync(
      [
        'encrypt',
        inputPath,
        '--json',
        '-r',
        key.publicKeyMultibase,
        '-o',
        jwePath
      ],
      { from: 'user' }
    )
    await makeEdvCommand().parseAsync(['decrypt', jwePath, '--document'], {
      from: 'user'
    })
    assert.equal(exitCode, 2)
    assert.ok(errors.join('\n').includes('not an EDV Document'))
  })

  it('returns the failure path when decrypting with a non-recipient key', async () => {
    const keyA = await createX25519Key()
    const keyB = await createX25519Key()
    const inputPath = join(walletDir, 'in.json')
    const jwePath = join(walletDir, 'out.jwe.json')
    await writeFile(inputPath, JSON.stringify({ secret: 1 }))

    await makeEdvCommand().parseAsync(
      [
        'encrypt',
        inputPath,
        '--json',
        '-r',
        keyA.publicKeyMultibase,
        '-o',
        jwePath
      ],
      { from: 'user' }
    )
    await makeEdvCommand().parseAsync(
      ['decrypt', jwePath, '--json', '--key', keyB.publicKeyMultibase],
      { from: 'user' }
    )
    assert.equal(exitCode, 1)
    assert.ok(errors.join('\n').toLowerCase().includes('decryption failed'))
  })

  it('round-trips a chunked stream bundle with --stream', async () => {
    const key = await createX25519Key()
    const inputPath = join(walletDir, 'big.bin')
    const bundlePath = join(walletDir, 'bundle.edvdoc')
    const outPath = join(walletDir, 'out.bin')
    // 2500 bytes at a 1000-byte chunk size => 3 chunks (ceil).
    const bytes = Buffer.alloc(2500)
    for (let index = 0; index < bytes.length; index++) {
      bytes[index] = (index * 7) % 256
    }
    await writeFile(inputPath, bytes)

    await makeEdvCommand().parseAsync(
      [
        'encrypt',
        inputPath,
        '--stream',
        '-r',
        key.publicKeyMultibase,
        '--chunk-size',
        '1000',
        '--meta',
        JSON.stringify({ name: 'big.bin' }),
        '-o',
        bundlePath
      ],
      { from: 'user' }
    )
    assert.equal(exitCode, undefined)

    const document = JSON.parse(
      await readFile(join(bundlePath, 'document.json'), 'utf8')
    )
    assert.match(document.id, /^z[1-9A-HJ-NP-Za-km-z]+$/)
    assert.equal(document.sequence, 0)
    assert.deepEqual(document.stream, { sequence: 0, chunks: 3 })

    const chunkFiles = (await readdir(join(bundlePath, 'chunks'))).filter(
      name => name.endsWith('.jwe.json')
    )
    assert.equal(chunkFiles.length, 3)
    const chunk0 = JSON.parse(
      await readFile(join(bundlePath, 'chunks', '0.jwe.json'), 'utf8')
    )
    assert.equal(chunk0.sequence, 0)
    assert.equal(chunk0.index, 0)
    assert.equal(chunk0.jwe.recipients[0].header.alg, 'ECDH-ES+A256KW')
    assert.equal(
      chunk0.jwe.recipients[0].header.kid,
      `did:key:${key.publicKeyMultibase}#${key.publicKeyMultibase}`
    )

    errors.length = 0
    await makeEdvCommand().parseAsync(['decrypt', bundlePath, '-o', outPath], {
      from: 'user'
    })
    assert.equal(exitCode, undefined)
    assert.deepEqual(await readFile(outPath), bytes)
    // meta and the stream descriptor are reported on stderr.
    assert.ok(errors.join('\n').includes('"name":"big.bin"'))
  })

  it('--stream requires -o/--out', async () => {
    const key = await createX25519Key()
    const inputPath = join(walletDir, 'big.bin')
    await writeFile(inputPath, Buffer.alloc(10))
    await makeEdvCommand().parseAsync(
      ['encrypt', inputPath, '--stream', '-r', key.publicKeyMultibase],
      { from: 'user' }
    )
    assert.equal(exitCode, 2)
    assert.ok(errors.join('\n').includes('-o'))
  })

  it('fails to decrypt a bundle with a non-recipient key', async () => {
    const keyA = await createX25519Key()
    const keyB = await createX25519Key()
    const inputPath = join(walletDir, 'big.bin')
    const bundlePath = join(walletDir, 'bundle.edvdoc')
    await writeFile(inputPath, Buffer.alloc(1500, 9))

    await makeEdvCommand().parseAsync(
      [
        'encrypt',
        inputPath,
        '--stream',
        '-r',
        keyA.publicKeyMultibase,
        '--chunk-size',
        '1000',
        '-o',
        bundlePath
      ],
      { from: 'user' }
    )
    await makeEdvCommand().parseAsync(
      ['decrypt', bundlePath, '--key', keyB.publicKeyMultibase],
      { from: 'user' }
    )
    assert.equal(exitCode, 1)
    assert.ok(errors.join('\n').toLowerCase().includes('decryption failed'))
  })
})
