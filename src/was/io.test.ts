import { describe, it, afterEach, mock } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { Readable } from 'node:stream'
import {
  readInputBytes,
  readPayload,
  writeBytesOutput,
  writeResourceOutput
} from './io.js'

describe('was io helpers', () => {
  let tempDir: string | undefined

  afterEach(async () => {
    mock.restoreAll()
    if (tempDir) {
      await rm(tempDir, { recursive: true, force: true })
      tempDir = undefined
    }
  })

  async function makeTempFile(name: string, content: string | Buffer) {
    tempDir = tempDir ?? (await mkdtemp(join(tmpdir(), 'did-cli-test-io-')))
    const filePath = join(tempDir, name)
    await writeFile(filePath, content)
    return filePath
  }

  describe('readPayload', () => {
    it('parses a .json file as a JSON payload', async () => {
      const filePath = await makeTempFile('vc.json', '{"name": "Alice"}')
      const payload = await readPayload({ file: filePath })
      assert.deepEqual(payload, { data: { name: 'Alice' } })
    })

    it('rejects a .json file that is not JSON', async () => {
      const filePath = await makeTempFile('bad.json', 'not json')
      await assert.rejects(
        readPayload({ file: filePath }),
        /does not contain a JSON object or array/
      )
    })

    it('rejects a .json file holding a JSON primitive', async () => {
      const filePath = await makeTempFile('prim.json', '42')
      await assert.rejects(
        readPayload({ file: filePath }),
        /does not contain a JSON object or array/
      )
    })

    it('sniffs JSON content in files without a .json extension', async () => {
      const filePath = await makeTempFile('data.txt', '[1, 2, 3]')
      const payload = await readPayload({ file: filePath })
      assert.deepEqual(payload, { data: [1, 2, 3] })
    })

    it('treats non-JSON content as binary octet-stream', async () => {
      const filePath = await makeTempFile('notes.txt', 'hello world')
      const payload = await readPayload({ file: filePath })
      assert.ok(payload.data instanceof Uint8Array)
      assert.equal(
        Buffer.from(payload.data as Uint8Array).toString(),
        'hello world'
      )
      assert.equal(payload.contentType, 'application/octet-stream')
    })

    it('treats invalid UTF-8 as binary', async () => {
      const filePath = await makeTempFile(
        'pixels.bin',
        Buffer.from([0xff, 0xfe, 0x00, 0x89])
      )
      const payload = await readPayload({ file: filePath })
      assert.ok(payload.data instanceof Uint8Array)
      assert.equal(payload.contentType, 'application/octet-stream')
    })

    it('an explicit content type wins over JSON detection', async () => {
      const filePath = await makeTempFile('vc.json', '{"name": "Alice"}')
      const payload = await readPayload({
        file: filePath,
        contentType: 'application/ld+json'
      })
      assert.ok(payload.data instanceof Uint8Array)
      assert.equal(payload.contentType, 'application/ld+json')
      assert.equal(
        Buffer.from(payload.data as Uint8Array).toString(),
        '{"name": "Alice"}'
      )
    })

    it('reads stdin when no file is given', async () => {
      const stdin = Readable.from([Buffer.from('{"from": "stdin"}')])
      const payload = await readPayload({ stdin })
      assert.deepEqual(payload, { data: { from: 'stdin' } })
    })

    it('sniffs binary stdin input', async () => {
      const stdin = Readable.from([Buffer.from('plain text')])
      const payload = await readPayload({ stdin })
      assert.ok(payload.data instanceof Uint8Array)
      assert.equal(payload.contentType, 'application/octet-stream')
    })
  })

  describe('readInputBytes', () => {
    it('reads a file as raw bytes', async () => {
      const filePath = await makeTempFile(
        'space.tar',
        Buffer.from([0x75, 0x73, 0x74, 0x61, 0x72])
      )
      const bytes = await readInputBytes({ file: filePath })
      assert.ok(bytes instanceof Uint8Array)
      assert.deepEqual(
        Buffer.from(bytes),
        Buffer.from([0x75, 0x73, 0x74, 0x61, 0x72])
      )
    })

    it('reads stdin when no file is given', async () => {
      const stdin = Readable.from([Buffer.from('tar bytes')])
      const bytes = await readInputBytes({ stdin })
      assert.equal(Buffer.from(bytes).toString(), 'tar bytes')
    })
  })

  describe('writeBytesOutput', () => {
    it('writes bytes to an output file with a stderr note', async () => {
      const notes: string[] = []
      mock.method(console, 'error', (...args: unknown[]) =>
        notes.push(args.join(' '))
      )
      tempDir = await mkdtemp(join(tmpdir(), 'did-cli-test-io-'))
      const output = join(tempDir, 'out.tar')
      await writeBytesOutput({ bytes: new Uint8Array([1, 2, 3]), output })
      assert.deepEqual(await readFile(output), Buffer.from([1, 2, 3]))
      assert.deepEqual(notes, [`Wrote 3 bytes to ${output}`])
    })

    it('writes bytes raw to stdout when no output is given', async () => {
      const written: Uint8Array[] = []
      mock.method(process.stdout, 'write', (chunk: Uint8Array): boolean => {
        written.push(chunk)
        return true
      })
      await writeBytesOutput({ bytes: new Uint8Array([4, 5]) })
      assert.deepEqual(Buffer.concat(written), Buffer.from([4, 5]))
    })
  })

  describe('writeResourceOutput', () => {
    it('pretty-prints JSON to stdout', async () => {
      const logs: string[] = []
      mock.method(console, 'log', (...args: unknown[]) =>
        logs.push(args.join(' '))
      )
      await writeResourceOutput({ data: { name: 'Alice' } })
      assert.deepEqual(logs, ['{\n  "name": "Alice"\n}'])
    })

    it('writes JSON to an output file', async () => {
      tempDir = await mkdtemp(join(tmpdir(), 'did-cli-test-io-'))
      const output = join(tempDir, 'out.json')
      await writeResourceOutput({ data: [1, 2], output })
      assert.equal(await readFile(output, 'utf8'), '[\n  1,\n  2\n]\n')
    })

    it('writes binary content raw to an output file', async () => {
      tempDir = await mkdtemp(join(tmpdir(), 'did-cli-test-io-'))
      const output = join(tempDir, 'out.bin')
      const blob = new Blob([Buffer.from([1, 2, 3])], {
        type: 'application/octet-stream'
      })
      await writeResourceOutput({ data: blob, output })
      assert.deepEqual(await readFile(output), Buffer.from([1, 2, 3]))
    })

    it('writes binary content raw to stdout when no output is given', async () => {
      const written: Uint8Array[] = []
      mock.method(process.stdout, 'write', (chunk: Uint8Array): boolean => {
        written.push(chunk)
        return true
      })
      const blob = new Blob([Buffer.from('raw bytes')])
      await writeResourceOutput({ data: blob })
      assert.equal(Buffer.concat(written).toString(), 'raw bytes')
    })
  })
})
