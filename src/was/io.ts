/**
 * Payload and output helpers for the `was resource` commands: reading write
 * payloads from a file or stdin with JSON-vs-binary detection, and writing
 * read results to stdout or an `--output` file.
 *
 * Detection rules: an explicit `--content-type` always wins and sends the
 * raw bytes with that type (so e.g. `application/ld+json` is preserved
 * exactly). Without it, a `*.json` file must parse as JSON and is sent as a
 * JSON payload; any other input is sniffed -- content that parses to a JSON
 * object or array is sent as JSON, everything else is sent as binary
 * `application/octet-stream`.
 */
import { readFile, writeFile } from 'node:fs/promises'
import type { Readable } from 'node:stream'
import type { Json } from '@interop/was-client'

const OCTET_STREAM = 'application/octet-stream'

/**
 * A resource write payload, resolved to either parsed JSON data or raw
 * binary bytes plus the content type to send them with.
 */
export interface ResourcePayload {
  data: Json | Uint8Array
  /** The content type of a binary payload (JSON payloads carry none). */
  contentType?: string
}

/**
 * Reads a whole stream (stdin) into a single byte buffer.
 *
 * @param stream {Readable}
 * @returns {Promise<Buffer>}
 */
async function readStream(stream: Readable): Promise<Buffer> {
  const chunks: Buffer[] = []
  for await (const chunk of stream) {
    chunks.push(chunk as Buffer)
  }
  return Buffer.concat(chunks)
}

/**
 * Parses bytes as a JSON object or array. Returns undefined when the bytes
 * are not valid UTF-8 JSON or parse to a primitive (which WAS resources do
 * not accept as JSON payloads).
 *
 * @param bytes {Buffer}
 * @returns {Json | undefined}
 */
function parseJsonPayload(bytes: Buffer): Json | undefined {
  let text: string
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes)
  } catch {
    return undefined
  }
  let parsed: Json
  try {
    parsed = JSON.parse(text) as Json
  } catch {
    return undefined
  }
  if (parsed === null || typeof parsed !== 'object') {
    return undefined
  }
  return parsed
}

/**
 * Reads a resource write payload from a file or stdin and resolves it to
 * JSON or binary form (see the module header for the detection rules).
 *
 * @param options {object}
 * @param [options.file] {string}   The input file path; stdin when omitted.
 * @param [options.contentType] {string}   Explicit content type: the bytes
 *   are sent as-is with this type, skipping JSON detection.
 * @param [options.stdin] {Readable}   The stdin stream (a test seam).
 * @returns {Promise<ResourcePayload>}
 */
export async function readPayload({
  file,
  contentType,
  stdin = process.stdin
}: {
  file?: string
  contentType?: string
  stdin?: Readable
} = {}): Promise<ResourcePayload> {
  const bytes = file ? await readFile(file) : await readStream(stdin)

  if (contentType) {
    return { data: new Uint8Array(bytes), contentType }
  }

  const parsed = parseJsonPayload(bytes)
  if (file?.endsWith('.json')) {
    if (parsed === undefined) {
      throw new Error(`${file} does not contain a JSON object or array.`)
    }
    return { data: parsed }
  }
  if (parsed !== undefined) {
    return { data: parsed }
  }
  return { data: new Uint8Array(bytes), contentType: OCTET_STREAM }
}

/**
 * Reads raw bytes from a file or stdin, without any payload detection.
 * Used for opaque pass-through content such as space export/import tars.
 *
 * @param options {object}
 * @param [options.file] {string}   The input file path; stdin when omitted.
 * @param [options.stdin] {Readable}   The stdin stream (a test seam).
 * @returns {Promise<Uint8Array>}
 */
export async function readInputBytes({
  file,
  stdin = process.stdin
}: {
  file?: string
  stdin?: Readable
} = {}): Promise<Uint8Array> {
  const bytes = file ? await readFile(file) : await readStream(stdin)
  return new Uint8Array(bytes)
}

/**
 * Writes raw bytes to an output file (with a byte-count note on stderr) or
 * raw to stdout when no file is given. Used for opaque pass-through
 * content such as space export tars.
 *
 * @param options {object}
 * @param options.bytes {Uint8Array}
 * @param [options.output] {string}   The output file path; stdout when
 *   omitted.
 * @returns {Promise<void>}
 */
export async function writeBytesOutput({
  bytes,
  output
}: {
  bytes: Uint8Array
  output?: string
}): Promise<void> {
  if (output) {
    await writeFile(output, bytes)
    console.error(`Wrote ${bytes.length} bytes to ${output}`)
    return
  }
  process.stdout.write(bytes)
}

/**
 * Pretty-prints a value as JSON to an output file (with a `Wrote <file>` note
 * on stderr) or to stdout when no file is given.
 *
 * @param options {object}
 * @param options.value {unknown}   The value to serialize.
 * @param [options.output] {string}   The output file path; stdout when
 *   omitted.
 * @returns {Promise<void>}
 */
export async function writeJsonOutput({
  value,
  output
}: {
  value: unknown
  output?: string
}): Promise<void> {
  const text = JSON.stringify(value, null, 2)
  if (output) {
    await writeFile(output, `${text}\n`, 'utf8')
    console.error(`Wrote ${output}`)
    return
  }
  console.log(text)
}

/**
 * Writes a resource read result: JSON is pretty-printed to stdout (or
 * written to the `--output` file); binary content is written raw to the
 * `--output` file, or to stdout when none is given.
 *
 * @param options {object}
 * @param options.data {Json | Blob}   The value returned by `resource.get()`.
 * @param [options.output] {string}   The output file path; stdout when
 *   omitted.
 * @returns {Promise<void>}
 */
export async function writeResourceOutput({
  data,
  output
}: {
  data: Json | Blob
  output?: string
}): Promise<void> {
  if (data instanceof Blob) {
    const bytes = new Uint8Array(await data.arrayBuffer())
    if (output) {
      await writeFile(output, bytes)
      console.error(`Wrote ${bytes.length} bytes to ${output}`)
      return
    }
    process.stdout.write(bytes)
    return
  }
  await writeJsonOutput({ value: data, output })
}
