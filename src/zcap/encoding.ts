/**
 * Multibase encoding for Authorization Capabilities (zcaps).
 *
 * The CLI prints an `encoded` form alongside each capability: the capability's
 * JSON serialized to UTF-8 bytes, base64url-encoded without padding, with a
 * leading `u` multibase prefix. `decodeCapability` reverses this so a
 * delegated capability can be passed back in via `--capability`. base64url
 * rather than base58btc because a delegated capability embeds its whole
 * chain, and base58 is quadratic in the input size, so `@scure/base` refuses
 * it past 2048 bytes -- smaller than a two-hop chain a wallet delegates.
 */
import { base64urlnopad } from '@scure/base'
import type { IZcap } from '@interop/data-integrity-core/zcap'

/**
 * Encodes a capability as a multibase (base64url, no padding) string.
 *
 * @param capability {IZcap}   The root or delegated capability to encode.
 * @returns {string}   The capability JSON, base64url-encoded with a leading
 *   `u`.
 */
export function encodeCapability(capability: IZcap): string {
  const bytes = new TextEncoder().encode(JSON.stringify(capability))
  return `u${base64urlnopad.encode(bytes)}`
}

/**
 * Tells whether a `--capability` value is an encoded capability rather than a
 * file path or a stored id/handle. The `u` form is base64url of JSON that
 * always opens with `{"`, so it always begins `ueyJ`; checking that prefix is
 * what keeps a `urn:` capability id (which also begins with `u`) out of the
 * decoder.
 *
 * @param value {string}
 * @returns {boolean}
 */
export function isEncodedCapability(value: string): boolean {
  return /^ueyJ[A-Za-z0-9_-]*$/.test(value)
}

/**
 * Decodes a multibase (base64url, `u` prefix) capability string back into a
 * capability.
 *
 * @param encoded {string}   A `u`-prefixed multibase string.
 * @returns {IZcap}   The decoded root or delegated capability.
 */
export function decodeCapability(encoded: string): IZcap {
  if (!encoded.startsWith('u')) {
    throw new Error(
      'Encoded capability must be a multibase base64url string (leading "u").'
    )
  }
  const bytes = base64urlnopad.decode(encoded.slice(1))
  return JSON.parse(new TextDecoder().decode(bytes)) as IZcap
}
