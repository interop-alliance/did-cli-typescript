/**
 * Multibase (base58btc) encoding for Authorization Capabilities (zcaps).
 *
 * The CLI prints an `encoded` form alongside each capability: the capability's
 * JSON serialized to UTF-8 bytes, base58btc-encoded, with a leading `z`
 * multibase prefix (matching the legacy did-cli output). `decodeCapability`
 * reverses this so a delegated capability can be passed back in via
 * `zcap delegate --capability`. Uses `@scure/base`'s `base58` (the same base58
 * implementation used by `@interop/ed25519-verification-key`), which operates on
 * raw base58 without a multibase prefix, so the `z` is added/stripped here.
 */
import { base58 } from '@scure/base'
import type { IZcap } from '@interop/data-integrity-core/zcap'

/**
 * Encodes a capability as a multibase (base58btc) string.
 *
 * @param capability {IZcap}   The root or delegated capability to encode.
 * @returns {string}   The capability JSON, base58btc-encoded with a leading `z`.
 */
export function encodeCapability(capability: IZcap): string {
  const bytes = new TextEncoder().encode(JSON.stringify(capability))
  return `z${base58.encode(bytes)}`
}

/**
 * Decodes a multibase (base58btc) capability string back into a capability.
 *
 * @param encoded {string}   A `z`-prefixed base58btc string from
 *   `encodeCapability`.
 * @returns {IZcap}   The decoded root or delegated capability.
 */
export function decodeCapability(encoded: string): IZcap {
  if (!encoded.startsWith('z')) {
    throw new Error(
      'Encoded capability must be a multibase base58btc string (leading "z").'
    )
  }
  const bytes = base58.decode(encoded.slice(1))
  return JSON.parse(new TextDecoder().decode(bytes)) as IZcap
}
