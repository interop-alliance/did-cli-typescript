/**
 * Root Authorization Capability (zcap) creation.
 *
 * `createCapability` builds an unsigned root capability via @interop/zcap's
 * `createRootCapability` (which sets `@context`, the `urn:zcap:root:<target>`
 * id, the controller, and the invocation target) and returns it alongside its
 * multibase-encoded form. Root capabilities are unsigned, so no key is needed.
 */
import { createRootCapability } from '@interop/zcap'
import type { IRootZcap } from '@interop/data-integrity-core/zcap'
import { encodeCapability } from './encoding.js'

/**
 * Creates a root capability for an invocation target.
 *
 * @param options {object}
 * @param options.controller {string}   The DID authorized to invoke (the root
 *   controller).
 * @param options.url {string}   The resource URI the capability targets (the
 *   `invocationTarget`).
 * @returns {{rootCapability: IRootZcap, encoded: string}}   The root capability
 *   and its multibase (base58btc) encoding.
 */
export function createCapability({
  controller,
  url
}: {
  controller: string
  url: string
}): { rootCapability: IRootZcap; encoded: string } {
  const rootCapability = createRootCapability({
    controller,
    invocationTarget: url
  })
  return { rootCapability, encoded: encodeCapability(rootCapability) }
}
