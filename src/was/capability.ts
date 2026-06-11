/**
 * Capability-based addressing for the `was` commands (the receiving side of
 * delegation): resolves a `--capability` reference -- a multibase-encoded
 * capability string, a JSON file path, or the id/handle of a zcap stored in
 * `~/.wallet/zcaps/` -- and rebuilds a signed access handle from it with
 * `was.fromCapability()`. The capability's `invocationTarget` determines
 * both the server URL (its origin) and the handle depth (space, collection,
 * or resource), so no path argument is needed. The signing DID falls back
 * from `--did` / `WAS_DID` to the capability's `controller` (the delegatee,
 * who is the one invoking it).
 */
import { access, readFile } from 'node:fs/promises'
import type {
  Collection,
  Resource,
  Space,
  IZcap,
  WasClient
} from '@interop/was-client'
import { decodeCapability } from '../zcap/encoding.js'
import { resolveZcapRef } from '../meta.js'
import { buildWasClient } from './client.js'

/**
 * The depth a capability handle operates at, implied by the path of its
 * `invocationTarget`.
 */
export type CapabilityDepth = 'space' | 'collection' | 'resource'

/**
 * The depth-independent fields of a resolved capability target.
 */
interface ResolvedCapabilityBase {
  client: WasClient
  zcap: IZcap
  /** The server base URL (the invocation target's origin). */
  server: string
  /** The resolved signing DID. */
  did: string
  /** The capability's invocation target URL, for messages and output. */
  url: string
}

/**
 * A ready-to-use command target rebuilt from a received capability. A
 * discriminated union keyed by `depth`, so checking the depth narrows the
 * `handle` to the matching access-handle type.
 */
export type ResolvedCapabilityTarget =
  | (ResolvedCapabilityBase & { depth: 'space'; handle: Space })
  | (ResolvedCapabilityBase & { depth: 'collection'; handle: Collection })
  | (ResolvedCapabilityBase & { depth: 'resource'; handle: Resource })

/**
 * Returns true when the path exists on disk.
 *
 * @param filePath {string}
 * @returns {Promise<boolean>}
 */
async function fileExists(filePath: string): Promise<boolean> {
  try {
    await access(filePath)
    return true
  } catch {
    return false
  }
}

/**
 * Resolves a `--capability` reference to a capability object. A value
 * beginning with `z` is decoded as a multibase capability string; a path to
 * an existing file is parsed as capability JSON; anything else is looked up
 * in the local zcap store by capability id or metadata handle.
 *
 * @param options {object}
 * @param options.ref {string}
 * @returns {Promise<IZcap>}
 */
export async function resolveCapabilityInput({
  ref
}: {
  ref: string
}): Promise<IZcap> {
  if (ref.startsWith('z')) {
    return decodeCapability(ref)
  }
  if (await fileExists(ref)) {
    try {
      return JSON.parse(await readFile(ref, 'utf8')) as IZcap
    } catch (err) {
      throw new Error(
        `${ref} does not contain capability JSON: ` +
          `${err instanceof Error ? err.message : String(err)}`,
        { cause: err }
      )
    }
  }
  const stored = await resolveZcapRef({ ref })
  if (!stored) {
    throw new Error(
      `No capability found for "${ref}" (not an encoded string, a file, ` +
        'or a stored zcap id/handle).'
    )
  }
  return stored.zcap as IZcap
}

/**
 * Resolves a `--capability` reference into a ready-to-use command target:
 * the capability itself, a signed client for the invocation target's
 * server, and the access handle rebuilt at the depth the capability
 * implies.
 *
 * @param options {object}
 * @param options.ref {string}   The `--capability` value.
 * @param [options.did] {string}   The `--did` flag value (DID or handle);
 *   falls back to `WAS_DID`, then the capability's `controller`.
 * @returns {Promise<ResolvedCapabilityTarget>}
 */
export async function resolveCapabilityTarget({
  ref,
  did
}: {
  ref: string
  did?: string
}): Promise<ResolvedCapabilityTarget> {
  const zcap = await resolveCapabilityInput({ ref })
  if (!zcap.invocationTarget) {
    throw new Error(`The capability "${ref}" has no invocationTarget.`)
  }
  const url = zcap.invocationTarget
  let server: string
  try {
    server = new URL(url).origin
  } catch (err) {
    throw new Error(
      `The capability's invocationTarget is not a valid URL: ${url}`,
      { cause: err }
    )
  }
  const didRef =
    did ??
    process.env.WAS_DID ??
    (typeof zcap.controller === 'string' ? zcap.controller : undefined)
  if (!didRef) {
    throw new Error(
      'No signing DID for the capability: provide --did or WAS_DID.'
    )
  }
  const { client, did: resolvedDid } = await buildWasClient({
    server,
    did: didRef
  })
  const handle = client.fromCapability(zcap)
  const base = { client, zcap, server, did: resolvedDid, url }
  // The handle's own shape implies the depth: a Resource carries
  // `collectionId`, a Collection carries `spaceId`, a Space carries neither.
  if ('collectionId' in handle) {
    return { ...base, depth: 'resource', handle }
  }
  if ('spaceId' in handle) {
    return { ...base, depth: 'collection', handle }
  }
  return { ...base, depth: 'space', handle }
}
