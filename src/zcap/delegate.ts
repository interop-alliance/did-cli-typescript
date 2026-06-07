/**
 * Delegated Authorization Capability (zcap) signing.
 *
 * `delegateCapability` signs a delegated capability using @interop/ezcap's
 * `ZcapClient.delegate`, which builds the delegated zcap (id, controller,
 * parent, invocation target, expiration, allowed actions), auto-computes the
 * capability chain, and signs it with the delegator's `capabilityDelegation`
 * key. For a first-level delegation the parent is the root capability generated
 * from the invocation target; for further (attenuated) delegation a decoded
 * parent capability is passed instead. The signing key is resolved from a stored
 * DID or `ZCAP_CONTROLLER_KEY_SEED` (see `loadDelegationSigner`).
 *
 * The document loader is `@interop/security-document-loader`'s loader, which
 * already bundles the zcap JSON-LD context (and the ed25519-2020 suite context),
 * so it can be passed to `ZcapClient` as-is.
 */
import { Ed25519Signature2020 } from '@interop/ed25519-signature'
import { ZcapClient } from '@interop/ezcap'
import { securityLoader } from '@interop/security-document-loader'
import type { IDelegatedZcap, IZcap } from '@interop/data-integrity-core/zcap'
import { encodeCapability } from './encoding.js'
import { expiresFromTtl } from './ttl.js'
import { loadDelegationSigner } from './signer.js'

/**
 * Offline document loader for signing: bundles the zcap, VC, Data Integrity, and
 * suite contexts plus a did:key resolver. Built once and reused across calls.
 */
const documentLoader = securityLoader().build()

/**
 * Signs a delegated capability.
 *
 * Exactly one of `url` (first-level delegation from the root capability for that
 * target) or `capability` (further delegation of an existing capability) drives
 * the parent; `invocationTarget` narrows the target when delegating an existing
 * capability. Expiration is `expires` (an ISO 8601 date) when given, otherwise
 * derived from `ttl`.
 *
 * @param options {object}
 * @param [options.did] {string}   The id of a stored DID to sign with.
 * @param [options.controller] {string}   The expected controller DID, when
 *   signing via `ZCAP_CONTROLLER_KEY_SEED`.
 * @param options.delegatee {string}   The DID to delegate to (the new
 *   capability's controller).
 * @param [options.url] {string}   The invocation target for a first-level
 *   delegation from the root capability.
 * @param [options.capability] {IZcap}   A parent capability to delegate (already
 *   decoded from its multibase string or a JSON file).
 * @param [options.invocationTarget] {string}   An attenuated invocation target.
 * @param [options.allow] {string[]}   Allowed actions; omitted inherits the
 *   parent's actions.
 * @param [options.ttl] {string}   Time-to-live for expiration (default `1y`).
 * @param [options.expires] {string}   Explicit ISO 8601 expiration (overrides
 *   `ttl`).
 * @returns {Promise<{delegatedCapability: IDelegatedZcap, encoded: string}>}
 *   The signed delegated capability and its multibase (base58btc) encoding.
 */
export async function delegateCapability({
  did,
  controller,
  delegatee,
  url,
  capability,
  invocationTarget,
  allow,
  ttl = '1y',
  expires
}: {
  did?: string
  controller?: string
  delegatee: string
  url?: string
  capability?: IZcap
  invocationTarget?: string
  allow?: string[]
  ttl?: string
  expires?: string
}): Promise<{ delegatedCapability: IDelegatedZcap; encoded: string }> {
  const delegationSigner = await loadDelegationSigner({ did, controller })
  const client = new ZcapClient({
    SuiteClass: Ed25519Signature2020,
    delegationSigner,
    documentLoader
  })

  const expiresValue = expires ?? expiresFromTtl(ttl)
  const target = invocationTarget ?? url

  const delegatedCapability = await client.delegate({
    capability,
    controller: delegatee,
    invocationTarget: target,
    expires: expiresValue,
    allowedActions: allow
  })

  return {
    delegatedCapability,
    encoded: encodeCapability(delegatedCapability)
  }
}
