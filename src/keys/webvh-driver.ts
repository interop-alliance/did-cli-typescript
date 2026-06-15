/**
 * Bridges `@interop/did-method-webvh`'s `resolveDID` to the DID-method driver
 * contract expected by the security document loader's `CachedResolver`
 * (`{ method, get({ did, url }) }`). Registering this driver lets the shared
 * loader resolve `did:webvh` DIDs (and dereference `did#fragment` URLs to their
 * verification method) without `@interop/security-document-loader` itself
 * taking on the `did:webvh` dependency stack.
 *
 * `resolveDID` fetches and verifies the DID's history log, then returns
 * `{ doc, meta }`; unlike the did:web driver it never throws, signalling
 * failure with `doc: null` and a `meta.problemDetails` instead, so this wrapper
 * converts that into a thrown error to match the other drivers' behaviour. The
 * `did#fragment` dereferencing reuses did:web's `getNode` for parity.
 */
import {
  MultibaseEncoding,
  multibaseEncode,
  resolveDID
} from '@interop/did-method-webvh'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'
import { getNode } from '@interop/did-web-resolver'

/**
 * Multicodec `ed25519-pub` varint header. Prepended to a raw 32-byte Ed25519
 * public key to form the multibase (`z6Mk...`) the key class expects.
 */
const ED25519_PUB_MULTICODEC_HEADER = Uint8Array.from([0xed, 0x01])

/**
 * Generic Ed25519 verifier for resolving a did:webvh history log. The webvh
 * resolver verifies each log entry's `eddsa-jcs-2022` proof by calling
 * `verify(signature, message, publicKey)` with the raw public-key bytes of that
 * entry's update key, so -- unlike the fixed-key signer/verifier in
 * `webvh-signer.ts` -- this reconstructs a key per call from those bytes.
 */
const webvhLogVerifier = {
  async verify(
    signature: Uint8Array,
    message: Uint8Array,
    publicKey: Uint8Array
  ): Promise<boolean> {
    const multikey = new Uint8Array(
      ED25519_PUB_MULTICODEC_HEADER.length + publicKey.length
    )
    multikey.set(ED25519_PUB_MULTICODEC_HEADER)
    multikey.set(publicKey, ED25519_PUB_MULTICODEC_HEADER.length)
    const publicKeyMultibase = multibaseEncode(
      multikey,
      MultibaseEncoding.BASE58_BTC
    )
    const key = await Ed25519VerificationKey.from({ publicKeyMultibase })
    return key.verifier().verify({ data: message, signature })
  }
}

/**
 * Build a `did:webvh` driver for the security document loader's resolver.
 *
 * @returns {{ method: string, get: (options: { did?: string, url?: string }) =>
 *   Promise<Record<string, unknown>> }}
 */
export function makeWebvhDriver(): {
  method: string
  get(options: { did?: string; url?: string }): Promise<Record<string, unknown>>
} {
  return {
    method: 'webvh',
    async get({ did, url } = {}) {
      const didOrUrl = did ?? url
      if (!didOrUrl) {
        throw new TypeError('A DID or a URL is required to resolve.')
      }
      // Separate the bare DID from any `?query` or `#fragment`.
      const [didAuthority = ''] = didOrUrl.split(/[#?]/)
      const fragment = didOrUrl.includes('#')
        ? didOrUrl.slice(didOrUrl.indexOf('#') + 1)
        : undefined

      const { doc, meta } = await resolveDID(didAuthority, {
        verifier: webvhLogVerifier
      })
      if (!doc) {
        throw new Error(
          meta?.problemDetails?.detail ?? `Could not resolve "${didAuthority}".`
        )
      }
      if (fragment) {
        // Dereference an individual subnode (key or service) by id.
        return getNode({ didDocument: doc, id: `${doc.id}#${fragment}` })
      }
      return doc
    }
  }
}
