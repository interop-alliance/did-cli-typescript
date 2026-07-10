/**
 * Bridge between the CLI's `@interop/ed25519-verification-key` key pair and the
 * `Signer` interface expected by `@interop/did-method-webvh`, so did:webvh
 * reuses the same Ed25519 key class as did:key / did:web rather than pulling in
 * a separate signing implementation.
 *
 * `sign({ document, proof })` returns a base58btc multibase `proofValue`.
 * `prepareDataForSigning` produces the bytes to sign (the `eddsa-jcs-2022`
 * cryptosuite hash); the key pair's own `signer()` does the cryptography.
 * Verification is left to the library's default log verifier, which recovers
 * each entry's public key from its proof rather than being bound to one key.
 */
import {
  MultibaseEncoding,
  multibaseEncode,
  prepareDataForSigning
} from '@interop/did-method-webvh'
import type { Signer } from '@interop/did-method-webvh'

/**
 * Build a did:webvh `Signer` backed by an Ed25519 key pair.
 *
 * `keyPair.signer()` requires `keyPair.id` to be set, so the caller must assign
 * an id before signing; this helper derives the verification method id from the
 * key's `publicKeyMultibase` (the did:key form the library validates against).
 *
 * @param options {object}
 * @param options.keyPair {object} an `@interop/ed25519-verification-key` pair.
 * @returns {Signer}
 */
export function makeWebvhSigner({
  keyPair
}: {
  keyPair: {
    publicKeyMultibase: string
    signer(): { sign(options: { data: Uint8Array }): Promise<Uint8Array> }
  }
}): Signer {
  const verificationMethodId = `did:key:${keyPair.publicKeyMultibase}#${keyPair.publicKeyMultibase}`
  return {
    async sign({ document, proof }) {
      const data = await prepareDataForSigning(document, proof)
      const signature = await keyPair.signer().sign({ data })
      return {
        proofValue: multibaseEncode(signature, MultibaseEncoding.BASE58_BTC)
      }
    },
    getVerificationMethodId() {
      return verificationMethodId
    }
  }
}
