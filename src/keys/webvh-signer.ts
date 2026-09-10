/**
 * Bridge between the CLI's `@interop/ed25519-verification-key` key pair and the
 * `Signer` interface expected by `@interop/did-method-webvh`, so did:webvh
 * reuses the same Ed25519 key class as did:key / did:web rather than pulling in
 * a separate signing implementation.
 *
 * `sign({ document, proof })` returns a base58btc multibase `proofValue`.
 * `prepareDataForSigning` produces the bytes to sign (the `eddsa-jcs-2022`
 * cryptosuite hash); the key pair's own `didKeySigner()` does the cryptography
 * and names the verification method id, so the caller does not need to assign
 * `keyPair.id` first. Verification is left to the library's default log
 * verifier, which recovers each entry's public key from its proof rather than
 * being bound to one key.
 */
import type { Ed25519VerificationKey } from '@interop/ed25519-verification-key'
import {
  MultibaseEncoding,
  multibaseEncode,
  prepareDataForSigning
} from '@interop/did-method-webvh'
import type { Signer } from '@interop/did-method-webvh'

/**
 * Build a did:webvh `Signer` backed by an Ed25519 key pair.
 *
 * @param options {object}
 * @param options.keyPair {Ed25519VerificationKey} an
 *   `@interop/ed25519-verification-key` pair.
 * @returns {Signer}
 */
export function makeWebvhSigner({
  keyPair
}: {
  keyPair: Ed25519VerificationKey
}): Signer {
  const keySigner = keyPair.didKeySigner()
  return {
    async sign({ document, proof }) {
      const data = await prepareDataForSigning(document, proof)
      const signature = await keySigner.sign({ data })
      return {
        proofValue: multibaseEncode(signature, MultibaseEncoding.BASE58_BTC)
      }
    },
    getVerificationMethodId() {
      return keySigner.id
    }
  }
}
