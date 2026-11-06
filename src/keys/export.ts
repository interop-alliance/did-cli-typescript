/**
 * Key pair export shared by the key- and DID-generating commands: the
 * exported object with its secret half, as written to local wallet storage
 * (a saved key or a DID's keys file) and printed back to the user.
 */
import type { AbstractKeyPair } from '@interop/data-integrity-core'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'

/**
 * Export a key pair with its secret half. X25519 keys export their private
 * half as `privateKeyMultibase`, the other suites as `secretKeyMultibase`.
 *
 * @param keyPair {AbstractKeyPair}
 * @returns {Promise<{ id?: string, publicKeyMultibase?: string }>}
 */
export async function exportStoredKey(
  keyPair: AbstractKeyPair
): Promise<{ id?: string; publicKeyMultibase?: string }> {
  if (keyPair instanceof X25519KeyAgreementKey2020) {
    return keyPair.export({ publicKey: true, privateKey: true })
  }
  return (await keyPair.export({ publicKey: true, secretKey: true })) as {
    id?: string
    publicKeyMultibase?: string
  }
}
