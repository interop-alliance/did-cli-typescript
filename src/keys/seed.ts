/**
 * Secret-key-seed resolution shared by the key- and DID-generating commands.
 * A seed (`SECRET_KEY_SEED` env var, multibase-encoded) deterministically
 * derives an Ed25519 key; `--with-seed` asks for one to be generated when the
 * env var is not set, so it can be echoed back to the user.
 */
import {
  decodeSecretKeySeed,
  generateSecretKeySeed
} from '@digitalcredentials/bnid'

/**
 * Resolve the secret key seed for a deterministic (Ed25519) key. With
 * `withSeed`, an existing `SECRET_KEY_SEED` env var is honored or a fresh
 * seed generated; without it, only an explicitly set env seed is used. An
 * empty or blank env var counts as unset rather than as an (invalid) seed.
 * Returns the encoded seed (echoed back to the user) and its decoded bytes
 * (for key generation).
 *
 * @param options {object}
 * @param [options.withSeed] {boolean}
 * @returns {Promise<{ secretKeySeed?: string, seedBytes?: Uint8Array }>}
 * @throws {Error} with a user-facing message when the env seed is not a valid
 *   multibase-encoded seed.
 */
export async function deriveSeed({
  withSeed
}: {
  withSeed?: boolean
}): Promise<{
  secretKeySeed?: string
  seedBytes?: Uint8Array
}> {
  const envValue = process.env.SECRET_KEY_SEED
  const envSeed = envValue?.trim() ? envValue : undefined
  const secretKeySeed = withSeed
    ? (envSeed ?? (await generateSecretKeySeed()))
    : envSeed
  let seedBytes: Uint8Array | undefined
  if (secretKeySeed) {
    try {
      seedBytes = decodeSecretKeySeed({ secretKeySeed })
    } catch (err) {
      throw new Error(`Invalid SECRET_KEY_SEED: ${(err as Error).message}`, {
        cause: err
      })
    }
  }
  return { secretKeySeed, seedBytes }
}
