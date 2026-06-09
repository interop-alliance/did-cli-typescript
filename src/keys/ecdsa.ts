/**
 * ECDSA key-type helpers shared across the `key` and `did` commands.
 *
 * Maps the curve spellings the CLI accepts on `--curve` (case-insensitive
 * short, hyphenated, and SECG names) onto the canonical curve identifiers used
 * by `@interop/ecdsa-multikey` (`P-256` / `P-384` / `P-521`).
 */
import { ECDSA_CURVE } from '@interop/ecdsa-multikey'
import type { EcdsaCurve } from '@interop/ecdsa-multikey'

// Accepted `--curve` spellings (lower-cased) mapped to the library's canonical
// curve identifier. Three forms per curve: short (`p256`), hyphenated
// (`p-256`), and SECG (`secp256r1`).
const CURVE_ALIASES: Record<string, EcdsaCurve> = {
  p256: ECDSA_CURVE.P256,
  'p-256': ECDSA_CURVE.P256,
  secp256r1: ECDSA_CURVE.P256,
  p384: ECDSA_CURVE.P384,
  'p-384': ECDSA_CURVE.P384,
  secp384r1: ECDSA_CURVE.P384,
  p521: ECDSA_CURVE.P521,
  'p-521': ECDSA_CURVE.P521,
  secp521r1: ECDSA_CURVE.P521
}

// Human-readable list of accepted curves, for `--help` text and error messages.
export const SUPPORTED_ECDSA_CURVES = 'p256, p384, p521'

/**
 * Resolve a user-supplied `--curve` value to a canonical ECDSA curve
 * identifier, or `undefined` if it is not a recognized spelling.
 *
 * @param options {object}
 * @param options.curve {string}   the raw `--curve` value, in any case
 * @returns {EcdsaCurve | undefined}
 */
export function normalizeEcdsaCurve({
  curve
}: {
  curve: string
}): EcdsaCurve | undefined {
  return CURVE_ALIASES[curve.toLowerCase()]
}
