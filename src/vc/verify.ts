/**
 * Credential verification adapter over @interop/verifier-core.
 *
 * A single `verifyCredentialFully` call runs the fork's default suite pipeline
 * (structure, cryptographic signature, revocation/status, issuer registry
 * lookup) plus two custom suites (`expirationSuite`, `issuerDetailsSuite`),
 * returning the unified `CredentialVerificationResult` directly -- it is
 * already dev-friendly (top-level `verified`, per-suite `summary[]`, flat
 * `results[]`). `toSummary` derives a compact flattened object for the CLI's
 * `--summary` flag. All knowledge of the verifier-core contract is isolated to
 * this file.
 */
import { verifyCredential, ProblemTypes } from '@interop/verifier-core'
import type {
  CredentialVerificationResult,
  CheckResult,
  EntityIdentityRegistry
} from '@interop/verifier-core'
import { expirationSuite } from './suites/expirationSuite.js'
import { issuerDetailsSuite } from './suites/issuerDetailsSuite.js'

/**
 * Dot-separated check ids emitted by the verifier-core pipeline (and the two
 * custom suites) that the summary reads.
 */
const CHECK_ID = {
  signature: 'proof.signature',
  status: 'status.bitstring',
  expiration: 'validity.expiration',
  issuerDetails: 'trust.issuer-details',
  parsing: 'parsing.envelope'
} as const

/**
 * Compact, human-friendly verification summary produced for the `--summary`
 * flag. `undefined` check values mean the check was skipped (not applicable).
 */
export interface VerificationSummary {
  verified: boolean
  checks: {
    signature?: boolean
    expired?: boolean
    revoked?: boolean
    issuerRecognized?: boolean
  }
  matchingIssuers: unknown[]
}

/**
 * Runs full verification on a credential: the default verifier-core pipeline
 * plus the expiration and issuer-details custom suites.
 *
 * @param options {object}
 * @param options.credential {object}   The parsed Verifiable Credential.
 * @param options.registries {EntityIdentityRegistry[]}   Trusted registries
 *   for the issuer DID lookup.
 * @returns {Promise<CredentialVerificationResult>}
 */
export async function verifyCredentialFully({
  credential,
  registries
}: {
  credential: object
  registries: EntityIdentityRegistry[]
}): Promise<CredentialVerificationResult> {
  return verifyCredential({
    credential: credential as never,
    registries,
    additionalSuites: [expirationSuite, issuerDetailsSuite],
    // verbose so results[] carries EVERY check (incl. successes and the
    // issuer-details payload), not just failures folded into summary[].
    verbose: true
  })
}

/**
 * Returns the result of a structural parse failure check, if the credential
 * was malformed. Callers treat this as a fatal (exit code 2) condition.
 *
 * @param result {CredentialVerificationResult}
 * @returns {CheckResult | undefined}
 */
export function findParseFailure(
  result: CredentialVerificationResult
): CheckResult | undefined {
  return result.results.find(
    check =>
      check.check === CHECK_ID.parsing && check.outcome.status === 'failure'
  )
}

/**
 * Translates a verifier-core result into a compact summary object for the
 * `--summary` flag.
 *
 * @param result {CredentialVerificationResult}
 * @returns {VerificationSummary}
 */
export function toSummary(
  result: CredentialVerificationResult
): VerificationSummary {
  const byCheck = (checkId: string): CheckResult | undefined =>
    result.results.find(check => check.check === checkId)

  return {
    verified: result.verified,
    checks: {
      signature: passed(byCheck(CHECK_ID.signature)),
      expired: failed(byCheck(CHECK_ID.expiration)),
      revoked: revoked(byCheck(CHECK_ID.status)),
      issuerRecognized: issuerRecognized(byCheck(CHECK_ID.issuerDetails))
    },
    matchingIssuers: matchingIssuersFrom(byCheck(CHECK_ID.issuerDetails))
  }
}

/**
 * Maps a check to `true` on success, `false` on failure, `undefined` when the
 * check was skipped or absent.
 *
 * @param check {CheckResult | undefined}
 * @returns {boolean | undefined}
 */
function passed(check: CheckResult | undefined): boolean | undefined {
  if (!check || check.outcome.status === 'skipped') {
    return undefined
  }
  return check.outcome.status === 'success'
}

/**
 * Maps a check to `true` when it failed (e.g. the expiration check), `false`
 * on success, `undefined` when skipped or absent.
 *
 * @param check {CheckResult | undefined}
 * @returns {boolean | undefined}
 */
function failed(check: CheckResult | undefined): boolean | undefined {
  const result = passed(check)
  return result === undefined ? undefined : !result
}

/**
 * Maps the status (revocation) check to a `revoked` boolean. A failure whose
 * first problem is STATUS_LIST_NOT_FOUND is treated as "not revoked" -- the
 * status list simply is not published, so the credential is unchecked rather
 * than revoked.
 *
 * @param check {CheckResult | undefined}
 * @returns {boolean | undefined}
 */
function revoked(check: CheckResult | undefined): boolean | undefined {
  if (!check || check.outcome.status === 'skipped') {
    return undefined
  }
  if (check.outcome.status === 'success') {
    return false
  }
  if (check.outcome.problems[0]?.type === ProblemTypes.STATUS_LIST_NOT_FOUND) {
    return false
  }
  return true
}

/**
 * Maps the issuer-details check to whether the issuer was found in a registry.
 *
 * @param check {CheckResult | undefined}
 * @returns {boolean | undefined}
 */
function issuerRecognized(check: CheckResult | undefined): boolean | undefined {
  if (!check || check.outcome.status !== 'success') {
    return undefined
  }
  return matchingIssuersFrom(check).length > 0
}

/**
 * Pulls the rich `matchingIssuers` array off the issuer-details check payload.
 *
 * @param check {CheckResult | undefined}
 * @returns {unknown[]}
 */
function matchingIssuersFrom(check: CheckResult | undefined): unknown[] {
  if (!check || check.outcome.status !== 'success') {
    return []
  }
  const payload = check.outcome.payload as
    | { matchingIssuers?: unknown[] }
    | undefined
  return payload?.matchingIssuers ?? []
}
