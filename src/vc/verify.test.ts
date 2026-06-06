import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { ProblemTypes } from '@interop/verifier-core'
import type {
  CheckResult,
  CredentialVerificationResult
} from '@interop/verifier-core'
import { findParseFailure, toSummary } from './verify.js'

/**
 * Builds a minimal CredentialVerificationResult from a list of check results,
 * for exercising the pure translation helpers without running the verifier.
 *
 * @param options {object}
 * @param options.verified {boolean}
 * @param options.results {CheckResult[]}
 * @returns {CredentialVerificationResult}
 */
function makeResult({
  verified,
  results
}: {
  verified: boolean
  results: CheckResult[]
}): CredentialVerificationResult {
  return {
    verified,
    verifiableCredential: {} as never,
    results,
    summary: []
  } as CredentialVerificationResult
}

function successCheck(check: string, payload?: unknown): CheckResult {
  return {
    check,
    suite: check.split('.')[0],
    outcome: { status: 'success', message: 'ok', payload }
  } as CheckResult
}

function failureCheck(check: string, type = 'urn:test:problem'): CheckResult {
  return {
    check,
    suite: check.split('.')[0],
    outcome: {
      status: 'failure',
      problems: [{ type, title: 'Problem', detail: 'detail' }]
    }
  } as CheckResult
}

function skippedCheck(check: string): CheckResult {
  return {
    check,
    suite: check.split('.')[0],
    outcome: { status: 'skipped', reason: 'n/a' }
  } as CheckResult
}

describe('toSummary', () => {
  it('maps a fully passing result to true checks', () => {
    const summary = toSummary(
      makeResult({
        verified: true,
        results: [
          successCheck('proof.signature'),
          successCheck('validity.expiration'),
          successCheck('status.bitstring'),
          successCheck('trust.issuer-details', {
            matchingIssuers: [{ name: 'Acme' }]
          })
        ]
      })
    )
    assert.equal(summary.verified, true)
    assert.equal(summary.checks.signature, true)
    assert.equal(summary.checks.expired, false)
    assert.equal(summary.checks.revoked, false)
    assert.equal(summary.checks.issuerRecognized, true)
    assert.deepEqual(summary.matchingIssuers, [{ name: 'Acme' }])
  })

  it('maps a failed signature to signature:false', () => {
    const summary = toSummary(
      makeResult({
        verified: false,
        results: [failureCheck('proof.signature')]
      })
    )
    assert.equal(summary.checks.signature, false)
  })

  it('maps a failed expiration to expired:true', () => {
    const summary = toSummary(
      makeResult({
        verified: true,
        results: [failureCheck('validity.expiration')]
      })
    )
    assert.equal(summary.checks.expired, true)
  })

  it('marks a revoked credential revoked:true', () => {
    const summary = toSummary(
      makeResult({
        verified: false,
        results: [
          failureCheck(
            'status.bitstring',
            ProblemTypes.CREDENTIAL_REVOKED_OR_SUSPENDED
          )
        ]
      })
    )
    assert.equal(summary.checks.revoked, true)
  })

  it('treats STATUS_LIST_NOT_FOUND as not revoked', () => {
    const summary = toSummary(
      makeResult({
        verified: true,
        results: [
          failureCheck('status.bitstring', ProblemTypes.STATUS_LIST_NOT_FOUND)
        ]
      })
    )
    assert.equal(summary.checks.revoked, false)
  })

  it('leaves skipped checks undefined', () => {
    const summary = toSummary(
      makeResult({
        verified: true,
        results: [
          skippedCheck('status.bitstring'),
          skippedCheck('validity.expiration')
        ]
      })
    )
    assert.equal(summary.checks.revoked, undefined)
    assert.equal(summary.checks.expired, undefined)
    assert.deepEqual(summary.matchingIssuers, [])
  })

  it('reports issuerRecognized:false when no registry matched', () => {
    const summary = toSummary(
      makeResult({
        verified: true,
        results: [successCheck('trust.issuer-details', { matchingIssuers: [] })]
      })
    )
    assert.equal(summary.checks.issuerRecognized, false)
  })
})

describe('findParseFailure', () => {
  it('returns the parsing.envelope failure when present', () => {
    const result = makeResult({
      verified: false,
      results: [failureCheck('parsing.envelope')]
    })
    const failure = findParseFailure(result)
    assert.ok(failure)
    assert.equal(failure?.check, 'parsing.envelope')
  })

  it('returns undefined when there is no parse failure', () => {
    const result = makeResult({
      verified: true,
      results: [successCheck('proof.signature')]
    })
    assert.equal(findParseFailure(result), undefined)
  })
})
