import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { FakeTimeService } from '@interop/verifier-core'
import type {
  VerificationContext,
  VerificationSubject
} from '@interop/verifier-core'
import { EXPIRED_PROBLEM_TYPE, expirationSuite } from './expirationSuite.js'

const check = expirationSuite.checks[0]

/**
 * Builds a verification context whose injected clock reports `nowMs` on its
 * first `dateNowMs()` read. FakeTimeService returns `baseDateMs + n` (1-based
 * per call), so we offset by 1 to pin "now" to `nowMs` on the first read.
 *
 * @param nowMs {number}
 * @returns {VerificationContext}
 */
function contextAt(nowMs: number): VerificationContext {
  return {
    timeService: new FakeTimeService({ baseDateMs: nowMs - 1 })
  } as unknown as VerificationContext
}

/**
 * Wraps a credential as a verification subject.
 *
 * @param credential {object}
 * @returns {VerificationSubject}
 */
function subjectFor(credential: object): VerificationSubject {
  return { verifiableCredential: credential } as unknown as VerificationSubject
}

describe('expirationSuite', () => {
  const now = Date.parse('2026-06-06T00:00:00Z')

  it('succeeds when the credential is within its validity period', async () => {
    const outcome = await check.execute(
      subjectFor({ validUntil: '2030-01-01T00:00:00Z' }),
      contextAt(now)
    )
    assert.equal(outcome.status, 'success')
  })

  it('fails when the credential has expired', async () => {
    const outcome = await check.execute(
      subjectFor({ validUntil: '2020-01-01T00:00:00Z' }),
      contextAt(now)
    )
    assert.equal(outcome.status, 'failure')
    if (outcome.status === 'failure') {
      assert.equal(outcome.problems[0]?.type, EXPIRED_PROBLEM_TYPE)
    }
  })

  it('falls back to the VC 1.x expirationDate property', async () => {
    const outcome = await check.execute(
      subjectFor({ expirationDate: '2020-01-01T00:00:00Z' }),
      contextAt(now)
    )
    assert.equal(outcome.status, 'failure')
  })

  it('skips when the credential has no expiration date', async () => {
    const outcome = await check.execute(subjectFor({}), contextAt(now))
    assert.equal(outcome.status, 'skipped')
  })

  it('skips when the expiration date is not a valid date', async () => {
    const outcome = await check.execute(
      subjectFor({ validUntil: 'not-a-date' }),
      contextAt(now)
    )
    assert.equal(outcome.status, 'skipped')
  })
})
