import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import type {
  EntityIdentityRegistry,
  VerificationContext,
  VerificationSubject
} from '@interop/verifier-core'
import { issuerDetailsSuite } from './issuerDetailsSuite.js'

const check = issuerDetailsSuite.checks[0]

const registries: EntityIdentityRegistry[] = [
  {
    type: 'dcc-legacy',
    name: 'Test Registry',
    url: 'https://example.test/r.json'
  }
]

/**
 * Builds a verification context with the given registries.
 *
 * @param contextRegistries {EntityIdentityRegistry[]}
 * @returns {VerificationContext}
 */
function contextWith(
  contextRegistries: EntityIdentityRegistry[]
): VerificationContext {
  return {
    registries: contextRegistries
  } as unknown as VerificationContext
}

/**
 * Wraps a credential as a verification subject.
 *
 * @param credential {object | undefined}
 * @returns {VerificationSubject}
 */
function subjectFor(credential: object | undefined): VerificationSubject {
  return { verifiableCredential: credential } as unknown as VerificationSubject
}

describe('issuerDetailsSuite', () => {
  it('skips when there is no credential', async () => {
    const outcome = await check.execute(
      subjectFor(undefined),
      contextWith(registries)
    )
    assert.equal(outcome.status, 'skipped')
  })

  it('skips when no registries are configured', async () => {
    const outcome = await check.execute(
      subjectFor({ issuer: 'did:key:zABC' }),
      contextWith([])
    )
    assert.equal(outcome.status, 'skipped')
  })

  it('skips when the credential has no issuer DID', async () => {
    const outcome = await check.execute(
      subjectFor({ credentialSubject: {} }),
      contextWith(registries)
    )
    assert.equal(outcome.status, 'skipped')
  })

  it('skips when the issuer object has no id', async () => {
    const outcome = await check.execute(
      subjectFor({ issuer: { name: 'Acme' } }),
      contextWith(registries)
    )
    assert.equal(outcome.status, 'skipped')
  })
})
