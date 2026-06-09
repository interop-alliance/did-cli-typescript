import { describe, it, beforeEach, afterEach, mock } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { Readable } from 'node:stream'
import { driver } from '@interop/did-method-key'
import * as didWeb from '@interop/did-web-resolver'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'
import { runIssue, runVerify } from './vc.js'
import { saveToDids } from '../storage.js'
import { toSummary, verifyCredentialFully } from '../vc/verify.js'
import { welcomeCredential } from '../vc/fixtures/welcomeCredential.js'

describe('did vc verify', () => {
  let logs: string[]
  let errors: string[]

  beforeEach(() => {
    logs = []
    errors = []
    mock.method(console, 'log', (...args: unknown[]) =>
      logs.push(args.join(' '))
    )
    mock.method(console, 'error', (...args: unknown[]) =>
      errors.push(args.join(' '))
    )
  })

  afterEach(() => {
    mock.restoreAll()
  })

  it('returns exit code 2 on malformed JSON from a file', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'did-cli-vc-test-'))
    const file = join(dir, 'bad.json')
    await writeFile(file, 'not json', 'utf8')
    try {
      const code = await runVerify(file, {})
      assert.equal(code, 2)
      assert.ok(errors[0].startsWith('Could not read credential:'))
      assert.equal(logs.length, 0)
    } finally {
      await rm(dir, { recursive: true })
    }
  })

  it('returns exit code 2 when the file does not exist', async () => {
    const code = await runVerify(join(tmpdir(), 'does-not-exist-xyz.json'), {})
    assert.equal(code, 2)
    assert.ok(errors[0].startsWith('Could not read credential:'))
  })

  it('returns exit code 2 on malformed JSON from stdin', async () => {
    const originalStdin = process.stdin
    const fake = Readable.from([Buffer.from('not json')])
    Object.defineProperty(process, 'stdin', {
      value: fake,
      configurable: true
    })
    try {
      const code = await runVerify(undefined, {})
      assert.equal(code, 2)
      assert.ok(errors[0].startsWith('Could not read credential:'))
    } finally {
      Object.defineProperty(process, 'stdin', {
        value: originalStdin,
        configurable: true
      })
    }
  })
})

/**
 * Generates a did:key, saves its DID document and `<did>.keys.json` to the
 * (temp) DIDs storage dir, and returns the DID id and its assertionMethod key
 * id -- mirroring what `id create --save` does.
 */
async function createSavedDid(): Promise<{ did: string; keyId: string }> {
  const keyPair = await Ed25519VerificationKey.generate()
  const didDriver = driver()
  didDriver.use({ keyPairClass: Ed25519VerificationKey })
  const { didDocument } = await didDriver.fromKeyPair({
    verificationKeyPair: keyPair
  })
  const did = didDocument.id as string
  const exported = keyPair.export({ publicKey: true, secretKey: true })
  await saveToDids({ method: 'key', did, data: didDocument })
  await saveToDids({ method: 'key', did, suffix: 'keys', data: exported })
  return { did, keyId: exported.id as string }
}

/**
 * Generates a did:web, saves its DID document and `<did>.keys.json` to the
 * (temp) DIDs storage dir, and returns the DID id and its assertionMethod key
 * id -- mirroring what `id create web --save` does. Unlike did:key, the saved
 * key file is a map keyed by verification-method id (a did:web may carry more
 * than one key).
 */
async function createSavedDidWeb(): Promise<{ did: string; keyId: string }> {
  const didWebDriver = didWeb.driver()
  didWebDriver.use({ keyPairClass: Ed25519VerificationKey })
  const { didDocument, keyPairs } = await didWebDriver.generate({
    url: 'https://example.com'
  })
  const did = didDocument.id as string
  const exported: Record<string, unknown> = {}
  for (const [methodId, keyPair] of keyPairs) {
    exported[methodId] = keyPair.export({ publicKey: true, secretKey: true })
  }
  await saveToDids({ method: 'web', did, data: didDocument })
  await saveToDids({ method: 'web', did, suffix: 'keys', data: exported })
  return { did, keyId: didDocument.assertionMethod[0] as string }
}

describe('did vc issue', () => {
  let logs: string[]
  let errors: string[]
  let dir: string
  let originalDidsDir: string | undefined
  let did: string
  let keyId: string

  beforeEach(async () => {
    logs = []
    errors = []
    mock.method(console, 'log', (...args: unknown[]) =>
      logs.push(args.join(' '))
    )
    mock.method(console, 'error', (...args: unknown[]) =>
      errors.push(args.join(' '))
    )
    dir = await mkdtemp(join(tmpdir(), 'did-cli-sign-test-'))
    originalDidsDir = process.env.DIDS_DIR
    process.env.DIDS_DIR = dir
    ;({ did, keyId } = await createSavedDid())
  })

  afterEach(async () => {
    mock.restoreAll()
    if (originalDidsDir === undefined) {
      delete process.env.DIDS_DIR
    } else {
      process.env.DIDS_DIR = originalDidsDir
    }
    await rm(dir, { recursive: true })
  })

  /**
   * Writes the unsigned credential (welcomeCredential without its `proof`, with
   * the issuer set to the test DID) to a file and returns its path.
   */
  async function writeUnsignedCredential(): Promise<string> {
    const { proof, ...unsigned } = welcomeCredential
    void proof
    const credential = { ...unsigned, issuer: did }
    const file = join(dir, 'unsigned.json')
    await writeFile(file, JSON.stringify(credential), 'utf8')
    return file
  }

  it('signs with the default eddsa-rdfc-2022 suite', async () => {
    const file = await writeUnsignedCredential()
    const code = await runIssue(file, { did })
    assert.equal(code, 0)
    const signed = JSON.parse(logs[0]) as { proof: Record<string, string> }
    assert.equal(signed.proof.type, 'DataIntegrityProof')
    assert.equal(signed.proof.cryptosuite, 'eddsa-rdfc-2022')
    assert.equal(signed.proof.verificationMethod, keyId)
  })

  it('signs with the Ed25519Signature2020 suite when requested', async () => {
    const file = await writeUnsignedCredential()
    const code = await runIssue(file, { did, suite: 'Ed25519Signature2020' })
    assert.equal(code, 0)
    const signed = JSON.parse(logs[0]) as { proof: Record<string, string> }
    assert.equal(signed.proof.type, 'Ed25519Signature2020')
    assert.equal(signed.proof.verificationMethod, keyId)
  })

  it('signs when an explicit, authorized --key is given', async () => {
    const file = await writeUnsignedCredential()
    const code = await runIssue(file, { did, key: keyId })
    assert.equal(code, 0)
    const signed = JSON.parse(logs[0]) as { proof: Record<string, string> }
    assert.equal(signed.proof.verificationMethod, keyId)
  })

  it('returns exit code 1 when --key is not in assertionMethod', async () => {
    const file = await writeUnsignedCredential()
    const code = await runIssue(file, {
      did,
      key: 'did:key:zNOTREAL#zNOTREAL'
    })
    assert.equal(code, 1)
    assert.equal(logs.length, 0)
    assert.ok(
      errors[0].includes(
        "Specified key is not authorized by the DID's assertionMethod array"
      )
    )
  })

  it('returns exit code 2 on malformed input JSON', async () => {
    const file = join(dir, 'bad.json')
    await writeFile(file, 'not json', 'utf8')
    const code = await runIssue(file, { did })
    assert.equal(code, 2)
    assert.ok(errors[0].startsWith('Could not read credential:'))
  })

  it('produces a credential whose signature verifies', async () => {
    const file = await writeUnsignedCredential()
    const code = await runIssue(file, { did })
    assert.equal(code, 0)
    const signed = JSON.parse(logs[0]) as object
    const result = await verifyCredentialFully({
      credential: signed,
      registries: []
    })
    assert.equal(toSummary(result).checks.signature, true)
  })

  it('sets the issuer to the signing DID when none is present', async () => {
    const { proof, issuer, ...unsigned } = welcomeCredential
    void proof
    void issuer
    const file = join(dir, 'no-issuer.json')
    await writeFile(file, JSON.stringify(unsigned), 'utf8')
    const code = await runIssue(file, { did })
    assert.equal(code, 0)
    const signed = JSON.parse(logs[0]) as { issuer: string }
    assert.equal(signed.issuer, did)
  })

  it('aborts when the issuer does not match the signing DID', async () => {
    const { proof, ...unsigned } = welcomeCredential
    void proof
    const credential = { ...unsigned, issuer: 'did:key:zMISMATCH' }
    const file = join(dir, 'wrong-issuer.json')
    await writeFile(file, JSON.stringify(credential), 'utf8')
    const code = await runIssue(file, { did })
    assert.equal(code, 1)
    assert.equal(logs.length, 0)
    assert.ok(
      errors[0].includes(
        "Signing DID does not match the existing 'issuer' property"
      )
    )
  })
})

describe('did vc issue with did:web', () => {
  let logs: string[]
  let errors: string[]
  let dir: string
  let originalDidsDir: string | undefined
  let did: string
  let keyId: string

  beforeEach(async () => {
    logs = []
    errors = []
    mock.method(console, 'log', (...args: unknown[]) =>
      logs.push(args.join(' '))
    )
    mock.method(console, 'error', (...args: unknown[]) =>
      errors.push(args.join(' '))
    )
    dir = await mkdtemp(join(tmpdir(), 'did-cli-sign-web-test-'))
    originalDidsDir = process.env.DIDS_DIR
    process.env.DIDS_DIR = dir
    ;({ did, keyId } = await createSavedDidWeb())
  })

  afterEach(async () => {
    mock.restoreAll()
    if (originalDidsDir === undefined) {
      delete process.env.DIDS_DIR
    } else {
      process.env.DIDS_DIR = originalDidsDir
    }
    await rm(dir, { recursive: true })
  })

  /**
   * Writes the unsigned credential (welcomeCredential without its `proof`, with
   * the issuer set to the test did:web) to a file and returns its path.
   */
  async function writeUnsignedCredential(): Promise<string> {
    const { proof, ...unsigned } = welcomeCredential
    void proof
    const credential = { ...unsigned, issuer: did }
    const file = join(dir, 'unsigned.json')
    await writeFile(file, JSON.stringify(credential), 'utf8')
    return file
  }

  it('signs with the default assertionMethod key from the keyed map', async () => {
    const file = await writeUnsignedCredential()
    const code = await runIssue(file, { did })
    assert.equal(code, 0)
    const signed = JSON.parse(logs[0]) as { proof: Record<string, string> }
    assert.equal(signed.proof.cryptosuite, 'eddsa-rdfc-2022')
    assert.equal(signed.proof.verificationMethod, keyId)
  })

  it('signs when an explicit, authorized --key is given', async () => {
    const file = await writeUnsignedCredential()
    const code = await runIssue(file, { did, key: keyId })
    assert.equal(code, 0)
    const signed = JSON.parse(logs[0]) as { proof: Record<string, string> }
    assert.equal(signed.proof.verificationMethod, keyId)
  })
})
