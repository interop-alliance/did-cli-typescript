import { describe, it, beforeEach, afterEach, mock } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { Readable } from 'node:stream'
import { driver } from '@interop/did-method-key'
import * as didWeb from '@interop/did-web-resolver'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'
import * as EcdsaMultikey from '@interop/ecdsa-multikey'
import {
  credentialStorageId,
  makeVcCommand,
  runImport,
  runIssue,
  runVerify
} from './vc.js'
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
  const exported = await keyPair.export({ publicKey: true, secretKey: true })
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
    exported[methodId] = await keyPair.export({
      publicKey: true,
      secretKey: true
    })
  }
  await saveToDids({ method: 'web', did, data: didDocument })
  await saveToDids({ method: 'web', did, suffix: 'keys', data: exported })
  return { did, keyId: didDocument.assertionMethod[0] as string }
}

/**
 * Generates an ECDSA (P-256) did:key, saves its DID document and
 * `<did>.keys.json` to the (temp) DIDs storage dir, and returns the DID id and
 * its assertionMethod key id -- mirroring what `did create key --type ecdsa
 * --save` does. ECDSA did:keys are minted via the driver's `fromKeyPair()`, so
 * no suite registration is required.
 */
async function createSavedEcdsaDid(): Promise<{ did: string; keyId: string }> {
  const keyPair = await EcdsaMultikey.generate({ curve: 'P-256' })
  const didDriver = driver()
  const { didDocument } = await didDriver.fromKeyPair({
    verificationKeyPair: keyPair
  })
  const did = didDocument.id as string
  const exported = await keyPair.export({ publicKey: true, secretKey: true })
  await saveToDids({ method: 'key', did, data: didDocument })
  await saveToDids({ method: 'key', did, suffix: 'keys', data: exported })
  return { did, keyId: exported.id as string }
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

describe('did vc issue with ecdsa', () => {
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
    dir = await mkdtemp(join(tmpdir(), 'did-cli-sign-ecdsa-test-'))
    originalDidsDir = process.env.DIDS_DIR
    process.env.DIDS_DIR = dir
    ;({ did, keyId } = await createSavedEcdsaDid())
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
   * the issuer set to the test ecdsa DID) to a file and returns its path.
   */
  async function writeUnsignedCredential(): Promise<string> {
    const { proof, ...unsigned } = welcomeCredential
    void proof
    const credential = { ...unsigned, issuer: did }
    const file = join(dir, 'unsigned.json')
    await writeFile(file, JSON.stringify(credential), 'utf8')
    return file
  }

  it('signs with the default ecdsa-rdfc-2019 suite', async () => {
    const file = await writeUnsignedCredential()
    const code = await runIssue(file, { did })
    assert.equal(code, 0)
    const signed = JSON.parse(logs[0]) as { proof: Record<string, string> }
    assert.equal(signed.proof.type, 'DataIntegrityProof')
    assert.equal(signed.proof.cryptosuite, 'ecdsa-rdfc-2019')
    assert.equal(signed.proof.verificationMethod, keyId)
  })

  it('signs when an explicit, authorized --key is given', async () => {
    const file = await writeUnsignedCredential()
    const code = await runIssue(file, { did, key: keyId })
    assert.equal(code, 0)
    const signed = JSON.parse(logs[0]) as { proof: Record<string, string> }
    assert.equal(signed.proof.cryptosuite, 'ecdsa-rdfc-2019')
    assert.equal(signed.proof.verificationMethod, keyId)
  })

  it('rejects an ed25519 suite for an ecdsa key', async () => {
    const file = await writeUnsignedCredential()
    const code = await runIssue(file, { did, suite: 'eddsa-rdfc-2022' })
    assert.equal(code, 1)
    assert.equal(logs.length, 0)
    assert.ok(errors[0].includes('is not supported for ecdsa keys'))
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
})

/**
 * A sample credential (with an `id`) used as `vc import` input. The `id` maps
 * to the storage id `urn_uuid_badge-credential-1`.
 */
const badgeCredential = {
  '@context': ['https://www.w3.org/ns/credentials/v2'],
  id: 'urn:uuid:badge-credential-1',
  type: ['VerifiableCredential', 'OpenBadgeCredential'],
  issuer: { id: 'did:key:z6MkExampleIssuer', name: 'Example Issuer' },
  validFrom: '2026-01-01T00:00:00Z',
  credentialSubject: { name: 'Test Subject' }
}

describe('did vc import', () => {
  let logs: string[]
  let errors: string[]
  let walletDir: string

  beforeEach(async () => {
    logs = []
    errors = []
    mock.method(console, 'log', (...args: unknown[]) =>
      logs.push(args.join(' '))
    )
    mock.method(console, 'error', (...args: unknown[]) =>
      errors.push(args.join(' '))
    )
    walletDir = await mkdtemp(join(tmpdir(), 'did-cli-vc-import-test-'))
    process.env.WALLET_DIR = walletDir
  })

  afterEach(async () => {
    mock.restoreAll()
    delete process.env.WALLET_DIR
    await rm(walletDir, { recursive: true })
  })

  it('imports a credential from a file and writes a metadata sidecar', async () => {
    const file = join(walletDir, 'input.json')
    await writeFile(file, JSON.stringify(badgeCredential), 'utf8')
    const code = await runImport(file, {
      handle: 'badge',
      description: 'An open badge'
    })
    assert.equal(code, 0)
    assert.ok(errors[0].startsWith('Credential saved to'))

    const storedPath = join(
      walletDir,
      'credentials',
      'urn_uuid_badge-credential-1.json'
    )
    const stored = JSON.parse(await readFile(storedPath, 'utf8')) as object
    assert.deepEqual(stored, badgeCredential)

    const meta = JSON.parse(
      await readFile(
        join(walletDir, 'credentials', 'urn_uuid_badge-credential-1.meta.json'),
        'utf8'
      )
    ) as { created?: string; handle?: string; description?: string }
    assert.ok(meta.created)
    assert.equal(meta.handle, 'badge')
    assert.equal(meta.description, 'An open badge')
  })

  it('imports a credential from stdin', async () => {
    const originalStdin = process.stdin
    const fake = Readable.from([Buffer.from(JSON.stringify(badgeCredential))])
    Object.defineProperty(process, 'stdin', {
      value: fake,
      configurable: true
    })
    try {
      const code = await runImport(undefined, {})
      assert.equal(code, 0)
      const stored = JSON.parse(
        await readFile(
          join(walletDir, 'credentials', 'urn_uuid_badge-credential-1.json'),
          'utf8'
        )
      ) as object
      assert.deepEqual(stored, badgeCredential)
    } finally {
      Object.defineProperty(process, 'stdin', {
        value: originalStdin,
        configurable: true
      })
    }
  })

  it('imports a credential from an https URL', async () => {
    mock.method(
      globalThis,
      'fetch',
      async () =>
        new Response(JSON.stringify(badgeCredential), {
          status: 200,
          headers: { 'content-type': 'application/json' }
        })
    )
    const code = await runImport('https://example.com/credentials/1', {})
    assert.equal(code, 0)
    const stored = JSON.parse(
      await readFile(
        join(walletDir, 'credentials', 'urn_uuid_badge-credential-1.json'),
        'utf8'
      )
    ) as object
    assert.deepEqual(stored, badgeCredential)
  })

  it('returns exit code 2 when the URL fetch fails', async () => {
    mock.method(
      globalThis,
      'fetch',
      async () =>
        new Response('not found', { status: 404, statusText: 'Not Found' })
    )
    const code = await runImport('https://example.com/missing.json', {})
    assert.equal(code, 2)
    assert.ok(errors[0].includes('404'))
  })

  it('derives a deterministic content-hash storage id for an id-less credential', async () => {
    // welcomeCredential carries no `id` property.
    const file = join(walletDir, 'input.json')
    await writeFile(file, JSON.stringify(welcomeCredential), 'utf8')
    const code = await runImport(file, {})
    assert.equal(code, 0)
    const storageId = credentialStorageId({ credential: welcomeCredential })
    assert.match(storageId, /^sha256-[0-9a-f]{24}$/)
    const stored = JSON.parse(
      await readFile(
        join(walletDir, 'credentials', `${storageId}.json`),
        'utf8'
      )
    ) as object
    assert.deepEqual(stored, welcomeCredential)
  })

  it('preserves existing metadata when re-importing the same credential', async () => {
    const file = join(walletDir, 'input.json')
    await writeFile(file, JSON.stringify(badgeCredential), 'utf8')
    assert.equal(await runImport(file, { handle: 'badge' }), 0)
    assert.equal(await runImport(file, {}), 0)
    const meta = JSON.parse(
      await readFile(
        join(walletDir, 'credentials', 'urn_uuid_badge-credential-1.meta.json'),
        'utf8'
      )
    ) as { handle?: string }
    assert.equal(meta.handle, 'badge')
  })

  it('returns exit code 1 for JSON that is not a credential', async () => {
    const file = join(walletDir, 'input.json')
    await writeFile(file, JSON.stringify({ hello: 'world' }), 'utf8')
    const code = await runImport(file, {})
    assert.equal(code, 1)
    assert.ok(errors[0].includes('does not look like a Verifiable Credential'))
  })

  it('returns exit code 2 on malformed JSON', async () => {
    const file = join(walletDir, 'input.json')
    await writeFile(file, 'not json', 'utf8')
    const code = await runImport(file, {})
    assert.equal(code, 2)
    assert.ok(errors[0].startsWith('Could not read credential:'))
  })
})

describe('did vc issue --save', () => {
  let logs: string[]
  let errors: string[]
  let exitCode: number | undefined
  let didsDir: string
  let walletDir: string
  let did: string

  beforeEach(async () => {
    logs = []
    errors = []
    exitCode = undefined
    mock.method(console, 'log', (...args: unknown[]) =>
      logs.push(args.join(' '))
    )
    mock.method(console, 'error', (...args: unknown[]) =>
      errors.push(args.join(' '))
    )
    mock.method(process, 'exit', (code: number) => {
      exitCode = code
    })
    didsDir = await mkdtemp(join(tmpdir(), 'did-cli-issue-save-dids-'))
    walletDir = await mkdtemp(join(tmpdir(), 'did-cli-issue-save-wallet-'))
    process.env.DIDS_DIR = didsDir
    process.env.WALLET_DIR = walletDir
    ;({ did } = await createSavedDid())
  })

  afterEach(async () => {
    mock.restoreAll()
    delete process.env.DIDS_DIR
    delete process.env.WALLET_DIR
    await rm(didsDir, { recursive: true })
    await rm(walletDir, { recursive: true })
  })

  /**
   * Writes the unsigned credential (welcomeCredential without its `proof`, with
   * the issuer set to the test DID) to a file and returns its path.
   */
  async function writeUnsignedCredential(): Promise<string> {
    const { proof, ...unsigned } = welcomeCredential
    void proof
    const credential = { ...unsigned, issuer: did }
    const file = join(didsDir, 'unsigned.json')
    await writeFile(file, JSON.stringify(credential), 'utf8')
    return file
  }

  it('--save writes the issued credential and sidecar to WALLET_DIR/credentials', async () => {
    const file = await writeUnsignedCredential()
    const code = await runIssue(file, { did, save: true, handle: 'welcome' })
    assert.equal(code, 0)
    assert.ok(errors[0].startsWith('Credential saved to'))

    const signed = JSON.parse(logs[0]) as object
    const storageId = credentialStorageId({ credential: signed })
    const stored = JSON.parse(
      await readFile(
        join(walletDir, 'credentials', `${storageId}.json`),
        'utf8'
      )
    ) as object
    assert.deepEqual(stored, signed)

    const meta = JSON.parse(
      await readFile(
        join(walletDir, 'credentials', `${storageId}.meta.json`),
        'utf8'
      )
    ) as { created?: string; handle?: string }
    assert.ok(meta.created)
    assert.equal(meta.handle, 'welcome')
  })

  it('--handle and --description require --save', async () => {
    await makeVcCommand().parseAsync(
      ['issue', 'unused.json', '--did', did, '--handle', 'welcome'],
      { from: 'user' }
    )
    assert.equal(exitCode, 1)
    assert.equal(errors[0], '--handle and --description require --save')
  })
})

describe('did vc list/show/meta/remove', () => {
  let logs: string[]
  let errors: string[]
  let exitCode: number | undefined
  let walletDir: string

  beforeEach(async () => {
    logs = []
    errors = []
    exitCode = undefined
    mock.method(console, 'log', (...args: unknown[]) =>
      logs.push(args.join(' '))
    )
    mock.method(console, 'error', (...args: unknown[]) =>
      errors.push(args.join(' '))
    )
    mock.method(process, 'exit', (code: number) => {
      exitCode = code
    })
    walletDir = await mkdtemp(join(tmpdir(), 'did-cli-vc-store-test-'))
    process.env.WALLET_DIR = walletDir
  })

  afterEach(async () => {
    mock.restoreAll()
    delete process.env.WALLET_DIR
    await rm(walletDir, { recursive: true })
  })

  /**
   * Imports the badge credential (with handle/description metadata) into the
   * temp wallet, mirroring `vc import badge.json --handle badge ...`.
   */
  async function importBadge(): Promise<void> {
    const file = join(walletDir, 'badge.json')
    await writeFile(file, JSON.stringify(badgeCredential), 'utf8')
    assert.equal(
      await runImport(file, { handle: 'badge', description: 'An open badge' }),
      0
    )
  }

  it('list prints a metadata table by default', async () => {
    await importBadge()
    logs = []
    await makeVcCommand().parseAsync(['list'], { from: 'user' })
    const [header, separator, row] = logs[0].split('\n')
    assert.match(header, /HANDLE\s+TYPE\s+ISSUER\s+CREATED\s+ID\s+DESCRIPTION/)
    assert.ok(separator.startsWith('-'))
    assert.match(row, /badge\s+OpenBadgeCredential/)
    assert.ok(row.includes('urn:uuid:badge-credential-1'))
  })

  it('list --json outputs id, type, issuer, and metadata', async () => {
    await importBadge()
    logs = []
    await makeVcCommand().parseAsync(['list', '--json'], { from: 'user' })
    const entries = JSON.parse(logs[0]) as Record<string, string>[]
    assert.equal(entries.length, 1)
    assert.equal(entries[0].id, 'urn:uuid:badge-credential-1')
    assert.equal(entries[0].type, 'OpenBadgeCredential')
    assert.equal(entries[0].issuer, 'did:key:z6MkExampleIssuer')
    assert.equal(entries[0].handle, 'badge')
    assert.equal(entries[0].description, 'An open badge')
  })

  it('list --plain prints credential ids, one per line', async () => {
    await importBadge()
    logs = []
    await makeVcCommand().parseAsync(['list', '--plain'], { from: 'user' })
    assert.deepEqual(logs, ['urn:uuid:badge-credential-1'])
  })

  it('show prints the stored credential by credential id', async () => {
    await importBadge()
    logs = []
    await makeVcCommand().parseAsync(['show', 'urn:uuid:badge-credential-1'], {
      from: 'user'
    })
    assert.deepEqual(JSON.parse(logs[0]), badgeCredential)
  })

  it('show accepts a metadata handle', async () => {
    await importBadge()
    logs = []
    await makeVcCommand().parseAsync(['show', 'badge'], { from: 'user' })
    assert.deepEqual(JSON.parse(logs[0]), badgeCredential)
  })

  it('show --meta --json prints metadata with issuer and validFrom', async () => {
    await importBadge()
    logs = []
    await makeVcCommand().parseAsync(['show', 'badge', '--meta', '--json'], {
      from: 'user'
    })
    const meta = JSON.parse(logs[0]) as Record<string, string>
    assert.equal(meta.id, 'urn:uuid:badge-credential-1')
    assert.equal(meta.type, 'OpenBadgeCredential')
    assert.equal(meta.handle, 'badge')
    assert.equal(meta.issuer, 'did:key:z6MkExampleIssuer')
    assert.equal(meta.validFrom, '2026-01-01T00:00:00Z')
  })

  it('show exits 1 when no stored credential matches', async () => {
    await makeVcCommand().parseAsync(['show', 'nope'], { from: 'user' })
    assert.equal(exitCode, 1)
    assert.ok(errors[0].includes('No locally stored credential found'))
  })

  it('meta edits the metadata sidecar', async () => {
    await importBadge()
    logs = []
    await makeVcCommand().parseAsync(
      ['meta', 'badge', '--description', 'Updated description'],
      { from: 'user' }
    )
    const meta = JSON.parse(logs[0]) as Record<string, string>
    assert.equal(meta.handle, 'badge')
    assert.equal(meta.description, 'Updated description')
    const sidecar = JSON.parse(
      await readFile(
        join(walletDir, 'credentials', 'urn_uuid_badge-credential-1.meta.json'),
        'utf8'
      )
    ) as Record<string, string>
    assert.equal(sidecar.description, 'Updated description')
  })

  it('remove deletes the credential and its sidecar', async () => {
    await importBadge()
    errors = []
    await makeVcCommand().parseAsync(['remove', 'badge'], { from: 'user' })
    assert.equal(errors.length, 2)
    assert.ok(errors[0].startsWith('Removed '))
    await makeVcCommand().parseAsync(['show', 'urn:uuid:badge-credential-1'], {
      from: 'user'
    })
    assert.equal(exitCode, 1)
  })
})
