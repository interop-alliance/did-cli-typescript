import { describe, it, beforeEach, afterEach, mock } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, rm } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { makeWasCommand } from '../was.js'
import {
  awaitGrantedCapabilities,
  buildCapabilityRequest,
  buildWalletDeepLink,
  extractCapabilities,
  setExchangeFetch,
  walletRequestRoute,
  PUBLIC_COLLECTION_TYPE
} from '../../was/request-grant.js'
import { listCollection, loadFromCollection, listDids } from '../../storage.js'

const SERVER = 'https://was.example'
const EXCHANGE_URL = `${SERVER}/workflows/ephemeral/exchanges/abc-123`

/**
 * A capability shaped like one a wallet delegates back for a
 * `#public-collection` request.
 */
function makeZcap({
  id = 'urn:uuid:granted-1',
  controller = 'did:key:z6MkAgent'
} = {}) {
  return {
    '@context': ['https://w3id.org/zcap/v1'],
    id,
    parentCapability: 'urn:zcap:root:encoded-space-url',
    controller,
    invocationTarget: `${SERVER}/space/abc/web`,
    allowedAction: ['GET', 'HEAD', 'POST', 'PUT'],
    expires: '2027-01-01T00:00:00Z',
    proof: { type: 'Ed25519Signature2020' }
  }
}

/**
 * Installs a stub `fetch` standing in for the server's ephemeral-exchange
 * facet: a create POST returning the exchange location, then polls that go
 * `pending` for `pendingPolls` ticks before completing with `response`.
 * Records every request so the wire payload can be asserted.
 */
function setUpExchangeStub({
  response,
  pendingPolls = 0
}: {
  response?: unknown
  pendingPolls?: number
} = {}) {
  const requests: { url: string; method: string; body?: unknown }[] = []
  let polls = 0
  setExchangeFetch(async (url: string, init?: RequestInit) => {
    const method = init?.method ?? 'GET'
    const body =
      typeof init?.body === 'string' ? JSON.parse(init.body) : undefined
    requests.push({ url, method, ...(body !== undefined && { body }) })
    if (method === 'POST') {
      return new Response(JSON.stringify({ location: EXCHANGE_URL }), {
        status: 201,
        headers: { 'content-type': 'application/json' }
      })
    }
    polls += 1
    if (polls <= pendingPolls) {
      return new Response(
        JSON.stringify({ id: 'abc-123', sequence: 0, state: 'pending' }),
        { status: 200, headers: { 'content-type': 'application/json' } }
      )
    }
    return new Response(
      JSON.stringify({
        id: 'abc-123',
        sequence: 1,
        state: 'complete',
        response
      }),
      { status: 200, headers: { 'content-type': 'application/json' } }
    )
  })
  return requests
}

describe('buildCapabilityRequest', () => {
  it('builds a zcap-only VPR with a public-collection descriptor', () => {
    const request = buildCapabilityRequest({
      controller: 'did:key:z6MkAgent',
      collection: 'web',
      actions: ['GET', 'put'],
      reason: 'Publish a page'
    })
    assert.deepEqual(request, {
      query: [
        {
          type: 'AuthorizationCapabilityQuery',
          capabilityQuery: [
            {
              reason: 'Publish a page',
              allowedAction: ['GET', 'PUT'],
              controller: 'did:key:z6MkAgent',
              invocationTarget: {
                type: PUBLIC_COLLECTION_TYPE,
                name: 'web'
              }
            }
          ]
        }
      ]
    })
  })

  it('sends no DIDAuthentication query and no domain', () => {
    const request = buildCapabilityRequest({ controller: 'did:key:z6MkAgent' })
    assert.equal(request.domain, undefined)
    assert.equal(request.challenge, undefined)
    const queries = request.query as { type: string }[]
    assert.equal(queries.length, 1)
    assert.equal(queries[0]?.type, 'AuthorizationCapabilityQuery')
  })

  it('defaults to the web collection and GET/HEAD/PUT/POST', () => {
    const request = buildCapabilityRequest({ controller: 'did:key:z6MkAgent' })
    const [query] = request.query as {
      capabilityQuery: {
        allowedAction: string[]
        invocationTarget: { name: string }
      }[]
    }[]
    const [detail] = query!.capabilityQuery
    assert.equal(detail?.invocationTarget.name, 'web')
    assert.deepEqual(detail?.allowedAction, ['GET', 'HEAD', 'PUT', 'POST'])
  })

  it('rejects an unknown action verb', () => {
    assert.throws(
      () =>
        buildCapabilityRequest({
          controller: 'did:key:z6MkAgent',
          actions: ['PATCH']
        }),
      /Unknown action "PATCH"/
    )
  })

  it('carries the agent name as the VPR root agent member when given', () => {
    const request = buildCapabilityRequest({
      controller: 'did:key:z6MkAgent',
      name: 'research-bot'
    })
    assert.deepEqual(
      (request as unknown as { agent?: { name: string } }).agent,
      { name: 'research-bot' }
    )
  })

  it('omits the agent member when no name is given', () => {
    const request = buildCapabilityRequest({ controller: 'did:key:z6MkAgent' })
    assert.equal(
      (request as unknown as { agent?: { name: string } }).agent,
      undefined
    )
  })

  it('passes the collection name through without imposing a naming rule', () => {
    const request = buildCapabilityRequest({
      controller: 'did:key:z6MkAgent',
      collection: 'gen-Ux3v0kQf9aPmB2hZ'
    })
    const [query] = request.query as {
      capabilityQuery: { invocationTarget: { name: string } }[]
    }[]
    assert.equal(
      query!.capabilityQuery[0]?.invocationTarget.name,
      'gen-Ux3v0kQf9aPmB2hZ'
    )
  })
})

describe('extractCapabilities', () => {
  it('reads the zcaps out of the response presentation', () => {
    const zcap = makeZcap()
    const zcaps = extractCapabilities({
      verifiablePresentation: { zcap: [zcap] }
    })
    assert.deepEqual(zcaps, [zcap])
  })

  it('accepts a single zcap that is not wrapped in an array', () => {
    const zcap = makeZcap()
    const zcaps = extractCapabilities({ verifiablePresentation: { zcap } })
    assert.deepEqual(zcaps, [zcap])
  })

  it('reports a response carrying no presentation', () => {
    assert.throws(() => extractCapabilities({}), /no verifiablePresentation/)
  })

  it('reports an approval that granted nothing', () => {
    assert.throws(
      () => extractCapabilities({ verifiablePresentation: { zcap: [] } }),
      /declined, or the collection could not be granted/
    )
  })

  it('reports a capability that carries no id', () => {
    const withoutId: Record<string, unknown> = { ...makeZcap() }
    delete withoutId.id
    assert.throws(
      () =>
        extractCapabilities({ verifiablePresentation: { zcap: withoutId } }),
      /capability with no id/
    )
  })
})

describe('buildWalletDeepLink', () => {
  it('carries the interaction URL on the external-request route', () => {
    const link = buildWalletDeepLink({
      route: walletRequestRoute({ wallet: 'https://wallet.example' }),
      interactionUrl: `${EXCHANGE_URL}/protocols?iuv=1`
    })
    assert.equal(
      link,
      'https://wallet.example/external/request?url=' +
        encodeURIComponent(`${EXCHANGE_URL}/protocols?iuv=1`)
    )
  })

  it('keeps a wallet deployed under a sub-path', () => {
    const link = buildWalletDeepLink({
      route: walletRequestRoute({ wallet: 'https://example.test/wallet' }),
      interactionUrl: 'https://was.example/exchange'
    })
    assert.match(link, /^https:\/\/example\.test\/wallet\/external\/request\?/)
  })

  it('refuses a wallet URL that is not absolute http(s)', () => {
    assert.throws(
      () => walletRequestRoute({ wallet: 'wallet.example' }),
      /expected an absolute http\(s\) URL/
    )
    assert.throws(
      () => walletRequestRoute({ wallet: 'javascript:alert(1)' }),
      /expected an http\(s\) URL/
    )
  })
})

describe('awaitGrantedCapabilities', () => {
  afterEach(() => {
    setExchangeFetch()
  })

  it('polls until the exchange completes', async () => {
    const requests = setUpExchangeStub({
      response: { verifiablePresentation: { zcap: [makeZcap()] } },
      pendingPolls: 2
    })
    const zcaps = await awaitGrantedCapabilities({
      exchangeUrl: EXCHANGE_URL,
      intervalMs: 1
    })
    assert.equal(zcaps[0]?.id, 'urn:uuid:granted-1')
    const polls = requests.filter(request => request.method === 'GET')
    assert.equal(polls.length, 3)
    assert.ok(polls.every(poll => poll.url === EXCHANGE_URL))
  })
})

describe('was request-grant', () => {
  let walletDir: string
  let logs: string[]
  let errors: string[]
  let exitCode: number | undefined

  beforeEach(async () => {
    walletDir = await mkdtemp(join(tmpdir(), 'did-cli-test-wallet-'))
    process.env.WALLET_DIR = walletDir
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
  })

  afterEach(async () => {
    mock.restoreAll()
    setExchangeFetch()
    delete process.env.WALLET_DIR
    delete process.env.WAS_SERVER_URL
    await rm(walletDir, { recursive: true, force: true })
  })

  it('posts the VPR, prints the interaction URL, and stores the grant', async () => {
    const requests = setUpExchangeStub({
      response: { verifiablePresentation: { zcap: [makeZcap()] } }
    })
    await makeWasCommand().parseAsync(
      ['request-grant', '--server', SERVER, '--reason', 'Publish a page'],
      { from: 'user' }
    )
    assert.equal(exitCode, undefined)

    // The create POST carries the VPR wrapped as a VC-API exchange response.
    const create = requests[0]!
    assert.equal(create.url, `${SERVER}/workflows/ephemeral/exchanges`)
    assert.equal(create.method, 'POST')
    const { verifiablePresentationRequest } = (
      create.body as {
        request: { verifiablePresentationRequest: { query: unknown[] } }
      }
    ).request
    const [query] = verifiablePresentationRequest.query as {
      type: string
      capabilityQuery: {
        controller: string
        invocationTarget: { type: string; name: string }
      }[]
    }[]
    assert.equal(query!.type, 'AuthorizationCapabilityQuery')
    const [detail] = query!.capabilityQuery
    assert.equal(detail!.invocationTarget.type, PUBLIC_COLLECTION_TYPE)
    assert.equal(detail!.invocationTarget.name, 'web')

    // The grantee key is minted here, and it is the query's controller.
    const dids = await listDids()
    assert.equal(dids.length, 1)
    assert.equal(detail!.controller, dids[0])

    // The interaction URL is offered for the user to open.
    assert.match(errors.join('\n'), /\/protocols\?iuv=1/)

    // The capability is filed in the zcap store under the default handle.
    const stored = await listCollection('zcaps')
    assert.equal(stored.length, 1)
    const saved = await loadFromCollection<{ id: string }>({
      collection: 'zcaps',
      storageId: stored[0]!
    })
    assert.equal(saved.id, 'urn:uuid:granted-1')
    assert.match(errors.join('\n'), /--capability agent/)

    // stdout carries the encoded capability, never key material.
    assert.equal(logs.length, 1)
    assert.match(logs[0]!, /^z/)
    assert.doesNotMatch(logs.join('\n'), /secretKeyMultibase/)
  })

  it('requests the named collection and actions', async () => {
    const requests = setUpExchangeStub({
      response: { verifiablePresentation: { zcap: [makeZcap()] } }
    })
    await makeWasCommand().parseAsync(
      [
        'request-grant',
        '--server',
        SERVER,
        '--collection',
        'site',
        '--action',
        'GET',
        'head'
      ],
      { from: 'user' }
    )
    assert.equal(exitCode, undefined)
    const [query] = (
      requests[0]!.body as {
        request: {
          verifiablePresentationRequest: {
            query: {
              capabilityQuery: {
                allowedAction: string[]
                invocationTarget: { name: string }
              }[]
            }[]
          }
        }
      }
    ).request.verifiablePresentationRequest.query
    const [detail] = query!.capabilityQuery
    assert.equal(detail!.invocationTarget.name, 'site')
    assert.deepEqual(detail!.allowedAction, ['GET', 'HEAD'])
  })

  it('sends the agent name as the VPR root agent member with --name', async () => {
    const requests = setUpExchangeStub({
      response: { verifiablePresentation: { zcap: [makeZcap()] } }
    })
    await makeWasCommand().parseAsync(
      ['request-grant', '--server', SERVER, '--name', 'research-bot'],
      { from: 'user' }
    )
    assert.equal(exitCode, undefined)
    const { verifiablePresentationRequest } = (
      requests[0]!.body as {
        request: {
          verifiablePresentationRequest: { agent?: { name: string } }
        }
      }
    ).request
    assert.deepEqual(verifiablePresentationRequest.agent, {
      name: 'research-bot'
    })
  })

  it('rejects an invalid --name before opening any exchange', async () => {
    const requests = setUpExchangeStub({
      response: { verifiablePresentation: { zcap: [makeZcap()] } }
    })
    await makeWasCommand().parseAsync(
      ['request-grant', '--server', SERVER, '--name', 'a'.repeat(65)],
      { from: 'user' }
    )
    assert.equal(exitCode, 2)
    assert.equal(
      requests.filter(request => request.method === 'POST').length,
      0
    )
  })

  it('prints a wallet deep link with --wallet', async () => {
    setUpExchangeStub({
      response: { verifiablePresentation: { zcap: [makeZcap()] } }
    })
    await makeWasCommand().parseAsync(
      [
        'request-grant',
        '--server',
        SERVER,
        '--wallet',
        'https://wallet.example',
        '--json'
      ],
      { from: 'user' }
    )
    assert.equal(exitCode, undefined)
    const { interactionUrl, walletUrl } = JSON.parse(logs.join('\n')) as {
      interactionUrl: string
      walletUrl: string
    }
    assert.equal(
      walletUrl,
      'https://wallet.example/external/request?url=' +
        encodeURIComponent(interactionUrl)
    )
    assert.match(errors.join('\n'), /Or open your wallet directly/)
  })

  it('rejects an invalid --wallet before opening any exchange', async () => {
    const requests = setUpExchangeStub({
      response: { verifiablePresentation: { zcap: [makeZcap()] } }
    })
    await makeWasCommand().parseAsync(
      ['request-grant', '--server', SERVER, '--wallet', 'wallet.example'],
      { from: 'user' }
    )
    assert.equal(exitCode, 2)
    assert.equal(
      requests.filter(request => request.method === 'POST').length,
      0
    )
  })

  it('files the grant under an explicit --handle', async () => {
    setUpExchangeStub({
      response: { verifiablePresentation: { zcap: [makeZcap()] } }
    })
    await makeWasCommand().parseAsync(
      ['request-grant', '--server', SERVER, '--handle', 'publisher'],
      { from: 'user' }
    )
    assert.equal(exitCode, undefined)
    assert.match(errors.join('\n'), /--capability publisher/)
  })

  it('stores nothing with --no-save, and says the grant is unusable', async () => {
    setUpExchangeStub({
      response: { verifiablePresentation: { zcap: [makeZcap()] } }
    })
    await makeWasCommand().parseAsync(
      ['request-grant', '--server', SERVER, '--no-save'],
      { from: 'user' }
    )
    assert.equal(exitCode, undefined)
    assert.deepEqual(await listCollection('zcaps'), [])
    assert.deepEqual(await listDids(), [])
    assert.match(errors.join('\n'), /cannot be invoked by a later command/)
    // The capability is still printed, so it can be inspected.
    assert.match(logs[0]!, /^z/)
  })

  it('rejects --handle without --save', async () => {
    setUpExchangeStub({
      response: { verifiablePresentation: { zcap: [makeZcap()] } }
    })
    await makeWasCommand().parseAsync(
      ['request-grant', '--server', SERVER, '--no-save', '--handle', 'x'],
      { from: 'user' }
    )
    assert.equal(exitCode, 2)
    assert.match(errors[0]!, /--handle and --description require --save/)
  })

  it('prints JSON with --json', async () => {
    setUpExchangeStub({
      response: { verifiablePresentation: { zcap: [makeZcap()] } }
    })
    await makeWasCommand().parseAsync(
      ['request-grant', '--server', SERVER, '--json'],
      { from: 'user' }
    )
    assert.equal(exitCode, undefined)
    const output = JSON.parse(logs.join('\n')) as {
      controller: string
      handle: string
      capabilities: { id: string }[]
      encoded: string[]
    }
    assert.match(output.controller, /^did:key:z6Mk/)
    assert.equal(output.handle, 'agent')
    assert.equal(output.capabilities[0]?.id, 'urn:uuid:granted-1')
    assert.match(output.encoded[0]!, /^z/)
  })

  it('requires a server URL', async () => {
    await makeWasCommand().parseAsync(['request-grant'], { from: 'user' })
    assert.equal(exitCode, 2)
    assert.match(errors[0]!, /No WAS server URL/)
  })

  it('falls back to WAS_SERVER_URL', async () => {
    process.env.WAS_SERVER_URL = SERVER
    const requests = setUpExchangeStub({
      response: { verifiablePresentation: { zcap: [makeZcap()] } }
    })
    await makeWasCommand().parseAsync(['request-grant'], { from: 'user' })
    assert.equal(exitCode, undefined)
    assert.equal(requests[0]?.url, `${SERVER}/workflows/ephemeral/exchanges`)
  })

  it('reports an approval that granted nothing as an operation error', async () => {
    setUpExchangeStub({ response: { verifiablePresentation: { zcap: [] } } })
    await makeWasCommand().parseAsync(['request-grant', '--server', SERVER], {
      from: 'user'
    })
    assert.equal(exitCode, 1)
    assert.match(errors.join('\n'), /declined, or the collection could not/)
  })

  it('reports an expired exchange as an operation error', async () => {
    setExchangeFetch(async (url: string, init?: RequestInit) => {
      if ((init?.method ?? 'GET') === 'POST') {
        return new Response(JSON.stringify({ location: EXCHANGE_URL }), {
          status: 201,
          headers: { 'content-type': 'application/json' }
        })
      }
      return new Response(null, { status: 404 })
    })
    await makeWasCommand().parseAsync(['request-grant', '--server', SERVER], {
      from: 'user'
    })
    assert.equal(exitCode, 1)
    assert.match(errors.join('\n'), /expired before it was approved/)
  })

  it('gives up with a clear message at --timeout', async () => {
    setUpExchangeStub({ pendingPolls: Number.MAX_SAFE_INTEGER })
    await makeWasCommand().parseAsync(
      ['request-grant', '--server', SERVER, '--timeout', '0.05'],
      { from: 'user' }
    )
    assert.equal(exitCode, 1)
    assert.match(errors.join('\n'), /Gave up waiting for approval/)
  })

  it('keeps no DID when the exchange produced no grant', async () => {
    setUpExchangeStub({ response: { verifiablePresentation: { zcap: [] } } })
    await makeWasCommand().parseAsync(['request-grant', '--server', SERVER], {
      from: 'user'
    })
    assert.equal(exitCode, 1)
    // An abandoned run must not leave a key filed under the handle, or the
    // next run's handle lookups become ambiguous.
    assert.deepEqual(await listDids(), [])
  })

  it('refuses a handle already taken by an earlier grant', async () => {
    setUpExchangeStub({
      response: { verifiablePresentation: { zcap: [makeZcap()] } }
    })
    await makeWasCommand().parseAsync(['request-grant', '--server', SERVER], {
      from: 'user'
    })
    assert.equal(exitCode, undefined)
    await makeWasCommand().parseAsync(['request-grant', '--server', SERVER], {
      from: 'user'
    })
    assert.equal(exitCode, 2)
    assert.match(errors.join('\n'), /handle "agent" is already taken/)
    assert.equal((await listDids()).length, 1)
  })

  it('rejects a --timeout past what the wait supports', async () => {
    await makeWasCommand().parseAsync(
      ['request-grant', '--server', SERVER, '--timeout', '5000000'],
      { from: 'user' }
    )
    assert.equal(exitCode, 2)
    assert.match(errors[0]!, /Invalid --timeout/)
  })

  it('rejects a non-numeric --timeout', async () => {
    await makeWasCommand().parseAsync(
      ['request-grant', '--server', SERVER, '--timeout', 'soon'],
      { from: 'user' }
    )
    assert.equal(exitCode, 2)
    assert.match(errors[0]!, /Invalid --timeout/)
  })
})
