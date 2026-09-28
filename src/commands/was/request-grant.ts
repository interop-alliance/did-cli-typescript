/**
 * `was request-grant` -- ask a user's wallet for a capability on one of its
 * public collections. The inverse of `was grant`: an agent runs this, the user
 * approves in their wallet, and the agent receives a signed zcap it can then
 * invoke with `was put --capability`.
 *
 * The grantee key is minted here rather than passed in, so the agent driving
 * the CLI never handles key material: the secret goes straight to local DID
 * storage and stdout carries only the capabilities (or, with `--json`, one
 * object holding the DID, the handle, the interaction URL, and the
 * capabilities). A returning agent names its saved key with `--did` instead,
 * so the wallet sees the same grant `controller` and recognizes the agent. Everything addressed to the human -- the approval link and
 * the progress notes -- goes to stderr, so stdout stays pipe-clean.
 */
import { driver } from '@interop/did-method-key'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'
import type { IZcap } from '@interop/data-integrity-core/zcap'
import {
  loadDidMeta,
  loadMetaFromCollection,
  sanitizeStorageId,
  saveToCollection
} from '../../storage.js'
import { resolveDidRef, resolveZcapRef } from '../../meta.js'
import { loadWasSigner } from '../../was/client.js'
import { encodeCapability } from '../../zcap/encoding.js'
import {
  awaitGrantedCapabilities,
  buildCapabilityRequest,
  buildWalletDeepLink,
  openGrantExchange,
  walletRequestRoute,
  GrantRequestError,
  DEFAULT_COLLECTION,
  DEFAULT_TIMEOUT_MS,
  MAX_TIMEOUT_MS
} from '../../was/request-grant.js'
import { saveDidArtifacts } from '../did/create.js'
import {
  requireSaveForMetaFlags,
  writeCreateMeta
} from '../collection-command.js'
import { reportError } from './shared.js'

/** The zcap wallet collection received capabilities are saved into. */
const ZCAP_COLLECTION = 'zcaps'

/** The handle the minted key and received capabilities are filed under. */
const DEFAULT_HANDLE = 'agent'

/**
 * Mints the Ed25519 `did:key` the capabilities will be delegated to, holding
 * it in memory only. Nothing is written yet: an exchange that is declined,
 * expires, or times out must not leave a DID behind, since every abandoned run
 * would otherwise file another key under the same handle and make later
 * lookups of that handle ambiguous.
 *
 * @returns {Promise<{did: string, keyPair: Ed25519VerificationKey, didDocument: object}>}
 */
async function mintAgentKey(): Promise<{
  did: string
  keyPair: Ed25519VerificationKey
  didDocument: object
}> {
  const keyPair = await Ed25519VerificationKey.generate()
  const didDriver = driver()
  didDriver.use({ keyPairClass: Ed25519VerificationKey })
  const { didDocument } = await didDriver.fromKeyPair({
    verificationKeyPair: keyPair
  })
  return { did: (didDocument as { id: string }).id, keyPair, didDocument }
}

/**
 * Writes the minted key to local DID storage, once the grant it was minted for
 * has actually arrived. Only a saved key can sign a later
 * `was put --capability`, since that resolves its signer out of the DID store.
 *
 * @param options {object}
 * @param options.keyPair {Ed25519VerificationKey}
 * @param options.didDocument {object}
 * @param options.handle {string}
 * @param [options.description] {string}
 * @returns {Promise<void>}
 */
async function saveAgentDid({
  keyPair,
  didDocument,
  handle,
  description
}: {
  keyPair: Ed25519VerificationKey
  didDocument: object
  handle: string
  description?: string
}): Promise<void> {
  const exported = await keyPair.export({ publicKey: true, secretKey: true })
  await saveDidArtifacts({
    method: 'key',
    didDocument,
    exportedKeys: exported,
    fingerprints: [
      (exported as { publicKeyMultibase?: string }).publicKeyMultibase
    ],
    handle,
    description
  })
}

/**
 * Reports whether a handle is already filed against a stored DID or zcap. A
 * run claims the handle in both stores at once, so a collision in either makes
 * a later `--did <handle>` or `--capability <handle>` ambiguous.
 *
 * @param options {object}
 * @param options.handle {string}
 * @returns {Promise<boolean>}
 */
async function isHandleTaken({ handle }: { handle: string }): Promise<boolean> {
  try {
    if (await resolveDidRef({ ref: handle })) {
      return true
    }
  } catch {
    // Resolution throws when the handle already matches more than one stored
    // item, which is itself proof that it is taken.
    return true
  }
  return isZcapHandleTaken({ handle })
}

/**
 * Reports whether a handle already names a stored zcap, so filing another
 * capability under it would make `--capability <handle>` ambiguous.
 *
 * @param options {object}
 * @param options.handle {string}
 * @returns {Promise<boolean>}
 */
async function isZcapHandleTaken({
  handle
}: {
  handle: string
}): Promise<boolean> {
  try {
    return (await resolveZcapRef({ ref: handle })) !== undefined
  } catch {
    // Ambiguous already, so taken.
    return true
  }
}

/**
 * Picks `count` handles that no stored zcap uses yet: `base` itself if free,
 * then `base-2`, `base-3`, and so on. A reused key keeps its handle while its
 * earlier grants hold `base` (and maybe some suffixes), so a new grant lands
 * on the next free suffix rather than colliding with them.
 *
 * @param options {object}
 * @param options.base {string}
 * @param options.count {number}
 * @returns {Promise<string[]>}
 */
async function freeZcapHandles({
  base,
  count
}: {
  base: string
  count: number
}): Promise<string[]> {
  const handles: string[] = []
  for (let suffix = 1; handles.length < count; suffix += 1) {
    const candidate = suffix === 1 ? base : `${base}-${suffix}`
    if (!(await isZcapHandleTaken({ handle: candidate }))) {
      handles.push(candidate)
    }
  }
  return handles
}

/**
 * Picks one handle per received capability. A capability already in the store
 * (the wallet re-returned an earlier grant with the same `id`) keeps the
 * handle it was filed under, so `--capability <handle>` keeps working. Each
 * new capability takes the next free handle from `base`.
 *
 * @param options {object}
 * @param options.zcaps {IZcap[]}
 * @param options.base {string}
 * @returns {Promise<string[]>}   One per capability, in order.
 */
async function assignZcapHandles({
  zcaps,
  base
}: {
  zcaps: IZcap[]
  base: string
}): Promise<string[]> {
  const storedHandles = await Promise.all(
    zcaps.map(
      async zcap =>
        (
          await loadMetaFromCollection({
            collection: ZCAP_COLLECTION,
            storageId: sanitizeStorageId(zcap.id)
          })
        )?.handle
    )
  )
  const freeHandles = await freeZcapHandles({
    base,
    count: storedHandles.filter(handle => handle === undefined).length
  })
  return storedHandles.map(handle => handle ?? freeHandles.shift()!)
}

/**
 * Loads a stored key to sign the request with instead of minting one. It
 * must be a did:key with an Ed25519 signing key, the same check a later
 * `was put --did` applies, so a key that could not invoke the grant is
 * refused before any exchange is opened.
 *
 * @param options {object}
 * @param options.ref {string}   A stored DID or its handle.
 * @returns {Promise<{did: string, handle?: string}>}
 */
async function loadAgentKey({
  ref
}: {
  ref: string
}): Promise<{ did: string; handle?: string }> {
  const { did } = await loadWasSigner({ did: ref })
  const handle = (await loadDidMeta({ did }))?.handle
  return { did, ...(handle !== undefined && { handle }) }
}

/**
 * Files the received capabilities in the local zcap store, one handle per
 * capability. The request carries one capability query, so one capability is
 * the expected answer; the caller picks free handles for any extras, which
 * keeps every handle unambiguous for later lookup.
 *
 * @param options {object}
 * @param options.zcaps {IZcap[]}
 * @param options.handles {string[]}   One per capability, in order.
 * @param [options.description] {string}
 * @returns {Promise<string[]>}   The saved file paths.
 */
async function saveCapabilities({
  zcaps,
  handles,
  description
}: {
  zcaps: IZcap[]
  handles: string[]
  description?: string
}): Promise<string[]> {
  const savedPaths: string[] = []
  for (const [index, zcap] of zcaps.entries()) {
    const storageId = sanitizeStorageId(zcap.id)
    savedPaths.push(
      await saveToCollection({
        collection: ZCAP_COLLECTION,
        storageId,
        data: zcap
      })
    )
    await writeCreateMeta({
      collection: ZCAP_COLLECTION,
      storageId,
      created: new Date().toISOString(),
      handle: handles[index],
      description,
      // A re-returned capability keeps its original timestamp.
      mergeExisting: true
    })
  }
  return savedPaths
}

/**
 * Requests a capability from a user's wallet: mints the grantee key (or loads
 * the stored one named by `did`), opens an ephemeral exchange carrying a zcap-only VPR, prints the interaction URL for
 * the user to open, then waits for their approval and records what came back.
 *
 * @param options {object}
 * @param [options.collection] {string}   The collection to request (default
 *   `web`).
 * @param [options.action] {string[]}   The actions to request.
 * @param [options.reason] {string}   Why access is wanted, shown at consent.
 * @param [options.name] {string}   The agent's self-declared display name,
 *   shown at consent as what it calls itself.
 * @param [options.exchange] {string}   Base URL of the WAS server that hosts
 *   the ephemeral exchange carrying the request (the grant itself may land on
 *   any space the wallet picks).
 * @param [options.wallet] {string}   A wallet base URL to print an approval
 *   deep link for, beside the interaction URL.
 * @param [options.save] {boolean}   Persist the key and capabilities
 *   (default true).
 * @param [options.did] {string}   A stored did:key (or its handle) to request
 *   the grant for instead of minting a key.
 * @param [options.handle] {string}   Handle to file them under. With `did`,
 *   names the capabilities only (default: the next free suffix of the key's
 *   handle).
 * @param [options.description] {string}   Longer description for the sidecar.
 * @param [options.timeout] {string}   Seconds to wait for approval.
 * @param [options.json] {boolean}   Print one JSON object instead of prose.
 * @returns {Promise<number>}   The process exit code.
 */
export async function runRequestGrant(options: {
  collection?: string
  action?: string[]
  reason?: string
  name?: string
  exchange?: string
  wallet?: string
  save?: boolean
  did?: string
  handle?: string
  description?: string
  timeout?: string
  json?: boolean
}): Promise<number> {
  const save = options.save !== false
  try {
    if (
      !requireSaveForMetaFlags({
        save,
        ...(options.handle !== undefined && { handle: options.handle }),
        ...(options.description !== undefined && {
          description: options.description
        })
      })
    ) {
      return 2
    }
    const exchange = options.exchange ?? process.env.WAS_SERVER_URL
    if (!exchange) {
      throw new Error(
        'No exchange server URL: provide --exchange or set WAS_SERVER_URL.'
      )
    }
    const timeoutMs =
      options.timeout === undefined
        ? DEFAULT_TIMEOUT_MS
        : Number(options.timeout) * 1000
    if (
      !Number.isFinite(timeoutMs) ||
      timeoutMs <= 0 ||
      timeoutMs > MAX_TIMEOUT_MS
    ) {
      throw new Error(
        `Invalid --timeout "${options.timeout}": use seconds, up to ` +
          `${Math.floor(MAX_TIMEOUT_MS / 1000)}.`
      )
    }

    const collection = options.collection ?? DEFAULT_COLLECTION
    const walletRoute =
      options.wallet === undefined
        ? undefined
        : walletRequestRoute({ wallet: options.wallet })

    // A reused key is already saved and keeps its own handle, so the handle
    // (explicit or derived) names only the capabilities.
    const reused =
      options.did === undefined
        ? undefined
        : await loadAgentKey({ ref: options.did })
    const baseHandle = options.handle ?? reused?.handle ?? DEFAULT_HANDLE
    if (
      save &&
      reused === undefined &&
      (await isHandleTaken({ handle: baseHandle }))
    ) {
      console.error(
        `The handle "${baseHandle}" is already taken by a stored DID or ` +
          'capability; pass a different --handle.'
      )
      return 2
    }
    if (save && reused !== undefined) {
      if (options.handle === undefined && reused.handle === undefined) {
        console.error(
          `The stored DID ${reused.did} has no handle to file the ` +
            'capabilities under; pass --handle.'
        )
        return 2
      }
      if (
        options.handle !== undefined &&
        (await isZcapHandleTaken({ handle: options.handle }))
      ) {
        console.error(
          `The handle "${options.handle}" is already taken by a stored ` +
            'capability; pass a different --handle.'
        )
        return 2
      }
    }
    const minted = reused === undefined ? await mintAgentKey() : undefined
    const controller = reused?.did ?? minted!.did
    const request = buildCapabilityRequest({
      controller,
      collection,
      ...(options.action !== undefined && { actions: options.action }),
      ...(options.reason !== undefined && { reason: options.reason }),
      ...(options.name !== undefined && { name: options.name })
    })
    const { exchangeUrl, interactionUrl } = await openGrantExchange({
      exchange,
      request
    })

    const walletUrl =
      walletRoute === undefined
        ? undefined
        : buildWalletDeepLink({ route: walletRoute, interactionUrl })

    console.error(
      `Requesting "${collection}" access for ${controller}.\n` +
        `Open this in your wallet to approve:\n\n  ${interactionUrl}\n\n` +
        (walletUrl === undefined
          ? ''
          : `Or open your wallet directly:\n\n  ${walletUrl}\n\n`) +
        'Waiting for approval...'
    )

    const zcaps = await awaitGrantedCapabilities({ exchangeUrl, timeoutMs })
    let savedPaths: string[] = []
    let handles: string[] = []
    if (save) {
      const description =
        options.description !== undefined
          ? { description: options.description }
          : {}
      handles = await assignZcapHandles({ zcaps, base: baseHandle })
      if (minted !== undefined) {
        await saveAgentDid({
          keyPair: minted.keyPair,
          didDocument: minted.didDocument,
          handle: baseHandle,
          ...description
        })
      }
      savedPaths = await saveCapabilities({ zcaps, handles, ...description })
    }
    for (const savedPath of savedPaths) {
      console.error(`Capability saved to ${savedPath}`)
    }
    if (!save) {
      console.error(
        minted === undefined
          ? 'Not saved (--no-save): the capabilities were not stored.'
          : 'Not saved (--no-save): the grantee key was discarded, so these ' +
              'capabilities cannot be invoked by a later command.'
      )
    }
    const handle = handles[0]
    const didRef =
      minted === undefined ? (reused?.handle ?? controller) : baseHandle

    const encoded = zcaps.map(zcap => encodeCapability(zcap))
    if (options.json) {
      console.log(
        JSON.stringify(
          {
            controller,
            ...(handle !== undefined && { handle }),
            interactionUrl,
            ...(walletUrl !== undefined && { walletUrl }),
            capabilities: zcaps,
            encoded
          },
          null,
          2
        )
      )
      return 0
    }
    console.error(
      handle === undefined
        ? 'Granted.'
        : `Granted. Use it with --capability ${handle}, for example:\n` +
            `  di was put ./index.html --capability ${handle} ` +
            `--did ${didRef} --resource index.html --content-type text/html`
    )
    for (const value of encoded) {
      console.log(value)
    }
    return 0
  } catch (err) {
    if (err instanceof GrantRequestError) {
      console.error(`Could not request a grant: ${err.message}`)
      return 1
    }
    return reportError({ action: 'request a grant', err })
  }
}
