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
 * capabilities). Everything addressed to the human -- the approval link and
 * the progress notes -- goes to stderr, so stdout stays pipe-clean.
 */
import { driver } from '@interop/did-method-key'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'
import type { IZcap } from '@interop/data-integrity-core/zcap'
import { sanitizeStorageId, saveToCollection } from '../../storage.js'
import { resolveDidRef, resolveZcapRef } from '../../meta.js'
import { encodeCapability } from '../../zcap/encoding.js'
import {
  awaitGrantedCapabilities,
  buildCapabilityRequest,
  openGrantExchange,
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
    return (await resolveZcapRef({ ref: handle })) !== undefined
  } catch {
    // Resolution throws when the handle already matches more than one stored
    // item, which is itself proof that it is taken.
    return true
  }
}

/**
 * Files the received capabilities in the local zcap store. The request carries
 * one capability query, so one capability is the expected answer; any extras
 * are saved under the same handle with a numeric suffix, which keeps every
 * handle unambiguous for later lookup.
 *
 * @param options {object}
 * @param options.zcaps {IZcap[]}
 * @param options.handle {string}
 * @param [options.description] {string}
 * @returns {Promise<string[]>}   The saved file paths.
 */
async function saveCapabilities({
  zcaps,
  handle,
  description
}: {
  zcaps: IZcap[]
  handle: string
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
      handle: index === 0 ? handle : `${handle}-${index + 1}`,
      description
    })
  }
  return savedPaths
}

/**
 * Requests a capability from a user's wallet: mints the grantee key, opens an
 * ephemeral exchange carrying a zcap-only VPR, prints the interaction URL for
 * the user to open, then waits for their approval and records what came back.
 *
 * @param options {object}
 * @param [options.collection] {string}   The collection to request (default
 *   `web`).
 * @param [options.action] {string[]}   The actions to request.
 * @param [options.reason] {string}   Why access is wanted, shown at consent.
 * @param [options.server] {string}   The WAS server base URL.
 * @param [options.save] {boolean}   Persist the key and capabilities
 *   (default true).
 * @param [options.handle] {string}   Handle to file them under.
 * @param [options.description] {string}   Longer description for the sidecar.
 * @param [options.timeout] {string}   Seconds to wait for approval.
 * @param [options.json] {boolean}   Print one JSON object instead of prose.
 * @returns {Promise<number>}   The process exit code.
 */
export async function runRequestGrant(options: {
  collection?: string
  action?: string[]
  reason?: string
  server?: string
  save?: boolean
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
    const server = options.server ?? process.env.WAS_SERVER_URL
    if (!server) {
      throw new Error(
        'No WAS server URL: provide --server or set WAS_SERVER_URL.'
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
    const handle = options.handle ?? DEFAULT_HANDLE
    if (save && (await isHandleTaken({ handle }))) {
      console.error(
        `The handle "${handle}" is already taken by a stored DID or ` +
          'capability; pass a different --handle.'
      )
      return 2
    }
    const { did: controller, keyPair, didDocument } = await mintAgentKey()
    const request = buildCapabilityRequest({
      controller,
      collection,
      ...(options.action !== undefined && { actions: options.action }),
      ...(options.reason !== undefined && { reason: options.reason })
    })
    const { exchangeUrl, interactionUrl } = await openGrantExchange({
      server,
      request
    })

    console.error(
      `Requesting "${collection}" access for ${controller}.\n` +
        `Open this in your wallet to approve:\n\n  ${interactionUrl}\n\n` +
        'Waiting for approval...'
    )

    const zcaps = await awaitGrantedCapabilities({ exchangeUrl, timeoutMs })
    let savedPaths: string[] = []
    if (save) {
      const description =
        options.description !== undefined
          ? { description: options.description }
          : {}
      await saveAgentDid({ keyPair, didDocument, handle, ...description })
      savedPaths = await saveCapabilities({ zcaps, handle, ...description })
    }
    for (const savedPath of savedPaths) {
      console.error(`Capability saved to ${savedPath}`)
    }
    if (!save) {
      console.error(
        'Not saved (--no-save): the grantee key was discarded, so these ' +
          'capabilities cannot be invoked by a later command.'
      )
    }

    const encoded = zcaps.map(zcap => encodeCapability(zcap))
    if (options.json) {
      console.log(
        JSON.stringify(
          {
            controller,
            ...(save && { handle }),
            interactionUrl,
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
      save
        ? `Granted. Use it with --capability ${handle}, for example:\n` +
            `  di was put ./index.html --capability ${handle} ` +
            `--did ${handle} --resource index.html --content-type text/html`
        : 'Granted.'
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
