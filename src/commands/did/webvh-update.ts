/**
 * did:webvh update-key plumbing and the `rotate-keys` runner. A stored
 * did:webvh is authored by appending entries to its history log (the source of
 * truth); each entry must be signed by an update (authorization) key. This
 * module owns the shared machinery for that -- loading and resolving the log,
 * selecting the signer (ordinary active key vs. a pre-rotation staged reveal),
 * and persisting the update-keys sidecar -- plus `runRotateKeys`, which rotates
 * the update key itself. The service-update and create runners reuse these
 * helpers.
 */
import { createInterface } from 'node:readline/promises'
import { stdin, stdout } from 'node:process'
import {
  deriveNextKeyHash,
  resolveDIDFromLog,
  updateDID,
  type DIDLog
} from '@interop/did-method-webvh'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'
import {
  loadDidLog,
  loadDidUpdateKeys,
  saveDidLog,
  saveDidUpdateKeys,
  saveToDids,
  type WebvhUpdateKey,
  type WebvhUpdateKeys
} from '../../storage.js'
import { resolveDidRef } from '../../meta.js'
import { deriveSeed } from '../../keys/seed.js'
import { makeWebvhSigner } from '../../keys/webvh-signer.js'
import {
  exportUpdateKey,
  generateStagedKey,
  loadUpdateKey
} from '../../keys/webvh-update.js'

/**
 * Parse a raw did:webvh history log (newline-delimited JSON) into the entry
 * array the library's resolver/updater expect, ignoring blank lines.
 *
 * @param logText {string}
 * @returns {DIDLog}
 */
export function parseDidLog(logText: string): DIDLog {
  return logText
    .split('\n')
    .filter(line => line.trim().length > 0)
    .map(line => JSON.parse(line)) as DIDLog
}

/**
 * Ask the user to confirm a hard-to-undo action. Returns true immediately when
 * `--yes` was passed. When stdin is not an interactive TTY the question cannot
 * be asked, so the action is refused (with a hint to pass `--yes`) rather than
 * silently confirmed -- a script or cron job must opt in explicitly. Otherwise
 * prompts and requires an explicit `y`.
 *
 * @param options {object}
 * @param options.message {string}
 * @param options.yes {boolean} the value of the `--yes` flag.
 * @returns {Promise<boolean>}
 */
export async function confirmAction({
  message,
  yes
}: {
  message: string
  yes?: boolean
}): Promise<boolean> {
  if (yes) {
    return true
  }
  if (!stdin.isTTY) {
    console.error(
      'This action needs confirmation, but stdin is not interactive; ' +
        'pass --yes to proceed.'
    )
    return false
  }
  const rl = createInterface({ input: stdin, output: stdout })
  try {
    const answer = await rl.question(`${message} [y/N] `)
    return answer.trim().toLowerCase() === 'y'
  } finally {
    rl.close()
  }
}

/**
 * Load and resolve a locally stored did:webvh history log in preparation for an
 * update, asserting it is updatable. The log is the source of truth for a
 * stored did:webvh, so its absence is what "not locally stored" means.
 *
 * @param options {object}
 * @param options.targetDid {string} the resolved did:webvh DID.
 * @param options.action {string} verb used in error messages (e.g.
 *   `rotate keys`, `update services`).
 * @returns {Promise<{ log, doc, meta }>}
 * @throws {Error} with a user-facing message if the log is missing, fails to
 *   resolve, or the DID is deactivated.
 */
export async function resolveWebvhForUpdate({
  targetDid,
  action
}: {
  targetDid: string
  action: string
}): Promise<{
  log: DIDLog
  doc: Awaited<ReturnType<typeof resolveDIDFromLog>>['doc']
  meta: Awaited<ReturnType<typeof resolveDIDFromLog>>['meta']
}> {
  let logText: string
  try {
    logText = await loadDidLog(targetDid)
  } catch {
    throw new Error(`No locally stored did:webvh found for ${targetDid}`)
  }
  const log = parseDidLog(logText)
  let resolved: Awaited<ReturnType<typeof resolveDIDFromLog>>
  try {
    resolved = await resolveDIDFromLog(log)
  } catch (err) {
    throw new Error(
      `Could not resolve the DID log: ${(err as Error).message}`,
      {
        cause: err
      }
    )
  }
  if (resolved.meta.deactivated) {
    throw new Error(`Cannot ${action}: the DID is deactivated.`)
  }
  return { log, doc: resolved.doc, meta: resolved.meta }
}

/**
 * Resolve a locally stored did:webvh DID from its history log (`.jsonl`) -- the
 * source of truth for the current document and its accumulated parameters.
 * Unlike `resolveWebvhForUpdate` this does not reject a deactivated DID, since
 * `show` should still display it; it returns `undefined` when no log is stored
 * so the caller can fall back to the stored document snapshot.
 *
 * @param did {string} the resolved did:webvh DID.
 * @returns {Promise<{ doc, meta } | undefined>}
 * @throws {Error} if a log exists but fails to resolve/verify.
 */
export async function resolveStoredWebvh(did: string): Promise<
  | {
      doc: Awaited<ReturnType<typeof resolveDIDFromLog>>['doc']
      meta: Awaited<ReturnType<typeof resolveDIDFromLog>>['meta']
    }
  | undefined
> {
  let logText: string
  try {
    logText = await loadDidLog(did)
  } catch {
    return undefined
  }
  const { doc, meta } = await resolveDIDFromLog(parseDidLog(logText))
  return { doc, meta }
}

/**
 * Load a did:webvh DID's update-keys sidecar, treating an absent file as
 * `undefined` (no stored secrets) rather than an error.
 *
 * @param did {string}
 * @returns {Promise<WebvhUpdateKeys | undefined>}
 */
export async function loadStoredUpdateKeys(
  did: string
): Promise<WebvhUpdateKeys | undefined> {
  try {
    return await loadDidUpdateKeys(did)
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== 'ENOENT') {
      throw err
    }
    return undefined
  }
}

/**
 * Pre-rotation reveal: validate and load the staged (pre-committed) update key
 * that must sign this entry, returning the signer key pair plus the records
 * that make it the new active key and retire the current one. As a recovery
 * path, when the staged record does not match the log's commitment but the
 * sidecar's `active` record does (an earlier rotation wrote the sidecar and
 * was then interrupted before the log write), the active record is revealed
 * instead; `retiredActive` is undefined in that case, since the active record
 * is not superseded.
 *
 * @param options {object}
 * @param options.stored {WebvhUpdateKeys | undefined} the update-keys sidecar.
 * @param options.meta {Awaited<ReturnType<typeof resolveDIDFromLog>>['meta']}
 * @param options.targetDid {string}
 * @param options.action {string} verb used in error messages.
 * @returns {Promise<{ signerKeyPair, newActive, retiredActive }>}
 * @throws {Error} if the staged secret is missing or has diverged from the
 *   log's committed nextKeyHashes.
 */
export async function revealStagedSigner({
  stored,
  meta,
  targetDid,
  action
}: {
  stored: WebvhUpdateKeys | undefined
  meta: Awaited<ReturnType<typeof resolveDIDFromLog>>['meta']
  targetDid: string
  action: string
}): Promise<{
  signerKeyPair: Ed25519VerificationKey
  newActive: WebvhUpdateKey
  retiredActive?: WebvhUpdateKey
}> {
  if (
    stored?.staged &&
    meta.nextKeyHashes.includes(stored.staged.nextKeyHash)
  ) {
    return {
      signerKeyPair: await loadUpdateKey(stored.staged),
      newActive: {
        publicKeyMultibase: stored.staged.publicKeyMultibase,
        secretKeyMultibase: stored.staged.secretKeyMultibase
      },
      retiredActive: stored.active
    }
  }
  if (
    stored?.active.secretKeyMultibase &&
    meta.nextKeyHashes.includes(
      await deriveNextKeyHash(stored.active.publicKeyMultibase)
    )
  ) {
    return {
      signerKeyPair: await loadUpdateKey(stored.active),
      newActive: stored.active
    }
  }
  if (!stored?.staged) {
    throw new Error(
      `Cannot ${action}: the pre-committed next-key secret was not found. ` +
        'While pre-rotation is armed the staged key must sign this entry; ' +
        `check for a backup of the ${targetDid}.update-keys.json sidecar.`
    )
  }
  throw new Error(
    `Cannot ${action}: the staged key's hash is not among the log's ` +
      'committed nextKeyHashes. The local update-keys record has diverged ' +
      'from the published log (an update may have happened elsewhere); ' +
      're-resolve before retrying.'
  )
}

/**
 * Ordinary (non-pre-rotation) signer: the current active update key signs.
 * Returns the signer key pair and the active record it was loaded from. When
 * the `active` record does not match the log's updateKeys, the staged and
 * retired records are searched as a recovery path: an interrupted rotation
 * can leave the sidecar one step ahead of (or behind) the log, and the secret
 * authorized by the log may then live in one of those records.
 *
 * @param options {object}
 * @param options.stored {WebvhUpdateKeys | undefined} the update-keys sidecar.
 * @param options.meta {Awaited<ReturnType<typeof resolveDIDFromLog>>['meta']}
 * @param options.targetDid {string}
 * @param options.action {string} verb used in error messages.
 * @returns {Promise<{ signerKeyPair, activeRecord }>}
 * @throws {Error} if no stored secret matches the log's updateKeys.
 */
export async function loadActiveSigner({
  stored,
  meta,
  targetDid,
  action
}: {
  stored: WebvhUpdateKeys | undefined
  meta: Awaited<ReturnType<typeof resolveDIDFromLog>>['meta']
  targetDid: string
  action: string
}): Promise<{
  signerKeyPair: Ed25519VerificationKey
  activeRecord: WebvhUpdateKey
}> {
  const candidates: (WebvhUpdateKey | undefined)[] = [
    stored?.active,
    stored?.staged,
    ...(stored?.retired ?? [])
  ]
  const activeRecord = candidates.find(
    (record): record is WebvhUpdateKey =>
      Boolean(record?.secretKeyMultibase) &&
      meta.updateKeys.includes(record!.publicKeyMultibase)
  )
  if (!activeRecord) {
    throw new Error(
      `Cannot ${action}: the current active update-key secret was not found ` +
        `in ${targetDid}.update-keys.json.`
    )
  }
  return { signerKeyPair: await loadUpdateKey(activeRecord), activeRecord }
}

/**
 * Build the entry signer for a did:webvh update from an update key pair.
 *
 * @param keyPair {Ed25519VerificationKey} mutated: its `id` is set in place.
 * @returns the signer to pass to `updateDID`.
 */
export function makeWebvhEntrySigner(keyPair: Ed25519VerificationKey) {
  const signer = makeWebvhSigner({ keyPair })
  // `keyPair.signer()` requires an id to be set before signing.
  keyPair.id = signer.getVerificationMethodId()
  return signer
}

/**
 * Append a signed entry to a did:webvh history log via the library's
 * `updateDID`, passing the already-resolved `meta` as `priorMeta` to skip its
 * internal re-resolution (a full re-verification of every log entry). The
 * library trusts `priorMeta` blindly, so it must describe this exact log's
 * head; that pairing is asserted here (an O(1) check) before signing, so a
 * future edit that reloads or truncates the log cannot sign a forked entry.
 *
 * @param options {object}
 * @param options.meta {Awaited<ReturnType<typeof resolveDIDFromLog>>['meta']}
 *   the metadata resolved from this same log (e.g. by
 *   `resolveWebvhForUpdate`).
 * @param options.log {DIDLog}
 * @param options.signer the entry signer (see `makeWebvhEntrySigner`).
 * @returns {Promise<Awaited<ReturnType<typeof updateDID>>>}
 * @throws {Error} if `meta` does not match the log head.
 */
export async function appendWebvhEntry({
  meta,
  ...update
}: Omit<Parameters<typeof updateDID>[0], 'priorMeta'> & {
  meta: Awaited<ReturnType<typeof resolveDIDFromLog>>['meta']
}): Promise<Awaited<ReturnType<typeof updateDID>>> {
  const head = update.log[update.log.length - 1] as
    { versionId?: string } | undefined
  if (head?.versionId !== meta.versionId) {
    throw new Error(
      'Internal error: the resolved DID metadata does not match the log head.'
    )
  }
  return updateDID({ ...update, priorMeta: meta })
}

/**
 * Persist the artifacts of a signed did:webvh update in a crash-safe order:
 * the update-keys sidecar first -- retaining the superseded secret regardless
 * of `keepOldKey`, so that every key authorized by either the old or the new
 * log head has its secret on disk -- then the log and document, then the
 * sidecar again in its final shape when the retained secret should be
 * dropped. An interruption at any point leaves a state the signer loaders
 * (`loadActiveSigner`, `revealStagedSigner`) can recover from; the reverse
 * order could commit a log whose only authorized secret was never persisted.
 *
 * @param options {object}
 * @param options.result {Awaited<ReturnType<typeof updateDID>>}
 * @param [options.sidecar] {object} update-keys sidecar changes, if any:
 *   the `persistUpdateKeysSidecar` arguments minus `did`.
 * @returns {Promise<{ logPath, docPath, updateKeysPath }>} the saved paths;
 *   `updateKeysPath` is undefined when no sidecar change was requested.
 */
export async function persistWebvhUpdate({
  result,
  sidecar
}: {
  result: Awaited<ReturnType<typeof updateDID>>
  sidecar?: {
    newActive: WebvhUpdateKey
    newStaged?: WebvhUpdateKey & { nextKeyHash: string }
    retiredActive?: WebvhUpdateKey
    stored?: WebvhUpdateKeys
    keepOldKey?: boolean
  }
}): Promise<{ logPath: string; docPath: string; updateKeysPath?: string }> {
  let updateKeysPath: string | undefined
  if (sidecar) {
    updateKeysPath = await persistUpdateKeysSidecar({
      did: result.did,
      ...sidecar,
      keepOldKey: true
    })
  }
  const logPath = await saveDidLog({ did: result.did, log: result.log })
  const docPath = await saveToDids({
    method: 'webvh',
    did: result.did,
    data: result.doc
  })
  if (sidecar && !sidecar.keepOldKey && sidecar.retiredActive) {
    updateKeysPath = await persistUpdateKeysSidecar({
      did: result.did,
      ...sidecar
    })
  }
  return { logPath, docPath, updateKeysPath }
}

/**
 * Write the update-keys sidecar: the active key, the staged next key (or
 * none), and any retired secrets. At creation there is no prior sidecar; after
 * an advance/rotation the superseded active key is appended to `retired` only
 * when `keepOldKey` asks to preserve it.
 *
 * @param options {object}
 * @param options.did {string}
 * @param options.newActive {WebvhUpdateKey}
 * @param [options.newStaged] {WebvhUpdateKey & { nextKeyHash: string }}
 * @param [options.retiredActive] {WebvhUpdateKey} the superseded active key.
 * @param [options.stored] {WebvhUpdateKeys} the prior sidecar, if any.
 * @param [options.keepOldKey] {boolean} retain the retired secret.
 * @returns {Promise<string>} the saved sidecar path.
 */
export async function persistUpdateKeysSidecar({
  did,
  newActive,
  newStaged,
  retiredActive,
  stored,
  keepOldKey
}: {
  did: string
  newActive: WebvhUpdateKey
  newStaged?: WebvhUpdateKey & { nextKeyHash: string }
  retiredActive?: WebvhUpdateKey
  stored?: WebvhUpdateKeys
  keepOldKey?: boolean
}): Promise<string> {
  const updated: WebvhUpdateKeys = { active: newActive }
  if (newStaged) {
    updated.staged = newStaged
  }
  const retiredList = stored?.retired ? [...stored.retired] : []
  // retiredActive is undefined on the stage-only path, so this also skips that
  // case without a separate guard.
  if (keepOldKey && retiredActive?.secretKeyMultibase) {
    retiredList.push(retiredActive)
  }
  if (retiredList.length > 0) {
    updated.retired = retiredList
  }
  return saveDidUpdateKeys({ did, updateKeys: updated })
}

/**
 * Rotate the update (authorization) key of a locally stored did:webvh DID. By
 * default advances key pre-rotation -- reveals the staged next key and stages a
 * fresh one -- and never touches the document verification methods.
 *
 * @param options {object}
 * @param options.didRef {string}   The DID or metadata handle.
 * @param [options.updateKey] {string[]}   Rotate to specific update key(s).
 * @param [options.enablePrerotation] {boolean}   Turn pre-rotation on.
 * @param [options.stopPrerotation] {boolean}   Turn pre-rotation off.
 * @param [options.keepOldKey] {boolean}   Retain the retired update key secret.
 * @param [options.withSeed] {boolean}   Emit the new/next update key's seed.
 * @param [options.yes] {boolean}   Skip the confirmation prompt.
 * @returns {Promise<number>}   The process exit code.
 */
export async function runRotateKeys(options: {
  didRef: string
  updateKey?: string[]
  enablePrerotation?: boolean
  stopPrerotation?: boolean
  keepOldKey?: boolean
  withSeed?: boolean
  yes?: boolean
}): Promise<number> {
  const { didRef } = options
  let resolved: string | undefined
  try {
    resolved = await resolveDidRef({ ref: didRef })
  } catch (err) {
    console.error((err as Error).message)
    return 1
  }
  const targetDid = resolved ?? didRef
  if (!targetDid.startsWith('did:webvh:')) {
    console.error('rotate-keys is only supported for did:webvh DIDs')
    return 1
  }
  // Options-only validation goes before the log resolution below, which
  // verifies every entry -- a pure argument error should not cost a full
  // log replay.
  if (options.enablePrerotation && options.stopPrerotation) {
    console.error(
      '--enable-prerotation and --stop-prerotation are mutually exclusive'
    )
    return 1
  }
  // The history log is the source of truth for a stored did:webvh (the
  // current document is just its last entry's state), so a key-only
  // rotation ignores the resolved document.
  let log: DIDLog
  let meta: Awaited<ReturnType<typeof resolveDIDFromLog>>['meta']
  try {
    ;({ log, meta } = await resolveWebvhForUpdate({
      targetDid,
      action: 'rotate keys'
    }))
  } catch (err) {
    console.error((err as Error).message)
    return 1
  }

  // Flag validation against the current pre-rotation state.
  if (meta.prerotation) {
    if (options.updateKey) {
      console.error(
        '--update-key is not allowed while pre-rotation is armed; the ' +
          'next update keys are fixed by the committed nextKeyHashes'
      )
      return 1
    }
    if (options.enablePrerotation) {
      console.error('pre-rotation is already enabled for this DID')
      return 1
    }
  } else if (options.stopPrerotation) {
    console.error('pre-rotation is already off for this DID')
    return 1
  }

  let stored: WebvhUpdateKeys | undefined
  try {
    stored = await loadStoredUpdateKeys(targetDid)
  } catch (err) {
    console.error((err as Error).message)
    return 1
  }

  // Whether this rotation stages a fresh next key only depends on the current
  // pre-rotation state and the flags, so decide it up front: it (and the
  // ordinary-mode generation path below) determine which freshly generated key
  // --with-seed backs.
  const arm = meta.prerotation
    ? !options.stopPrerotation
    : Boolean(options.enablePrerotation)
  // An ordinary rotation generates a fresh active key only when it is not a
  // stage-only --enable-prerotation and no external --update-key is supplied.
  const generatesFreshActive =
    !meta.prerotation && !options.enablePrerotation && !options.updateKey

  // --with-seed backs the one update key this rotation freshly generates and
  // stores: the staged next key when armed (the happy path), otherwise the
  // fresh active key of an ordinary rotation. The two are mutually exclusive,
  // so a single seed is unambiguous. A rotation that generates neither (a bare
  // pre-rotation reveal, --stop-prerotation, or rotating to an external
  // --update-key) has no secret to seed.
  if (options.withSeed && !arm && !generatesFreshActive) {
    console.error(
      '--with-seed has no effect for this rotation: it does not generate a ' +
        'new update key (no next key is staged and the active key is either ' +
        'revealed from a prior commitment or supplied via --update-key)'
    )
    return 1
  }
  let secretKeySeed: string | undefined
  let seedBytes: Uint8Array | undefined
  if (options.withSeed) {
    try {
      ;({ secretKeySeed, seedBytes } = await deriveSeed({ withSeed: true }))
    } catch (err) {
      console.error((err as Error).message)
      return 1
    }
  }

  // Inbound: who signs this entry, what becomes the active key, and the new
  // authorized set (`updateKeys`) for the entry. The log may authorize keys
  // beyond the locally stored active one (a co-managed DID), so the set is
  // edited, not rebuilt from the single local key -- collapsing it would
  // silently revoke the co-authorized keys.
  let signerKeyPair: Ed25519VerificationKey
  let newActive: WebvhUpdateKey
  let retiredActive: WebvhUpdateKey | undefined
  let newUpdateKeys: string[]
  try {
    if (meta.prerotation) {
      // Pre-rotation reveal: the staged key signs its own activation. The
      // commitment forces a full replacement of the set -- every authorized
      // key must hash into the prior nextKeyHashes, and the staged key is
      // the only preimage held here.
      ;({ signerKeyPair, newActive, retiredActive } = await revealStagedSigner({
        stored,
        meta,
        targetDid,
        action: 'rotate keys'
      }))
      newUpdateKeys = [newActive.publicKeyMultibase]
    } else {
      // Ordinary rotation: the current active key signs.
      let activeRecord: WebvhUpdateKey
      ;({ signerKeyPair, activeRecord } = await loadActiveSigner({
        stored,
        meta,
        targetDid,
        action: 'rotate keys'
      }))
      if (options.enablePrerotation && !options.updateKey) {
        // Stage only: arm pre-rotation without changing the active key or
        // the authorized set.
        newActive = activeRecord
        newUpdateKeys = meta.updateKeys
      } else if (options.updateKey) {
        // Rotate to externally-held key(s), which become the whole new
        // authorized set; the secrets are not ours to store.
        newActive = { publicKeyMultibase: options.updateKey[0] }
        newUpdateKeys = options.updateKey
        retiredActive = activeRecord
      } else {
        // Fresh active key; --with-seed (when present) backs it here, since no
        // staged key is generated in this branch. Only the retired key is
        // replaced in the authorized set.
        newActive = await exportUpdateKey(
          await Ed25519VerificationKey.generate({ seed: seedBytes })
        )
        newUpdateKeys = meta.updateKeys.map(publicKeyMultibase =>
          publicKeyMultibase === activeRecord.publicKeyMultibase
            ? newActive.publicKeyMultibase
            : publicKeyMultibase
        )
        retiredActive = activeRecord
      }
    }
  } catch (err) {
    console.error((err as Error).message)
    return 1
  }

  // Outbound: keep the ratchet armed (stage a fresh next key) or not. When
  // armed, --with-seed (when present) backs the staged key; in that case the
  // active key was revealed or supplied, not freshly generated above, so the
  // seed is unambiguously the staged key's.
  const newStaged = arm
    ? await generateStagedKey({ seed: seedBytes })
    : undefined
  const nextKeyHashes = newStaged ? [newStaged.nextKeyHash] : []

  const confirmed = await confirmAction({
    message:
      `Rotate the update key of ${targetDid}? This appends a new log ` +
      'entry and is hard to undo.',
    yes: options.yes
  })
  if (!confirmed) {
    console.error('Aborted.')
    return 1
  }

  const signer = makeWebvhEntrySigner(signerKeyPair)

  // A sparse updateDID() carries the prior DID document state forward and
  // only overlays the fields an update actually supplies, so a key-only
  // rotation omits all document directives to leave the document
  // unchanged.
  let result: Awaited<ReturnType<typeof updateDID>>
  try {
    result = await appendWebvhEntry({
      log,
      meta,
      signer,
      updateKeys: newUpdateKeys,
      nextKeyHashes
    })
  } catch (err) {
    console.error(`Key rotation failed: ${(err as Error).message}`)
    return 1
  }

  const { logPath, docPath, updateKeysPath } = await persistWebvhUpdate({
    result,
    sidecar: {
      newActive,
      newStaged,
      retiredActive,
      stored,
      keepOldKey: options.keepOldKey
    }
  })

  console.error(`DID document saved to ${docPath}`)
  console.error(`DID history log saved to ${logPath}`)
  console.error(`Update keys saved to ${updateKeysPath}`)
  console.error(
    nextKeyHashes.length > 0
      ? 'Pre-rotation is armed: a next update key is staged.'
      : 'Pre-rotation is off after this rotation.'
  )

  const output: Record<string, unknown> = { id: result.did }
  if (secretKeySeed !== undefined) {
    output.secretKeySeed = secretKeySeed
  }
  output.didDocument = result.doc
  console.log(JSON.stringify(output, null, 2))
  return 0
}
