/**
 * `did webvh set-purpose`: change the verification relationships of the
 * document verification method of a locally stored did:webvh DID. Appends a
 * log entry whose document lists the same key, under the same method id, in
 * exactly the given relationships (the full replacement set). The log
 * machinery is reused from `./webvh-update.js`, and the relationship / id
 * helpers from `./replace-key.js`.
 */
import { type DataIntegrityProofPurpose } from '@interop/did-method-webvh'
import { resolveDidRef } from '../../meta.js'
import { parseWebvhPurposes } from './create.js'
import { purposesOf, vmIdFragmentModeOf } from './replace-key.js'
import { runWebvhDocumentUpdate } from './webvh-update.js'

/**
 * Set the verification relationships of the document verification method of
 * a locally stored did:webvh DID, appending a signed log entry. The key and
 * its method id are kept.
 *
 * @param options {object}
 * @param options.didRef {string}   The DID or metadata handle.
 * @param options.purpose {string[]}   The full set of verification
 *   relationships the key is listed under after the update.
 * @param [options.keepOldKey] {boolean}   Retain the retired update key secret
 *   (pre-rotation path only).
 * @param [options.yes] {boolean}   Skip the confirmation prompt.
 * @param [options.offline] {boolean}   Skip the fast-forward check against
 *   the served log.
 * @returns {Promise<number>}   The process exit code.
 */
export async function runSetPurpose({
  didRef,
  purpose,
  keepOldKey,
  yes,
  offline
}: {
  didRef: string
  purpose: string[]
  keepOldKey?: boolean
  yes?: boolean
  offline?: boolean
}): Promise<number> {
  let resolved: string | undefined
  try {
    resolved = await resolveDidRef({ ref: didRef })
  } catch (err) {
    console.error((err as Error).message)
    return 1
  }
  const targetDid = resolved ?? didRef
  if (!targetDid.startsWith('did:webvh:')) {
    console.error('set-purpose is only supported for did:webvh DIDs')
    return 1
  }
  // Options-only validation goes before the log resolution, which verifies
  // every entry -- a pure argument error should not cost a full log replay.
  let purposes: DataIntegrityProofPurpose[]
  try {
    purposes = parseWebvhPurposes(purpose)
  } catch (err) {
    console.error((err as Error).message)
    return 1
  }
  if (purposes.length === 0) {
    console.error('--purpose needs at least one verification relationship.')
    return 1
  }

  return runWebvhDocumentUpdate({
    targetDid,
    action: 'change the verification relationships',
    confirmMessage:
      `Change the verification relationships of ${targetDid} to ` +
      `${purposes.join(', ')}? This appends a new log entry and is hard to ` +
      'undo.',
    failurePrefix: 'Relationship change failed',
    buildUpdate: doc => {
      const methods = doc?.verificationMethod ?? []
      if (methods.length !== 1) {
        throw new Error(
          'set-purpose expects the document to list exactly one ' +
            `verification method (found ${methods.length}).`
        )
      }
      const method = methods[0]
      if (!method.id || !method.publicKeyMultibase) {
        throw new Error(
          'The current verification method has no id or publicKeyMultibase.'
        )
      }
      const current = purposesOf({ doc: doc!, vmId: method.id })
      const unchanged =
        current.length === purposes.length &&
        current.every(relationship => purposes.includes(relationship))
      if (unchanged) {
        throw new Error(
          `The document already lists ${method.id} under exactly ` +
            `${current.join(', ')}.`
        )
      }
      return {
        verificationMethods: [
          {
            type: 'Multikey',
            publicKeyMultibase: method.publicKeyMultibase,
            purpose: purposes
          }
        ],
        vmIdFragment: vmIdFragmentModeOf(method)
      }
    },
    yes,
    keepOldKey,
    offline
  })
}
