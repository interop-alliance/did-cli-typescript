/**
 * `did webvh replace-key`: swap the document verification method of a locally
 * stored did:webvh DID for an external public key. Appends a log entry whose
 * document lists the new key in place of the old one (the old method is
 * dropped) under the same verification relationships, unless `--purpose`
 * selects others. The vm id fragment mode chosen at creation is honored, and
 * the old key's stored secret (if any) is removed from the keys file. The log
 * machinery is reused from `./webvh-update.js`.
 */
import {
  type DataIntegrityProofPurpose,
  type DIDDoc,
  type VerificationMethod
} from '@interop/did-method-webvh'
import { loadDidKeys, saveToDids } from '../../storage.js'
import { removeKeyDidAssociation, resolveDidRef } from '../../meta.js'
import { parseVerificationKey, parseWebvhPurposes } from './create.js'
import { runWebvhDocumentUpdate } from './webvh-update.js'

/**
 * The verification relationships that reference a verification method, by
 * full id or by its bare `#fragment`.
 *
 * @param options {object}
 * @param options.doc {DIDDoc} the resolved DID document.
 * @param options.vmId {string} the method's full id.
 * @returns {DataIntegrityProofPurpose[]}
 */
export function purposesOf({
  doc,
  vmId
}: {
  doc: DIDDoc
  vmId: string
}): DataIntegrityProofPurpose[] {
  const fragment = vmId.slice(vmId.indexOf('#'))
  const purposes: DataIntegrityProofPurpose[] = []
  for (const relationship of [
    'authentication',
    'assertionMethod',
    'keyAgreement',
    'capabilityDelegation',
    'capabilityInvocation'
  ] as const) {
    const references = (doc[relationship] ?? []).some(
      id => id === vmId || id === fragment
    )
    if (references) {
      purposes.push(relationship)
    }
  }
  return purposes
}

/**
 * The vm id fragment mode a stored method was created with, recovered from its
 * id: a `multibase` fragment equals the method's `publicKeyMultibase`,
 * anything else is `short`.
 *
 * @param method {VerificationMethod}
 * @returns {'short' | 'multibase'}
 */
export function vmIdFragmentModeOf(
  method: VerificationMethod
): 'short' | 'multibase' {
  const fragment = method.id?.slice(method.id.indexOf('#') + 1)
  return fragment !== undefined && fragment === method.publicKeyMultibase
    ? 'multibase'
    : 'short'
}

/**
 * Replace the document verification method of a locally stored did:webvh DID
 * with an external Ed25519 public key, appending a signed log entry.
 *
 * @param options {object}
 * @param options.didRef {string}   The DID or metadata handle.
 * @param options.verificationKey {string}   The new key's publicKeyMultibase.
 * @param [options.purpose] {string[]}   Verification relationships for the
 *   new key (default: those of the method being replaced).
 * @param [options.keepOldKey] {boolean}   Retain the retired update key secret
 *   (pre-rotation path only).
 * @param [options.yes] {boolean}   Skip the confirmation prompt.
 * @param [options.offline] {boolean}   Skip the fast-forward check against
 *   the served log.
 * @returns {Promise<number>}   The process exit code.
 */
export async function runReplaceKey({
  didRef,
  verificationKey,
  purpose,
  keepOldKey,
  yes,
  offline
}: {
  didRef: string
  verificationKey: string
  purpose?: string[]
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
    console.error('replace-key is only supported for did:webvh DIDs')
    return 1
  }
  // Options-only validation goes before the log resolution, which verifies
  // every entry -- a pure argument error should not cost a full log replay.
  let newKey: Awaited<ReturnType<typeof parseVerificationKey>>
  let requestedPurposes: DataIntegrityProofPurpose[] | undefined
  try {
    newKey = await parseVerificationKey(verificationKey)
    requestedPurposes = purpose ? parseWebvhPurposes(purpose) : undefined
  } catch (err) {
    console.error((err as Error).message)
    return 1
  }

  let oldMethodId: string | undefined
  return runWebvhDocumentUpdate({
    targetDid,
    action: 'replace the verification key',
    confirmMessage:
      `Replace the verification key of ${targetDid}? This appends a new ` +
      'log entry and is hard to undo.',
    failurePrefix: 'Key replacement failed',
    buildUpdate: doc => {
      const methods = doc?.verificationMethod ?? []
      if (methods.length !== 1) {
        throw new Error(
          'replace-key expects the document to list exactly one ' +
            `verification method (found ${methods.length}).`
        )
      }
      const oldMethod = methods[0]
      if (!oldMethod.id) {
        throw new Error('The current verification method has no id.')
      }
      oldMethodId = oldMethod.id
      if (oldMethod.publicKeyMultibase === newKey.publicKeyMultibase) {
        throw new Error(
          `The document already lists ${newKey.publicKeyMultibase} as its ` +
            'verification method.'
        )
      }
      const purposes =
        requestedPurposes ?? purposesOf({ doc: doc!, vmId: oldMethod.id })
      if (purposes.length === 0) {
        throw new Error(
          'The current verification method is not referenced by any ' +
            'verification relationship; pass --purpose to select the new ' +
            "key's relationships."
        )
      }
      return {
        verificationMethods: [
          {
            type: 'Multikey',
            publicKeyMultibase: newKey.publicKeyMultibase,
            purpose: purposes
          }
        ],
        vmIdFragment: vmIdFragmentModeOf(oldMethod)
      }
    },
    onPersisted: async result => {
      // The replaced method is gone from the document, so its stored secret
      // (when the old key was generated locally) no longer belongs in the
      // keys file, nor in the wallet key's DID association cache.
      let keys: Record<string, { publicKeyMultibase?: string }>
      try {
        keys = await loadDidKeys(result.did)
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code !== 'ENOENT') {
          throw err
        }
        return
      }
      const oldEntry = oldMethodId ? keys[oldMethodId] : undefined
      if (!oldEntry) {
        return
      }
      delete keys[oldMethodId!]
      await saveToDids({
        method: 'webvh',
        did: result.did,
        suffix: 'keys',
        data: keys
      })
      if (oldEntry.publicKeyMultibase) {
        await removeKeyDidAssociation({
          publicKeyMultibase: oldEntry.publicKeyMultibase,
          did: result.did
        })
      }
      console.error('Removed the replaced key from the keys file.')
    },
    yes,
    keepOldKey,
    offline
  })
}
