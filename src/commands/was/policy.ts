/**
 * `was policy` run functions: show, set (from `--type` or a JSON file), and
 * clear the access-control policy of a space, collection, or resource.
 */
import { readFile } from 'node:fs/promises'
import { type PolicyDocument } from '@interop/was-client'
import { resolveWasTarget } from '../../was/client.js'
import { handleForTarget, reportError } from './shared.js'

/**
 * Shows the access-control policy of a space, collection, or resource.
 *
 * @param options {object}
 * @param options.address {string}   A space/collection/resource address.
 * @param [options.server] {string}   The server base URL.
 * @param [options.did] {string}   The signing DID or stored-DID handle.
 * @returns {Promise<number>}   The process exit code.
 */
export async function runPolicyShow(options: {
  address: string
  server?: string
  did?: string
}): Promise<number> {
  try {
    const target = await resolveWasTarget({
      address: options.address,
      server: options.server,
      did: options.did
    })
    const { handle, url } = handleForTarget(target)
    const policy = await handle.getPolicy()
    if (policy === null) {
      console.error(`No policy set (or not visible to you): ${url}`)
      return 1
    }
    console.log(JSON.stringify(policy, null, 2))
    return 0
  } catch (err) {
    return reportError({ action: 'show the policy', err })
  }
}

/**
 * Parses the `policy set` arguments -- `--type <type>` for a simple
 * type-only policy, or a JSON file for richer ones -- into a policy
 * document.
 *
 * @param options {object}
 * @param [options.type] {string}
 * @param [options.file] {string}
 * @returns {Promise<PolicyDocument>}
 */
async function resolvePolicyInput({
  type,
  file
}: {
  type?: string
  file?: string
}): Promise<PolicyDocument> {
  if (type && file) {
    throw new Error('Provide either --type or a policy file, not both.')
  }
  if (type) {
    return { type }
  }
  if (!file) {
    throw new Error('Provide --type <type> or a policy JSON file.')
  }
  let parsed: unknown
  try {
    parsed = JSON.parse(await readFile(file, 'utf8'))
  } catch (err) {
    throw new Error(
      `${file} does not contain policy JSON: ` +
        `${err instanceof Error ? err.message : String(err)}`,
      { cause: err }
    )
  }
  if (
    parsed === null ||
    typeof parsed !== 'object' ||
    Array.isArray(parsed) ||
    typeof (parsed as { type?: unknown }).type !== 'string'
  ) {
    throw new Error(`${file} must hold a policy object with a "type" field.`)
  }
  return parsed as PolicyDocument
}

/**
 * Sets (creates or replaces) the access-control policy of a space,
 * collection, or resource, and prints the policy document that was set.
 *
 * @param options {object}
 * @param options.address {string}   A space/collection/resource address.
 * @param [options.file] {string}   A policy JSON file.
 * @param [options.type] {string}   A simple type-only policy (e.g.
 *   PublicCanRead).
 * @param [options.server] {string}   The server base URL.
 * @param [options.did] {string}   The signing DID or stored-DID handle.
 * @returns {Promise<number>}   The process exit code.
 */
export async function runPolicySet(options: {
  address: string
  file?: string
  type?: string
  server?: string
  did?: string
}): Promise<number> {
  try {
    const policy = await resolvePolicyInput({
      type: options.type,
      file: options.file
    })
    const target = await resolveWasTarget({
      address: options.address,
      server: options.server,
      did: options.did
    })
    const { handle, url } = handleForTarget(target)
    await handle.setPolicy(policy)
    console.error(`Policy set on ${url}`)
    console.log(JSON.stringify(policy, null, 2))
    return 0
  } catch (err) {
    return reportError({ action: 'set the policy', err })
  }
}

/**
 * Removes the access-control policy of a space, collection, or resource,
 * reverting it to capability-only access. Idempotent.
 *
 * @param options {object}
 * @param options.address {string}   A space/collection/resource address.
 * @param [options.server] {string}   The server base URL.
 * @param [options.did] {string}   The signing DID or stored-DID handle.
 * @returns {Promise<number>}   The process exit code.
 */
export async function runPolicyClear(options: {
  address: string
  server?: string
  did?: string
}): Promise<number> {
  try {
    const target = await resolveWasTarget({
      address: options.address,
      server: options.server,
      did: options.did
    })
    const { handle, url } = handleForTarget(target)
    await handle.clearPolicy()
    console.error(`Cleared the policy on ${url} (capability-only access).`)
    return 0
  } catch (err) {
    return reportError({ action: 'clear the policy', err })
  }
}
