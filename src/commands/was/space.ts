/**
 * `was space` run functions: create, list (local registry, or `--remote`),
 * show (server description or `--meta` registry record), update, delete
 * (server + registry), forget (registry only), add (register an existing
 * remote space), and export/import of a whole space as a tar archive.
 */
import { buildWasClient, resolveWasTarget } from '../../was/client.js'
import { readInputBytes, writeBytesOutput } from '../../was/io.js'
import {
  listSpaceRecords,
  removeSpaceRecord,
  resolveSpaceRef,
  saveSpaceRecord
} from '../../was/registry.js'
import { renderTable } from '../../table.js'
import { parseSpaceAddress, reportError, wasUrl } from './shared.js'

/**
 * Creates a space on the server and prints `{ id, url, name?, controller }`.
 *
 * @param options {object}
 * @param [options.name] {string}   The space's display name.
 * @param [options.server] {string}   The server base URL.
 * @param [options.did] {string}   The signing DID or stored-DID handle.
 * @param [options.id] {string}   A caller-chosen space id.
 * @param [options.save] {boolean}   Register the space in the local wallet.
 * @param [options.handle] {string}   Short tag for the registry entry.
 * @param [options.description] {string}   Longer registry entry description.
 * @returns {Promise<number>}   The process exit code.
 */
export async function runSpaceCreate(options: {
  name?: string
  server?: string
  did?: string
  id?: string
  save?: boolean
  handle?: string
  description?: string
}): Promise<number> {
  try {
    const { client, server, did } = await buildWasClient({
      server: options.server,
      did: options.did
    })
    const space = await client.createSpace({
      ...(options.name !== undefined && { name: options.name }),
      ...(options.id !== undefined && { id: options.id })
    })
    const url = wasUrl({ server, spaceId: space.id })
    if (options.save) {
      const filePath = await saveSpaceRecord({
        record: {
          id: space.id,
          ...(options.name !== undefined && { name: options.name }),
          server,
          controller: did
        },
        handle: options.handle,
        description: options.description
      })
      console.error(`Space registered in ${filePath}`)
    }
    console.log(
      JSON.stringify(
        {
          id: space.id,
          url,
          ...(options.name !== undefined && { name: options.name }),
          controller: did
        },
        null,
        2
      )
    )
    return 0
  } catch (err) {
    return reportError({ action: 'create the space', err })
  }
}

/**
 * Lists the locally registered spaces (the working model while servers do
 * not implement List Spaces); `--remote` asks the server instead.
 *
 * @param options {object}
 * @param [options.json] {boolean}   Output a JSON array with metadata.
 * @param [options.plain] {boolean}   Output one space id per line.
 * @param [options.remote] {boolean}   List spaces on the server instead.
 * @param [options.server] {string}   The server base URL (with `--remote`).
 * @param [options.did] {string}   The signing DID (with `--remote`).
 * @returns {Promise<number>}   The process exit code.
 */
export async function runSpaceList(options: {
  json?: boolean
  plain?: boolean
  remote?: boolean
  server?: string
  did?: string
}): Promise<number> {
  try {
    if (options.remote) {
      const { client } = await buildWasClient({
        server: options.server,
        did: options.did
      })
      const listing = await client.listSpaces()
      console.log(JSON.stringify(listing, null, 2))
      return 0
    }

    const entries = await listSpaceRecords()
    if (options.plain) {
      const spaceIds = entries.map(entry => entry.record.id).sort()
      for (const spaceId of spaceIds) {
        console.log(spaceId)
      }
      return 0
    }
    if (options.json) {
      const output = entries.map(entry => ({
        id: entry.record.id,
        server: entry.record.server,
        ...(entry.record.name && { name: entry.record.name }),
        ...(entry.record.controller && {
          controller: entry.record.controller
        }),
        ...(entry.meta?.created && { created: entry.meta.created }),
        ...(entry.meta?.handle && { handle: entry.meta.handle }),
        ...(entry.meta?.description && {
          description: entry.meta.description
        })
      }))
      console.log(JSON.stringify(output, null, 2))
      return 0
    }
    if (entries.length === 0) {
      return 0
    }
    const rows = entries.map(entry => [
      entry.meta?.handle ?? '',
      entry.record.name ?? '',
      entry.record.id,
      entry.record.server,
      entry.meta?.created?.slice(0, 10) ?? ''
    ])
    console.log(
      renderTable({
        columns: [
          { header: 'HANDLE', maxWidth: 16 },
          { header: 'NAME', maxWidth: 20 },
          { header: 'SPACE ID', maxWidth: 40 },
          { header: 'SERVER', maxWidth: 32 },
          { header: 'CREATED' }
        ],
        rows
      })
    )
    return 0
  } catch (err) {
    return reportError({ action: 'list spaces', err })
  }
}

/**
 * Shows a space: its Space Description from the server, or (`--meta`) its
 * local registry record and metadata.
 *
 * @param options {object}
 * @param options.address {string}   The space address.
 * @param [options.meta] {boolean}   Show the local registry metadata instead.
 * @param [options.json] {boolean}   With `--meta`, output JSON.
 * @param [options.server] {string}   The server base URL.
 * @param [options.did] {string}   The signing DID or stored-DID handle.
 * @returns {Promise<number>}   The process exit code.
 */
export async function runSpaceShow(options: {
  address: string
  meta?: boolean
  json?: boolean
  server?: string
  did?: string
}): Promise<number> {
  try {
    const parsed = parseSpaceAddress(options.address)
    if (options.meta) {
      const entry = await resolveSpaceRef({ ref: parsed.spaceRef })
      if (!entry) {
        throw new Error(
          `No locally registered space found for "${parsed.spaceRef}".`
        )
      }
      if (options.json) {
        const output = {
          id: entry.record.id,
          server: entry.record.server,
          ...(entry.record.name && { name: entry.record.name }),
          ...(entry.record.controller && {
            controller: entry.record.controller
          }),
          ...(entry.meta?.created && { created: entry.meta.created }),
          ...(entry.meta?.handle && { handle: entry.meta.handle }),
          ...(entry.meta?.description && {
            description: entry.meta.description
          })
        }
        console.log(JSON.stringify(output, null, 2))
        return 0
      }
      const rows = [
        ['ID', entry.record.id],
        ['Name', entry.record.name ?? ''],
        ['Server', entry.record.server],
        ['Controller', entry.record.controller ?? ''],
        ['Handle', entry.meta?.handle ?? ''],
        ['Created', entry.meta?.created ?? ''],
        ['Description', entry.meta?.description ?? '']
      ]
      console.log(
        renderTable({
          columns: [{ header: 'FIELD' }, { header: 'VALUE' }],
          rows
        })
      )
      return 0
    }

    const target = await resolveWasTarget({
      address: options.address,
      server: options.server,
      did: options.did
    })
    const description = await target.client.space(target.spaceId).describe()
    if (description === null) {
      console.error(
        'Not found (or not visible to you): ' +
          wasUrl({ server: target.server, spaceId: target.spaceId })
      )
      return 1
    }
    console.log(JSON.stringify(description, null, 2))
    return 0
  } catch (err) {
    return reportError({ action: 'show the space', err })
  }
}

/**
 * Updates a space's description fields on the server (upsert via
 * `configure()`), refreshing the name in the local registry entry when one
 * exists.
 *
 * @param options {object}
 * @param options.address {string}   The space address.
 * @param [options.name] {string}   The new display name.
 * @param [options.server] {string}   The server base URL.
 * @param [options.did] {string}   The signing DID or stored-DID handle.
 * @returns {Promise<number>}   The process exit code.
 */
export async function runSpaceUpdate(options: {
  address: string
  name?: string
  server?: string
  did?: string
}): Promise<number> {
  try {
    parseSpaceAddress(options.address)
    const target = await resolveWasTarget({
      address: options.address,
      server: options.server,
      did: options.did
    })
    const description = await target.client.space(target.spaceId).configure({
      ...(options.name !== undefined && { name: options.name })
    })
    if (target.entry && options.name !== undefined) {
      await saveSpaceRecord({
        record: { ...target.entry.record, name: options.name }
      })
    }
    console.log(JSON.stringify(description, null, 2))
    return 0
  } catch (err) {
    return reportError({ action: 'update the space', err })
  }
}

/**
 * Deletes a space on the server (idempotent) and removes its local registry
 * entry when one exists. The local-only counterpart is `forget`.
 *
 * @param options {object}
 * @param options.address {string}   The space address.
 * @param [options.server] {string}   The server base URL.
 * @param [options.did] {string}   The signing DID or stored-DID handle.
 * @returns {Promise<number>}   The process exit code.
 */
export async function runSpaceDelete(options: {
  address: string
  server?: string
  did?: string
}): Promise<number> {
  try {
    parseSpaceAddress(options.address)
    const target = await resolveWasTarget({
      address: options.address,
      server: options.server,
      did: options.did
    })
    await target.client.space(target.spaceId).delete()
    console.error(
      'Deleted ' +
        wasUrl({ server: target.server, spaceId: target.spaceId }) +
        ' on the server.'
    )
    if (target.entry) {
      const removed = await removeSpaceRecord({
        storageId: target.entry.storageId
      })
      for (const filePath of removed) {
        console.error(`Removed ${filePath}`)
      }
    }
    return 0
  } catch (err) {
    return reportError({ action: 'delete the space', err })
  }
}

/**
 * Removes a space's local registry entry only; the server-side space is
 * untouched. The remote counterpart is `delete`.
 *
 * @param options {object}
 * @param options.address {string}   The space address.
 * @returns {Promise<number>}   The process exit code.
 */
export async function runSpaceForget(options: {
  address: string
}): Promise<number> {
  try {
    const parsed = parseSpaceAddress(options.address)
    const entry = await resolveSpaceRef({ ref: parsed.spaceRef })
    if (!entry) {
      throw new Error(
        `No locally registered space found for "${parsed.spaceRef}".`
      )
    }
    const removed = await removeSpaceRecord({ storageId: entry.storageId })
    for (const filePath of removed) {
      console.error(`Removed ${filePath}`)
    }
    return 0
  } catch (err) {
    return reportError({ action: 'forget the space', err })
  }
}

/**
 * Registers an existing remote space (e.g. created elsewhere or received via
 * delegation) in the local registry, verifying it first with `describe()`.
 *
 * @param options {object}
 * @param options.address {string}   A full space https URL or a bare space id.
 * @param [options.server] {string}   The server base URL (with a bare id).
 * @param [options.did] {string}   The signing DID or stored-DID handle.
 * @param [options.handle] {string}   Short tag for the registry entry.
 * @param [options.description] {string}   Longer registry entry description.
 * @returns {Promise<number>}   The process exit code.
 */
export async function runSpaceAdd(options: {
  address: string
  server?: string
  did?: string
  handle?: string
  description?: string
}): Promise<number> {
  try {
    parseSpaceAddress(options.address)
    const target = await resolveWasTarget({
      address: options.address,
      server: options.server,
      did: options.did
    })
    const description = await target.client.space(target.spaceId).describe()
    if (description === null) {
      console.error(
        'Not found (or not visible to you): ' +
          wasUrl({ server: target.server, spaceId: target.spaceId })
      )
      return 1
    }
    const filePath = await saveSpaceRecord({
      record: {
        id: target.spaceId,
        ...(description.name && { name: description.name }),
        server: target.server,
        controller: description.controller ?? target.did
      },
      handle: options.handle,
      description: options.description
    })
    console.error(`Space registered in ${filePath}`)
    console.log(JSON.stringify(description, null, 2))
    return 0
  } catch (err) {
    return reportError({ action: 'add the space', err })
  }
}

/**
 * Exports a whole space as a tar archive, written to `--output` or raw to
 * stdout.
 *
 * @param options {object}
 * @param options.address {string}   The space address.
 * @param [options.output] {string}   The output file path; stdout when
 *   omitted.
 * @param [options.server] {string}   The server base URL.
 * @param [options.did] {string}   The signing DID or stored-DID handle.
 * @returns {Promise<number>}   The process exit code.
 */
export async function runSpaceExport(options: {
  address: string
  output?: string
  server?: string
  did?: string
}): Promise<number> {
  try {
    parseSpaceAddress(options.address)
    const target = await resolveWasTarget({
      address: options.address,
      server: options.server,
      did: options.did
    })
    const bytes = await target.client.space(target.spaceId).export()
    await writeBytesOutput({ bytes, output: options.output })
    return 0
  } catch (err) {
    return reportError({ action: 'export the space', err })
  }
}

/**
 * Imports (merges) a tar archive into a space and prints the import stats
 * summary.
 *
 * @param options {object}
 * @param options.address {string}   The space address.
 * @param [options.file] {string}   The tar file; stdin when omitted.
 * @param [options.server] {string}   The server base URL.
 * @param [options.did] {string}   The signing DID or stored-DID handle.
 * @returns {Promise<number>}   The process exit code.
 */
export async function runSpaceImport(options: {
  address: string
  file?: string
  server?: string
  did?: string
}): Promise<number> {
  try {
    parseSpaceAddress(options.address)
    const target = await resolveWasTarget({
      address: options.address,
      server: options.server,
      did: options.did
    })
    const tar = await readInputBytes({ file: options.file })
    const stats = await target.client.space(target.spaceId).import(tar)
    console.log(JSON.stringify(stats, null, 2))
    return 0
  } catch (err) {
    return reportError({ action: 'import into the space', err })
  }
}
