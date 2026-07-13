/**
 * The interactive shell's working-directory model: a current path of up to two
 * segments (`[]` root, `[space]`, or `[space, collection]`) plus the `cd`/`use`
 * math that walks it. A WAS path is at most `SPACE/COLLECTION/RESOURCE` deep,
 * so the cwd never descends past a collection (resources are leaves you `get`,
 * not directories you enter).
 */
import { parseWasAddress, tryParseHttpUrl } from '../../../was/address.js'

/**
 * The mutable interactive-shell session state. The signing server/DID defaults
 * ride the `WAS_SERVER_URL` / `WAS_DID` environment channel (see
 * `runWasShell`), so the session only tracks the working directory.
 */
export interface ShellSession {
  /** The current path segments: `[]`, `[space]`, or `[space, collection]`. */
  cwd: string[]
}

/**
 * Computes a new working directory from a `cd`/`use` argument. Supports an
 * absolute path (leading `/`), `.`/`..` navigation, a relative path joined onto
 * the current cwd, and a full space URL (which also yields the server origin to
 * adopt as the session default). Throws when the result would descend past a
 * collection.
 *
 * @param options {object}
 * @param options.cwd {string[]}   The current working directory segments.
 * @param options.arg {string}   The `cd`/`use` argument.
 * @returns {{cwd: string[], server?: string}}
 */
export function resolveCwdChange({
  cwd,
  arg
}: {
  cwd: string[]
  arg: string
}): { cwd: string[]; server?: string } {
  if (tryParseHttpUrl(arg)) {
    const parsed = parseWasAddress(arg)
    if (parsed.resourceId !== undefined) {
      throw new Error(
        `Cannot cd to "${arg}": it addresses a resource, not a directory.`
      )
    }
    const next = [parsed.spaceRef]
    if (parsed.collectionId !== undefined) {
      next.push(parsed.collectionId)
    }
    return { cwd: next, server: parsed.server }
  }

  let next: string[]
  let path = arg
  if (path.startsWith('/')) {
    next = []
    path = path.slice(1)
  } else {
    next = [...cwd]
  }

  for (const segment of path.split('/')) {
    if (segment === '' || segment === '.') {
      continue
    }
    if (segment === '..') {
      next = next.slice(0, -1)
      continue
    }
    next.push(segment)
  }

  if (next.length > 2) {
    throw new Error(
      `Cannot cd to "${arg}": a WAS path is at most SPACE/COLLECTION deep.`
    )
  }
  return { cwd: next }
}

/**
 * Formats a working directory for display in the prompt (`/`, `/space`, or
 * `/space/collection`).
 *
 * @param cwd {string[]}
 * @returns {string}
 */
export function formatCwd(cwd: string[]): string {
  return `/${cwd.join('/')}`
}
