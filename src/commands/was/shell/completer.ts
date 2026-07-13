/**
 * Tab-completion for the interactive shell's readline interface. Completes the
 * first word (builtins plus top-level subcommand names and aliases), the
 * subcommand after a command group (`space`, `collection`, `resource`,
 * `resource-meta`, `policy`), and -- at the root working directory -- the first
 * path segment of a path verb from the local space registry (handles and ids).
 * Network-backed completion (collection/resource listings) is deferred.
 */
import type { Command } from 'commander'
import { listSpaceRecords } from '../../../was/registry.js'
import type { ShellSession } from './session.js'

/** The shell builtins, offered as first-word completions. */
const BUILTINS = ['cd', 'use', 'pwd', 'connect', 'did', 'help', 'exit', 'quit']

/** Top-level verbs that take a WAS path as their first positional argument. */
const PATH_VERBS = new Set([
  'ls',
  'get',
  'put',
  'rm',
  'publish',
  'unpublish',
  'grant'
])

/**
 * Collects a command's own name plus its aliases.
 *
 * @param command {Command}
 * @returns {string[]}
 */
function namesOf(command: Command): string[] {
  return [command.name(), ...command.aliases()]
}

/**
 * Finds a direct subcommand of a command by name or alias.
 *
 * @param options {object}
 * @param options.parent {Command}
 * @param options.name {string}
 * @returns {Command | undefined}
 */
function findSubcommand({
  parent,
  name
}: {
  parent: Command
  name: string
}): Command | undefined {
  return parent.commands.find(command => namesOf(command).includes(name))
}

/**
 * Narrows a candidate list to those starting with the word being edited,
 * falling back to the full list when nothing matches (so a bare Tab lists
 * everything).
 *
 * @param options {object}
 * @param options.candidates {string[]}
 * @param options.editing {string}
 * @returns {string[]}
 */
function filterHits({
  candidates,
  editing
}: {
  candidates: string[]
  editing: string
}): string[] {
  const hits = candidates.filter(candidate => candidate.startsWith(editing))
  return hits.length > 0 ? hits : candidates
}

/**
 * Lists the registry space completions (handles and space ids).
 *
 * @returns {Promise<string[]>}
 */
async function spaceCompletions(): Promise<string[]> {
  const records = await listSpaceRecords()
  const out: string[] = []
  for (const { record, meta } of records) {
    if (meta?.handle) {
      out.push(meta.handle)
    }
    out.push(record.id)
  }
  return out
}

/**
 * Builds the readline completer function bound to the command tree and shell
 * session.
 *
 * @param options {object}
 * @param options.tree {Command}   The `was` command tree.
 * @param options.session {ShellSession}
 * @returns {(line: string) => Promise<[string[], string]>}
 */
export function makeShellCompleter({
  tree,
  session
}: {
  tree: Command
  session: ShellSession
}): (line: string) => Promise<[string[], string]> {
  return async function completer(line: string): Promise<[string[], string]> {
    const words = line.split(/\s+/)
    const editing = words[words.length - 1] ?? ''

    if (words.length <= 1) {
      const candidates = [...BUILTINS, ...tree.commands.flatMap(namesOf)].sort()
      return [filterHits({ candidates, editing }), editing]
    }

    const first = words[0]

    if (words.length === 2) {
      const group = findSubcommand({ parent: tree, name: first })
      if (group && group.commands.length > 0) {
        const candidates = group.commands.flatMap(namesOf).sort()
        return [filterHits({ candidates, editing }), editing]
      }
      if (session.cwd.length === 0 && PATH_VERBS.has(first)) {
        const candidates = (await spaceCompletions()).sort()
        return [
          candidates.filter(candidate => candidate.startsWith(editing)),
          editing
        ]
      }
    }

    return [[], editing]
  }
}
