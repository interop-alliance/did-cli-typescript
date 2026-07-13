/**
 * The interactive shell's per-line dispatcher: tokenizes a line, handles the
 * builtins (`cd`/`use`, `pwd`, `connect`, `did`, `help`, `exit`/`quit`, blank
 * and `#`-comment lines, and a rejected nested `shell`), guards stdin-payload
 * commands that would fight readline for stdin, then hands the rest to the
 * shared command tree via `parseAsync`. Command errors are reported by the
 * commands themselves (and swallowed as `CommanderError`s here), so a bad line
 * never stops the loop.
 */
import { Command, CommanderError } from 'commander'
import { tokenizeShellLine } from './tokenize.js'
import { formatCwd, resolveCwdChange, type ShellSession } from './session.js'

/**
 * A summary of the shell builtins, printed by `help` before commander's own
 * command help.
 */
const BUILTINS_HELP = `Shell builtins:
  cd / use <path>   change the current directory (SPACE[/COLLECTION], .., /, or a full space URL)
  pwd               print the current directory and effective server/DID
  connect <url>     set the session WAS server URL (WAS_SERVER_URL)
  did <ref>         set the session signing DID (WAS_DID)
  help              show this summary and the command help
  exit / quit       leave the shell (Ctrl+D also works)

`

/**
 * Options on the stdin-reading verbs that take a following value; used to
 * count positional arguments when guarding stdin payloads and bare `ls`.
 */
const VALUE_FLAGS = new Set([
  '--server',
  '--did',
  '--capability',
  '--content-type',
  '--output'
])

const STDIN_GUARD_MESSAGE =
  'Provide a file argument inside the shell (the shell owns stdin).'

/**
 * Splits a verb's argument tokens into positionals and notes whether
 * `--capability` was given, skipping the values of value-taking flags. Handles
 * the `--flag=value` form (no separate value token) as well.
 *
 * @param rest {string[]}
 * @returns {{positionals: string[], hasCapability: boolean}}
 */
function splitArgs(rest: string[]): {
  positionals: string[]
  hasCapability: boolean
} {
  const positionals: string[] = []
  let hasCapability = false
  for (let index = 0; index < rest.length; index++) {
    const token = rest[index]
    if (token.startsWith('-')) {
      const name = token.split('=')[0]
      if (name === '--capability') {
        hasCapability = true
      }
      if (!token.includes('=') && VALUE_FLAGS.has(name)) {
        index++
      }
      continue
    }
    positionals.push(token)
  }
  return { positionals, hasCapability }
}

/**
 * Returns a guard message when a line would run a stdin-reading verb (`put`,
 * `add`, or `space import`) with no file argument -- which cannot work while
 * readline owns stdin -- or undefined when the line is safe to dispatch.
 *
 * @param tokens {string[]}
 * @returns {string | undefined}
 */
function guardStdinPayload(tokens: string[]): string | undefined {
  const [head, ...tail] = tokens
  let group: string | undefined
  let verb = head
  let rest = tail
  if (head === 'resource' || head === 'res' || head === 'space') {
    group = head
    verb = tail[0]
    rest = tail.slice(1)
  }

  if (verb === 'put' || verb === 'add') {
    const { positionals, hasCapability } = splitArgs(rest)
    const fileProvided = hasCapability
      ? positionals.length >= 1
      : positionals.length >= 2
    if (!fileProvided) {
      return STDIN_GUARD_MESSAGE
    }
  }
  if (group === 'space' && verb === 'import') {
    const { positionals } = splitArgs(rest)
    if (positionals.length < 2) {
      return STDIN_GUARD_MESSAGE
    }
  }
  return undefined
}

/**
 * Appends `.` to a bare `ls` when a directory is selected, so it lists the
 * current directory (the address base turns `.` into the cwd). At the root
 * `ls` has nothing to list and is left alone.
 *
 * @param options {object}
 * @param options.tokens {string[]}
 * @param options.session {ShellSession}
 * @returns {string[]}
 */
function appendCwdForBareLs({
  tokens,
  session
}: {
  tokens: string[]
  session: ShellSession
}): string[] {
  if (tokens[0] !== 'ls' || session.cwd.length === 0) {
    return tokens
  }
  const { positionals } = splitArgs(tokens.slice(1))
  return positionals.length > 0 ? tokens : [...tokens, '.']
}

/**
 * Handles `cd`/`use`: updates the session cwd, adopting a full space URL's
 * origin as the server default.
 */
function handleCd({
  session,
  arg,
  output
}: {
  session: ShellSession
  arg?: string
  output: NodeJS.WritableStream
}): void {
  if (arg === undefined) {
    session.cwd = []
    return
  }
  try {
    const { cwd, server } = resolveCwdChange({ cwd: session.cwd, arg })
    session.cwd = cwd
    if (server) {
      process.env.WAS_SERVER_URL = server
    }
  } catch (err) {
    output.write(`${(err as Error).message}\n`)
  }
}

/**
 * Handles `pwd`: prints the current directory and the effective server/DID.
 */
function handlePwd({
  session,
  output
}: {
  session: ShellSession
  output: NodeJS.WritableStream
}): void {
  output.write(`${formatCwd(session.cwd)}\n`)
  output.write(`server: ${process.env.WAS_SERVER_URL ?? '(unset)'}\n`)
  output.write(`did: ${process.env.WAS_DID ?? '(unset)'}\n`)
}

/**
 * Builds the per-line dispatch function bound to the command tree. The
 * returned function reports `'exit'` when the loop should stop.
 *
 * @param options {object}
 * @param options.tree {Command}
 * @returns {(options: {line: string, session: ShellSession, output: NodeJS.WritableStream}) => Promise<'exit' | void>}
 */
export function makeWasShellDispatcher({
  tree
}: {
  tree: Command
}): (options: {
  line: string
  session: ShellSession
  output: NodeJS.WritableStream
}) => Promise<'exit' | void> {
  return async function dispatch({
    line,
    session,
    output
  }): Promise<'exit' | void> {
    const trimmed = line.trim()
    if (trimmed === '' || trimmed.startsWith('#')) {
      return
    }

    let tokens: string[]
    try {
      tokens = tokenizeShellLine(trimmed)
    } catch (err) {
      output.write(`${(err as Error).message}\n`)
      return
    }
    if (tokens.length === 0) {
      return
    }

    const [command, ...args] = tokens
    switch (command) {
      case 'exit':
      case 'quit':
        return 'exit'
      case 'cd':
      case 'use':
        handleCd({ session, arg: args[0], output })
        return
      case 'pwd':
        handlePwd({ session, output })
        return
      case 'connect':
        if (!args[0]) {
          output.write('Usage: connect <url>\n')
          return
        }
        process.env.WAS_SERVER_URL = args[0]
        output.write(`server: ${args[0]}\n`)
        return
      case 'did':
        if (!args[0]) {
          output.write('Usage: did <ref>\n')
          return
        }
        process.env.WAS_DID = args[0]
        output.write(`did: ${args[0]}\n`)
        return
      case 'help':
        output.write(BUILTINS_HELP)
        tree.outputHelp()
        return
      case 'shell':
        output.write(
          'Already inside a shell; nested shells are not supported.\n'
        )
        return
    }

    const guardMessage = guardStdinPayload(tokens)
    if (guardMessage) {
      output.write(`${guardMessage}\n`)
      return
    }

    try {
      await tree.parseAsync(appendCwdForBareLs({ tokens, session }), {
        from: 'user'
      })
    } catch (err) {
      // exitOverride throws after commander has already written help or the
      // usage/error message through the configured output; nothing more to do.
      if (err instanceof CommanderError) {
        return
      }
      output.write(`${(err as Error).message}\n`)
    }
  }
}
