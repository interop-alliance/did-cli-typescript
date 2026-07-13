/**
 * `was shell` -- an interactive REPL over the `was` command tree. It builds the
 * existing `makeWasCommand()` tree once and re-`parseAsync`es it per input
 * line, so every subcommand, the space registry, signer loading, and the
 * address grammar are reused verbatim. A "current directory" (`cd`/`use`) makes
 * paths relative via the `setWasAddressBase` seam, and the `setRunAndExitReporter`
 * seam keeps a failing command from exiting the process.
 *
 * Session server/DID defaults ride the `WAS_SERVER_URL` / `WAS_DID` environment
 * channel that `resolveWasTarget`/`buildWasClient` already read at the right
 * precedence; the shell snapshots both at startup and restores them on exit.
 *
 * The prompt and diagnostics go to stderr (the readline `output`); command data
 * stays on stdout via the commands' own `console.log`, so `di was shell < script`
 * keeps a pipe-clean stdout.
 */
import { createInterface } from 'node:readline/promises'
import { Command } from 'commander'
import { setWasAddressBase } from '../../was/address.js'
import { didOption, serverOption, setRunAndExitReporter } from './shared.js'
import { makeWasShellDispatcher } from './shell/dispatcher.js'
import { makeShellCompleter } from './shell/completer.js'
import {
  formatCwd,
  resolveCwdChange,
  type ShellSession
} from './shell/session.js'

/**
 * Builds the `shell [path]` command. `[path]` is the initial working directory
 * and `--server`/`--did` seed the session defaults.
 *
 * @returns {Command}
 */
export function makeWasShellCommand(): Command {
  return new Command('shell')
    .argument('[path]', 'initial working directory (SPACE[/COLLECTION])')
    .description('Start an interactive WAS shell (REPL) for exploring spaces')
    .addOption(serverOption())
    .addOption(didOption())
    .action(
      async (
        path: string | undefined,
        options: { server?: string; did?: string }
      ) => {
        const code = await runWasShell({ path, ...options })
        if (code !== 0) {
          process.exit(code)
        }
      }
    )
}

/**
 * Recursively applies `exitOverride()` (throw instead of `process.exit`) and
 * routes commander's own output to the shell's stream, across the whole tree.
 * `addCommand()` does not inherit these settings, so every subcommand must be
 * configured explicitly.
 *
 * @param options {object}
 * @param options.command {Command}
 * @param options.output {NodeJS.WritableStream}
 * @returns {void}
 */
function configureTreeForShell({
  command,
  output
}: {
  command: Command
  output: NodeJS.WritableStream
}): void {
  command.exitOverride()
  command.configureOutput({
    writeOut: str => output.write(str),
    writeErr: str => output.write(str)
  })
  for (const sub of command.commands) {
    configureTreeForShell({ command: sub, output })
  }
}

/**
 * Sets or clears a process environment variable, deleting it when the value is
 * undefined (so a snapshot restore removes vars that were unset at startup).
 *
 * @param options {object}
 * @param options.key {string}
 * @param [options.value] {string}
 * @returns {void}
 */
function assignEnv({ key, value }: { key: string; value?: string }): void {
  if (value === undefined) {
    delete process.env[key]
  } else {
    process.env[key] = value
  }
}

/**
 * Runs the interactive WAS shell: snapshots the env defaults, builds and
 * shell-configures the command tree, and drives a readline question loop until
 * `exit`/`quit` or end-of-input. Server/DID env defaults and the address base
 * are restored on exit.
 *
 * @param options {object}
 * @param [options.path] {string}   Initial working directory.
 * @param [options.server] {string}   Initial `WAS_SERVER_URL` default.
 * @param [options.did] {string}   Initial `WAS_DID` default.
 * @param [options.input] {NodeJS.ReadableStream}   REPL input (defaults to stdin).
 * @param [options.output] {NodeJS.WritableStream}   REPL output (defaults to stderr).
 * @returns {Promise<number>}   The process exit code (always 0).
 */
export async function runWasShell({
  path,
  server,
  did,
  input = process.stdin,
  output = process.stderr
}: {
  path?: string
  server?: string
  did?: string
  input?: NodeJS.ReadableStream
  output?: NodeJS.WritableStream
} = {}): Promise<number> {
  // `makeWasCommand` is imported lazily to break the module cycle with was.ts
  // (which wires this shell command into the tree).
  const { makeWasCommand } = await import('../was.js')
  const tree = makeWasCommand()
  configureTreeForShell({ command: tree, output })

  const savedServer = process.env.WAS_SERVER_URL
  const savedDid = process.env.WAS_DID
  if (server !== undefined) {
    process.env.WAS_SERVER_URL = server
  }
  if (did !== undefined) {
    process.env.WAS_DID = did
  }

  const session: ShellSession = { cwd: [] }
  if (path) {
    try {
      const change = resolveCwdChange({ cwd: [], arg: path })
      session.cwd = change.cwd
      if (change.server) {
        process.env.WAS_SERVER_URL = change.server
      }
    } catch (err) {
      output.write(`${(err as Error).message}\n`)
    }
  }

  // Keep failing commands from exiting the process.
  setRunAndExitReporter(() => {})

  const terminal = Boolean((input as NodeJS.ReadStream).isTTY)
  const rl = createInterface({
    input,
    output,
    terminal,
    completer: makeShellCompleter({ tree, session })
  })

  const dispatch = makeWasShellDispatcher({ tree })

  // Ctrl+C clears the current line and re-prompts (best effort) rather than
  // exiting; Ctrl+D / end-of-input ends the readline async iterator below.
  let currentPrompt = ''
  rl.on('SIGINT', () => {
    output.write(`\n${currentPrompt}`)
  })

  if (terminal) {
    output.write(
      'Interactive WAS shell. Type "help" for builtins, "exit" to quit.\n'
    )
  }

  // The readline async iterator (unlike a `question` loop) buffers input lines
  // instead of dropping any that arrive between prompts -- essential for
  // scripted input (`di was shell < script`).
  const lines = rl[Symbol.asyncIterator]()
  try {
    for (;;) {
      setWasAddressBase(session.cwd)
      currentPrompt = `was:${formatCwd(session.cwd)}> `
      output.write(currentPrompt)
      const next = await lines.next()
      if (next.done) {
        output.write('\n')
        break
      }
      const outcome = await dispatch({ line: next.value, session, output })
      if (outcome === 'exit') {
        break
      }
    }
  } finally {
    setWasAddressBase([])
    setRunAndExitReporter()
    rl.close()
    assignEnv({ key: 'WAS_SERVER_URL', value: savedServer })
    assignEnv({ key: 'WAS_DID', value: savedDid })
  }

  return 0
}
