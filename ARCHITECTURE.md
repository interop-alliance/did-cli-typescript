# Architecture

A map of this codebase for contributors (human or AI). For code-style rules see
[CONTRIBUTING.md](CONTRIBUTING.md); for the on-disk wallet layout see
[STORAGE.md](STORAGE.md); for end-user command docs see [README.md](README.md).

`@interop/did-cli` is a command-line wallet (`di`) for creating and managing
DIDs, Verifiable Credentials, authorization capabilities (zCaps), and their
cryptographic key pairs, plus a client for Wallet Attached Storage (WAS)
servers. It is an ES-module TypeScript project (Node `>=22`), built with `tsc`
and tested with the native `node:test` runner.

## Entry point and command wiring

`src/index.ts` is the executable. It builds a single [`commander`](https://github.com/tj/commander.js)
program named `di` and registers each command group:

```ts
program.addCommand(makeDidCommand())
program.addCommand(makeKeyCommand())
// ...one per command group
```

Each `src/commands/<name>.ts` exports a `makeXCommand(): Command` factory that
returns a configured `commander` `Command`. **To add a command:** create
`src/commands/<name>.ts` exporting `makeXCommand()`, then add one
`program.addCommand(makeXCommand())` line to `src/index.ts`.

## The command-factory pattern

Inside a factory, subcommands are declared with
`.command().description().option().action()`. The `.action()` callback
destructures its options and delegates to a `run*` function that returns a
numeric exit code; output goes to `console.log`, diagnostics and errors to
`console.error`, and a non-zero return triggers `process.exit`. This split keeps
the `run*` functions directly unit-testable (see
[Testing](#testing)). The `was` group is large enough that its `run*` functions
live in their own directory, `src/commands/was/` (see the module map), while
`src/commands/was.ts` keeps only `makeWasCommand()`.

## Module map

| Path | Responsibility |
| --- | --- |
| `src/index.ts` | Executable entry point; builds the `di` program and registers command groups. |
| `src/commands/` | Command factories: `did`, `key`, `vc`, `wallet`, `was`, `zcap`. |
| `src/commands/was/` | The `was` group's `run*` functions, split by noun: `space`, `collection`, `resource`, `tree` (the `ls`/`rm` shorthands), `policy`, `publish` (publish/unpublish/grant), and `shared` (option factories, address parsing, listing renderers). |
| `src/storage.ts` | Wallet + DID-document file I/O: `listCollection`, `loadFromCollection`, `saveToCollection`, and `.meta.json` sidecars. |
| `src/meta.ts` | Key/DID resolution: `resolve*Ref` (DID, key, zcap, credential), `parseKeyStorageId`, `mapFingerprintsToDids`. |
| `src/table.ts` | Dependency-free column-aligned table rendering (`renderTable`, `truncateMiddle`). |
| `src/keys/ecdsa.ts` | ECDSA curve normalization and VC-issuance capability checks. |
| `src/vc/` | Verifiable Credential `issue`/`verify`, issuer registries, and signature suites. |
| `src/was/` | WAS client logic (non-CLI): `client`, `address`, `registry`, `capability`, `io`. |
| `src/zcap/` | Capability `create`/`delegate`/`signer`/`encoding`/`ttl`. |

## Storage and configuration

Wallet items and DID documents are persisted as JSON files with `.meta.json`
sidecars; the full layout is in [STORAGE.md](STORAGE.md). Storage locations and
per-command defaults/seeds are controlled by environment variables --
`WALLET_DIR`, `DIDS_DIR`, `SECRET_KEY_SEED`, `WAS_DID`, `WAS_SERVER_URL`,
`ZCAP_CONTROLLER_KEY_SEED` -- documented in the
[Environment Variables](README.md#environment-variables) table in the README.

## Build, test, lint

```bash
pnpm build      # tsc -> dist/
pnpm test       # lint + format check + node:test suite
pnpm lint       # eslint src
pnpm fix        # eslint --fix + prettier --write

# run a single test file:
node --test --import tsx --enable-source-maps src/commands/<name>.test.ts
```

## Testing

Tests use `node:test` with `node:assert/strict`. Command tests capture output by
mocking `console.log`/`console.error` into arrays, point storage at temp dirs via
the `WALLET_DIR`/`DIDS_DIR` env vars, and invoke a command through its factory:
`makeXCommand().parseAsync([...args], { from: 'user' })`. The conventions are
spelled out under "Command Tests" in [CONTRIBUTING.md](CONTRIBUTING.md).

## Command surface

```
di did create [method]          create a DID (key | web | webvh; default key)
di did add-key <did>            add a verification method to a stored DID
di did resolve <did>            resolve a DID to its document
di did show|view|cat <did>      show a stored DID document
di did list                     list stored DIDs
di did meta <did>               show/edit a DID's local metadata
di did remove|delete|rm <did>   remove a stored DID

di key create                   generate a key pair
di key list                     list stored keys
di key show|view|cat <id>       show a stored key
di key meta <id>                show/edit a key's local metadata
di key remove|delete|rm <id>    remove a stored key
di key export <id>              export a key pair

di vc verify [file]             verify a Verifiable Credential
di vc issue [file]              issue (sign) a Verifiable Credential
di vc import [source]           import a credential into the wallet
di vc list                      list stored credentials
di vc show|view|cat <id>        show a stored credential
di vc meta <id>                 show/edit a credential's local metadata
di vc remove|delete|rm <id>     remove a stored credential

di zcap create                  create a root capability
di zcap delegate                delegate (attenuate) a capability
di zcap list                    list stored capabilities
di zcap show|view|cat <id>      show a stored capability
di zcap meta <id>               show/edit a capability's local metadata
di zcap remove|delete|rm <id>   remove a stored capability
di zcap revoke <id>             revoke a delegated capability

di wallet ls|list               list all wallet collections and items

di was space <create|list|show|update|delete|forget|add|export|import>
di was collection|coll <create|list|show|update|delete>
di was resource|res <add|put|get|list|delete>
di was ls|get|put|rm [path]     depth-dispatching shorthands
di was policy <show|set|clear>  manage access-control policies
di was publish|unpublish <path> toggle world-readable access
di was grant <path>             delegate access via a signed capability
```
