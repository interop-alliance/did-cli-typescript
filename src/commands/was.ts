/**
 * `was` command -- Wallet Attached Storage (WAS) operations.
 *
 * Talks to WAS servers via `@interop/was-client`, signing every request with
 * a `did:key` DID stored in the local wallet. Spaces are addressed by a
 * single positional WAS path -- `SPACE[/COLLECTION[/RESOURCE]]` -- where the
 * space part is a local registry handle, a bare space id, or a full space
 * https URL (see `src/was/address.ts`). The local space registry
 * (`~/.config/did-cli-wallet/was-spaces/`) records each space's server URL and controller
 * DID so day-to-day commands need no `--server`/`--did` flags.
 *
 * Subcommand groups: `space` (`create`, `list`, `show`, `update` alias
 * `configure`, `delete`, `forget`, `meta`, `add`, `backends`, `quotas`),
 * `collection` (alias `coll`;
 * `create`, `list`, `show`, `update`, `delete`, `backend`, `quota`),
 * `resource` (alias
 * `res`; `add`, `put`, `get`, `list`, `delete`), and `resource-meta`
 * (alias `meta`; `get`, `put`). The top-level shorthand
 * verbs `ls`, `get`, `put`, and `rm` dispatch on the path depth, mirroring
 * the client's uniform-verbs-at-every-level design. Resource payloads come
 * from a file argument or stdin, with JSON-vs-binary detection in
 * `src/was/io.ts`.
 *
 * Data goes to stdout, diagnostics to stderr. Exit codes: 0 success, 1
 * operation error (typed WAS errors and not-found/not-visible reads), 2
 * input error (bad path syntax, unknown handle/DID, missing server URL).
 *
 * The run functions for each subcommand group live in `src/commands/was/`;
 * this module wires them onto the commander command tree.
 */
import { Command } from 'commander'
import {
  capabilityOption,
  contentTypeOption,
  didOption,
  disambiguatePayloadArgs,
  runAndExit,
  serverOption
} from './was/shared.js'
import {
  runSpaceAdd,
  runSpaceBackends,
  runSpaceCreate,
  runSpaceDelete,
  runSpaceExport,
  runSpaceForget,
  runSpaceImport,
  runSpaceList,
  runSpaceMeta,
  runSpaceQuotas,
  runSpaceShow,
  runSpaceUpdate
} from './was/space.js'
import {
  runCollectionBackend,
  runCollectionCreate,
  runCollectionDelete,
  runCollectionList,
  runCollectionQuota,
  runCollectionShow,
  runCollectionUpdate
} from './was/collection.js'
import {
  runResourceAdd,
  runResourceDelete,
  runResourceGet,
  runResourceList,
  runResourceMetaGet,
  runResourceMetaPut,
  runResourcePut
} from './was/resource.js'
import { runLs, runRm } from './was/tree.js'
import { runPolicyClear, runPolicySet, runPolicyShow } from './was/policy.js'
import { runGrant, runPublish, runUnpublish } from './was/publish.js'

/**
 * Adds a resource `get [path]` verb to a parent command. Shared by
 * `was resource get` and the top-level `was get` shorthand, which differ only
 * in their description.
 *
 * @param parent {Command}
 * @param description {string}
 * @returns {void}
 */
function addGetCommand(parent: Command, description: string): void {
  parent
    .command('get [path]')
    .description(description)
    .option('--output <file>', 'write the resource content to a file')
    .addOption(capabilityOption())
    .addOption(serverOption())
    .addOption(didOption())
    .action(
      async (
        address: string | undefined,
        options: {
          output?: string
          capability?: string
          server?: string
          did?: string
        }
      ) => {
        await runAndExit(runResourceGet({ address, ...options }))
      }
    )
}

/**
 * Adds a resource `put [path] [file]` verb to a parent command. Shared by
 * `was resource put` and the top-level `was put` shorthand, which differ only
 * in their description.
 *
 * @param parent {Command}
 * @param description {string}
 * @returns {void}
 */
function addPutCommand(parent: Command, description: string): void {
  parent
    .command('put [path] [file]')
    .description(description)
    .addOption(contentTypeOption())
    .addOption(capabilityOption())
    .addOption(serverOption())
    .addOption(didOption())
    .action(
      async (
        address: string | undefined,
        file: string | undefined,
        options: {
          contentType?: string
          capability?: string
          server?: string
          did?: string
        }
      ) => {
        const args = disambiguatePayloadArgs({
          address,
          file,
          capability: options.capability
        })
        await runAndExit(runResourcePut({ ...args, ...options }))
      }
    )
}

export function makeWasCommand(): Command {
  const was = new Command('was').description(
    'Wallet Attached Storage (WAS) operations'
  )

  const space = new Command('space').description('Manage WAS spaces')

  space
    .command('create')
    .description('Create a new space on a WAS server')
    .option('--name <name>', "the space's display name")
    .addOption(serverOption())
    .addOption(didOption())
    .option(
      '--id <id>',
      'a caller-chosen space id (server-generated otherwise)'
    )
    .option(
      '--save',
      'register the space in the local wallet (~/.config/did-cli-wallet/was-spaces/)'
    )
    .option(
      '--handle <handle>',
      'short tag for the registered space (requires --save)'
    )
    .option(
      '--description <description>',
      'longer description of the registered space (requires --save)'
    )
    .action(
      async (options: {
        name?: string
        server?: string
        did?: string
        id?: string
        save?: boolean
        handle?: string
        description?: string
      }) => {
        await runAndExit(runSpaceCreate(options))
      }
    )

  space
    .command('list')
    .description('List locally registered spaces')
    .option(
      '--json',
      'output the list as a JSON array of objects with metadata'
    )
    .option('--plain', 'output one space id per line, sorted (no metadata)')
    .option(
      '--remote',
      'list the spaces on the server instead (requires server support)'
    )
    .option('--server <url>', 'the WAS server base URL (with --remote)')
    .option(
      '--did <did>',
      'DID or stored-DID handle to sign with (with --remote)'
    )
    .action(
      async (options: {
        json?: boolean
        plain?: boolean
        remote?: boolean
        server?: string
        did?: string
      }) => {
        await runAndExit(runSpaceList(options))
      }
    )

  space
    .command('show <space>')
    .aliases(['view', 'cat'])
    .description(
      "Show a space's description from the server (--meta for its local " +
        'registry metadata)'
    )
    .option('--meta', 'show the local registry metadata instead')
    .option('--json', 'with --meta, output the metadata as JSON')
    .addOption(serverOption())
    .addOption(didOption())
    .action(
      async (
        address: string,
        options: {
          meta?: boolean
          json?: boolean
          server?: string
          did?: string
        }
      ) => {
        await runAndExit(runSpaceShow({ address, ...options }))
      }
    )

  space
    .command('update <space>')
    .alias('configure')
    .description("Update a space's description fields on the server (upsert)")
    .option('--name <name>', "the space's new display name")
    .addOption(serverOption())
    .addOption(didOption())
    .action(
      async (
        address: string,
        options: { name?: string; server?: string; did?: string }
      ) => {
        await runAndExit(runSpaceUpdate({ address, ...options }))
      }
    )

  space
    .command('delete <space>')
    .alias('rm')
    .description(
      'Delete a space on the server (idempotent) and remove its local ' +
        'registry entry'
    )
    .addOption(serverOption())
    .addOption(didOption())
    .action(
      async (address: string, options: { server?: string; did?: string }) => {
        await runAndExit(runSpaceDelete({ address, ...options }))
      }
    )

  space
    .command('forget <space>')
    .description(
      'Remove only the local registry entry of a space (the server-side ' +
        'space is untouched)'
    )
    .action(async (address: string) => {
      await runAndExit(runSpaceForget({ address }))
    })

  space
    .command('meta <space>')
    .description(
      "Update a registered space's local metadata only (the server-side " +
        'space is untouched)'
    )
    .option(
      '--handle <handle>',
      'new short tag for the registered space (empty string clears it)'
    )
    .option(
      '--description <description>',
      'new longer description of the registered space (empty string clears it)'
    )
    .action(
      async (
        address: string,
        options: { handle?: string; description?: string }
      ) => {
        await runAndExit(runSpaceMeta({ address, ...options }))
      }
    )

  space
    .command('add <space>')
    .description(
      'Register an existing remote space (a full space URL, or a space id ' +
        'plus --server) in the local registry'
    )
    .addOption(serverOption())
    .addOption(didOption())
    .option('--handle <handle>', 'short tag for the registered space')
    .option(
      '--description <description>',
      'longer description of the registered space'
    )
    .action(
      async (
        address: string,
        options: {
          server?: string
          did?: string
          handle?: string
          description?: string
        }
      ) => {
        await runAndExit(runSpaceAdd({ address, ...options }))
      }
    )

  space
    .command('export <space>')
    .description('Export a whole space as a tar archive')
    .option('--output <file>', 'write the tar to a file (stdout otherwise)')
    .addOption(serverOption())
    .addOption(didOption())
    .action(
      async (
        address: string,
        options: { output?: string; server?: string; did?: string }
      ) => {
        await runAndExit(runSpaceExport({ address, ...options }))
      }
    )

  space
    .command('import <space> [file]')
    .description(
      'Import (merge) a tar archive into a space; tar from file or stdin'
    )
    .addOption(serverOption())
    .addOption(didOption())
    .action(
      async (
        address: string,
        file: string | undefined,
        options: { server?: string; did?: string }
      ) => {
        await runAndExit(runSpaceImport({ address, file, ...options }))
      }
    )

  space
    .command('backends <space>')
    .description('List the storage backends available within a space')
    .option('--json', 'output the raw backends JSON')
    .addOption(serverOption())
    .addOption(didOption())
    .action(
      async (
        address: string,
        options: { json?: boolean; server?: string; did?: string }
      ) => {
        await runAndExit(runSpaceBackends({ address, ...options }))
      }
    )

  space
    .command('quotas <space>')
    .description("Show a space's storage quota report, grouped by backend")
    .option('--json', 'output the raw quota report JSON')
    .addOption(serverOption())
    .addOption(didOption())
    .action(
      async (
        address: string,
        options: { json?: boolean; server?: string; did?: string }
      ) => {
        await runAndExit(runSpaceQuotas({ address, ...options }))
      }
    )

  was.addCommand(space)

  const collection = new Command('collection')
    .alias('coll')
    .description('Manage WAS collections')

  collection
    .command('create <space>')
    .description('Create a new collection within a space')
    .option('--name <name>', "the collection's display name")
    .option(
      '--id <id>',
      'a caller-chosen collection id (server-generated otherwise)'
    )
    .addOption(serverOption())
    .addOption(didOption())
    .action(
      async (
        address: string,
        options: { name?: string; id?: string; server?: string; did?: string }
      ) => {
        await runAndExit(runCollectionCreate({ address, ...options }))
      }
    )

  collection
    .command('list <space>')
    .description('List the collections in a space')
    .option('--json', 'output the raw listing JSON')
    .option('--plain', 'output one collection id per line, sorted')
    .addOption(serverOption())
    .addOption(didOption())
    .action(
      async (
        address: string,
        options: {
          json?: boolean
          plain?: boolean
          server?: string
          did?: string
        }
      ) => {
        await runAndExit(runCollectionList({ address, ...options }))
      }
    )

  collection
    .command('show <path>')
    .aliases(['view', 'cat'])
    .description(
      "Show a collection's description from the server (SPACE/COLLECTION)"
    )
    .addOption(serverOption())
    .addOption(didOption())
    .action(
      async (address: string, options: { server?: string; did?: string }) => {
        await runAndExit(runCollectionShow({ address, ...options }))
      }
    )

  collection
    .command('update <path>')
    .alias('configure')
    .description(
      "Update a collection's description fields on the server (upsert)"
    )
    .requiredOption('--name <name>', "the collection's new display name")
    .addOption(serverOption())
    .addOption(didOption())
    .action(
      async (
        address: string,
        options: { name: string; server?: string; did?: string }
      ) => {
        await runAndExit(runCollectionUpdate({ address, ...options }))
      }
    )

  collection
    .command('delete <path>')
    .alias('rm')
    .description(
      'Delete a whole collection and its contents on the server (idempotent)'
    )
    .addOption(serverOption())
    .addOption(didOption())
    .action(
      async (address: string, options: { server?: string; did?: string }) => {
        await runAndExit(runCollectionDelete({ address, ...options }))
      }
    )

  collection
    .command('backend <path>')
    .description(
      'Show the storage backend a collection is stored on (SPACE/COLLECTION)'
    )
    .option('--json', 'output the raw backend JSON')
    .addOption(serverOption())
    .addOption(didOption())
    .action(
      async (
        address: string,
        options: { json?: boolean; server?: string; did?: string }
      ) => {
        await runAndExit(runCollectionBackend({ address, ...options }))
      }
    )

  collection
    .command('quota <path>')
    .description(
      "Show a collection's storage usage, scoped to its backend " +
        '(SPACE/COLLECTION)'
    )
    .option('--json', 'output the raw usage JSON')
    .addOption(serverOption())
    .addOption(didOption())
    .action(
      async (
        address: string,
        options: { json?: boolean; server?: string; did?: string }
      ) => {
        await runAndExit(runCollectionQuota({ address, ...options }))
      }
    )

  was.addCommand(collection)

  const resource = new Command('resource')
    .alias('res')
    .description('Manage WAS resources')

  resource
    .command('add [path] [file]')
    .description(
      'Add a resource to a collection (server-generated id); payload from ' +
        'file or stdin'
    )
    .addOption(contentTypeOption())
    .addOption(capabilityOption())
    .addOption(serverOption())
    .addOption(didOption())
    .action(
      async (
        address: string | undefined,
        file: string | undefined,
        options: {
          contentType?: string
          capability?: string
          server?: string
          did?: string
        }
      ) => {
        const args = disambiguatePayloadArgs({
          address,
          file,
          capability: options.capability
        })
        await runAndExit(runResourceAdd({ ...args, ...options }))
      }
    )

  addPutCommand(
    resource,
    'Create or replace a resource at a known id (upsert); payload from ' +
      'file or stdin'
  )

  addGetCommand(
    resource,
    'Read a resource: JSON pretty-printed to stdout, binary written raw'
  )

  resource
    .command('list <collection>')
    .description('List the resources in a collection (SPACE/COLLECTION)')
    .option('--json', 'output the raw listing JSON')
    .option('--plain', 'output one resource id per line, sorted')
    .addOption(serverOption())
    .addOption(didOption())
    .action(
      async (
        address: string,
        options: {
          json?: boolean
          plain?: boolean
          server?: string
          did?: string
        }
      ) => {
        await runAndExit(runResourceList({ address, ...options }))
      }
    )

  resource
    .command('delete <path>')
    .alias('rm')
    .description('Delete a resource on the server (idempotent)')
    .addOption(serverOption())
    .addOption(didOption())
    .action(
      async (address: string, options: { server?: string; did?: string }) => {
        await runAndExit(runResourceDelete({ address, ...options }))
      }
    )

  was.addCommand(resource)

  const resourceMeta = new Command('resource-meta')
    .alias('meta')
    .description("Read and update a resource's metadata (custom name and tags)")

  resourceMeta
    .command('get [path]')
    .description(
      "Show a resource's metadata: content type, size, timestamps, and " +
        'custom name/tags'
    )
    .addOption(capabilityOption())
    .addOption(serverOption())
    .addOption(didOption())
    .action(
      async (
        address: string | undefined,
        options: { capability?: string; server?: string; did?: string }
      ) => {
        await runAndExit(runResourceMetaGet({ address, ...options }))
      }
    )

  resourceMeta
    .command('put [path]')
    .description(
      "Update a resource's custom metadata: --name and/or --tag key=value " +
        '(both repeatable-friendly and non-destructive), or --json for a ' +
        'full replacement'
    )
    .option(
      '--name <name>',
      "the resource's display name (preserves existing tags)"
    )
    .option(
      '--tag <pair>',
      'a custom tag as key=value; repeatable (preserves the existing name)',
      (value: string, previous: string[]) => previous.concat(value),
      []
    )
    .option(
      '--json <jsonOrFile>',
      'full custom-metadata replacement as inline JSON or a JSON file path ' +
        '(clears any omitted field)'
    )
    .addOption(capabilityOption())
    .addOption(serverOption())
    .addOption(didOption())
    .action(
      async (
        address: string | undefined,
        options: {
          name?: string
          tag: string[]
          json?: string
          capability?: string
          server?: string
          did?: string
        }
      ) => {
        await runAndExit(runResourceMetaPut({ address, ...options }))
      }
    )

  was.addCommand(resourceMeta)

  was
    .command('ls [path]')
    .description(
      'List the collections of a space, or the resources of a collection'
    )
    .option('--json', 'output the raw listing JSON')
    .option('--plain', 'output one id per line, sorted')
    .addOption(capabilityOption())
    .addOption(serverOption())
    .addOption(didOption())
    .action(
      async (
        address: string | undefined,
        options: {
          json?: boolean
          plain?: boolean
          capability?: string
          server?: string
          did?: string
        }
      ) => {
        await runAndExit(runLs({ address, ...options }))
      }
    )

  addGetCommand(was, 'Read a resource (shorthand for "resource get")')

  addPutCommand(
    was,
    'Create or replace a resource (shorthand for "resource put")'
  )

  was
    .command('rm [path]')
    .description(
      'Delete whatever the path points at: a space, a collection, or a ' +
        'resource'
    )
    .addOption(capabilityOption())
    .addOption(serverOption())
    .addOption(didOption())
    .action(
      async (
        address: string | undefined,
        options: { capability?: string; server?: string; did?: string }
      ) => {
        await runAndExit(runRm({ address, ...options }))
      }
    )

  const policy = new Command('policy').description(
    'Manage access-control policies (at space, collection, or resource depth)'
  )

  policy
    .command('show <path>')
    .aliases(['view', 'cat'])
    .description('Show the access-control policy of a path')
    .addOption(serverOption())
    .addOption(didOption())
    .action(
      async (address: string, options: { server?: string; did?: string }) => {
        await runAndExit(runPolicyShow({ address, ...options }))
      }
    )

  policy
    .command('set <path> [file]')
    .description(
      'Set the access-control policy of a path: --type for a simple ' +
        'type-only policy, or a policy JSON file'
    )
    .option('--type <type>', 'a simple type-only policy, e.g. PublicCanRead')
    .addOption(serverOption())
    .addOption(didOption())
    .action(
      async (
        address: string,
        file: string | undefined,
        options: { type?: string; server?: string; did?: string }
      ) => {
        await runAndExit(runPolicySet({ address, file, ...options }))
      }
    )

  policy
    .command('clear <path>')
    .description(
      'Remove the access-control policy of a path (back to capability-only ' +
        'access; idempotent)'
    )
    .addOption(serverOption())
    .addOption(didOption())
    .action(
      async (address: string, options: { server?: string; did?: string }) => {
        await runAndExit(runPolicyClear({ address, ...options }))
      }
    )

  was.addCommand(policy)

  was
    .command('publish <path>')
    .description(
      'Make a space, collection, or resource world-readable and print its ' +
        'public URL'
    )
    .addOption(serverOption())
    .addOption(didOption())
    .action(
      async (address: string, options: { server?: string; did?: string }) => {
        await runAndExit(runPublish({ address, ...options }))
      }
    )

  was
    .command('unpublish <path>')
    .description(
      'Revert a published space, collection, or resource to capability-only ' +
        'access'
    )
    .addOption(serverOption())
    .addOption(didOption())
    .action(
      async (address: string, options: { server?: string; did?: string }) => {
        await runAndExit(runUnpublish({ address, ...options }))
      }
    )

  was
    .command('grant <path>')
    .description(
      'Delegate access to a space, collection, or resource (prints the ' +
        'signed capability and its encoded form)'
    )
    .requiredOption(
      '--to <did>',
      'the DID (or stored-DID handle) to delegate to'
    )
    .requiredOption(
      '--action <verb...>',
      'allowed action(s): GET, PUT, POST, DELETE (lowercase accepted)'
    )
    .option('--ttl <duration>', 'time to live, e.g. 1y, 30d, 24h', '1y')
    .option('--expires <iso>', 'explicit ISO 8601 expiration (overrides --ttl)')
    .option(
      '--save',
      'save the capability to local wallet storage (~/.config/did-cli-wallet/zcaps/)'
    )
    .option(
      '--handle <handle>',
      'short tag for the saved capability (requires --save)'
    )
    .option(
      '--description <description>',
      'longer description of the saved capability (requires --save)'
    )
    .addOption(serverOption())
    .addOption(didOption())
    .action(
      async (
        address: string,
        options: {
          to: string
          action: string[]
          ttl?: string
          expires?: string
          save?: boolean
          handle?: string
          description?: string
          server?: string
          did?: string
        }
      ) => {
        await runAndExit(runGrant({ address, ...options }))
      }
    )

  return was
}
