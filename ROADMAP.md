# Roadmap

Planned work for `@interop/did-cli`. Completed work is recorded in
[CHANGELOG.md](CHANGELOG.md); this file only tracks what is still open.

## Item format

Each work item is a `### CLI-N: Title` heading followed by a field block and
free prose context. Ids are permanent and never reused; new items take the next
unused number regardless of section. Statuses: `todo`, `in-progress`, `draft`
(no actionable done-state yet -- blocked or a parking record); `done` items
move verbatim to [archived-roadmap.md](archived-roadmap.md) in the same pass
that marks them done (CHANGELOG.md is the record of what landed). Full
conventions live in [AGENTS.md](AGENTS.md) under "Roadmap & Task Conventions".

---

## `edv`: real client over WAS

Graduate `di edv` from a fixture tool (encrypt/decrypt to files) to a real EDV
client that round-trips documents through Wallet Attached Storage. The
building blocks are already in place: `src/edv/core.ts` routes envelope
encryption/decryption and index blinding through `EdvClientCore`
(`@interop/edv-client`), and `@interop/was-client` ships a documents-only
`WasTransport` (plus `EDV_CONTENT_TYPE`) on its `/edv` subpath, mapping
`insert`/`update`/`get` onto ordinary WAS Resource CRUD (vault = Collection,
EDV doc id = WAS resource id).

### CLI-1: `di edv insert | get | update` over `WasTransport`

- status: todo
- priority: medium
- labels: edv, was
- acceptance:
  - [ ] `di edv insert | get | update` subcommands wire `EdvClientCore` +
        `WasTransport`
  - [ ] Existing plumbing reused: `resolveWasTarget` (`src/was/client.ts`) for
        the `SPACE/COLLECTION[/DOCID]` address + signed `WasClient`;
        `resolveRecipient` / `resolveRecipientFile` (`src/edv/recipients.ts`)
        for `--recipient`; `loadKeyAgreementKey` / `autoSelectKeyAgreementKey`
        for the decrypt key
  - [ ] Command tests follow the command-test conventions with a stubbed
        `WasClient` (`setWasClientFactory`), as in the existing `was` tests

Canonical wiring (mirrors was-client's own
`test/integration/edv-roundtrip.test.ts`):
`new EdvClientCore({ keyAgreementKey, keyResolver })` +
`new WasTransport({ was, spaceId, collectionId })`, then
`edv.insert({ doc: { content }, transport })` / `edv.get({ id, transport })` /
`edv.update({ doc, transport })`. The core encrypts/decrypts client-side; the
transport only moves opaque JWE envelopes.

Stored content type defaults to `application/json` (works against an unmodified
server); pass `EDV_CONTENT_TYPE` (`application/edv+json`) where the server
registers an `application/*+json` parser. `insert` is atomic where the
collection's backend advertises `conditional-writes`; on `update` the EDV
`sequence` is advisory (last-writer-wins).

Open decisions to settle here:

- Command verbs: `insert`/`get`/`update` (matches `EdvClientCore`'s method
  names) vs. `put`/`get` (matches the existing `was resource` verbs).
- Convergence with the `was resource` commands: does `was resource put` gain
  an `--encrypt` mode backed by this client, or does `edv` stay a parallel
  surface? (Depends on WAS's own encryption story.)

### CLI-2: `edv find` + chunked streams over WAS

- status: todo
- priority: low
- labels: edv, was
- blocked-by: CLI-1
- acceptance:
  - [ ] `@interop/was-client` bumped to a version whose `WasTransport` ships
        `find` and the chunk operations (>= 0.18.0)
  - [ ] `di edv find` subcommand wiring `EdvClientCore.find` (blinded-index
        query) through the transport
  - [ ] Chunked-stream insert/get wired through the transport's chunk
        operations

Formerly server-blocked; no longer. The WAS server now ships all the needed
affordances (blinded `/query`, chunk addressing, conditional writes), and
`WasTransport` (was-client 0.18.0) implements `find` and chunk read/write,
gated on the collection's backend advertising the `blinded-index-query` /
`chunked-streams` feature tokens (it throws `NotSupportedError` only when the
token is absent). The remaining work is entirely CLI-side.

## `did webvh`

### CLI-3: `rotate-keys` with multiple update keys / thresholds

- status: todo
- priority: medium
- labels: webvh
- acceptance:
  - [ ] `rotate-keys` manages multiple concurrent update keys (the
        `active`/`staged` layout of `<did>.update-keys.json` extends to arrays
        without a format break)
  - [ ] A signing threshold is supported if (and only if) the method spec
        settles one

`rotate-keys` v1 assumes a single active update key. The library treats
`updateKeys` as a set (and its pre-rotation check validates all of them), so
the command is the only piece that needs extending.

---

## Agent storage demo (requesting side)

The requesting half of the agent storage demo (freewallet FW-227, designed
in freewallet's `designs/FW-227-agent-storage-demo.md`): a CLI LLM agent
asks the user's wallet for a scoped grant on a public `web` collection and
publishes `index.html` with the existing `di was put ... --capability`.
The agent is a zcap grantee with its own did:key; it never logs into the
wallet. The delegating side (`di was grant`) already exists; these items add
the inverse.

### CLI-7: `di was request-grant`

- status: in-progress
- priority: high
- labels: was, zcap, agents
- touches:
  - freewallet -- FW-228 is the wallet entry point this command talks to
    (the interaction-URL handler and the deep-link route); the VPR shape
    and the deep-link path/parameter are signed off in FW-227's design doc
    before either side codes them
  - was-teaching-server -- the ephemeral-exchanges facet
    (`/workflows/ephemeral/exchanges`, 10-minute TTL) as shipped; no
    change
  - wallet-core -- WC-129 re-homes the requester-side exchange helpers and
    supplies the zcap-only VPR builder this command consumes
  - this repo -- CLI-13 (the resource-depth write the returned grant
    needs; done), CLI-8 (key file modes)
- acceptance:
  - [x] `di was request-grant` builds a zcap-only VPR (no
        `DIDAuthentication`, no `domain`) with one
        `AuthorizationCapabilityQuery` entry: a
        `https://w3id.org/byoe#public-collection` descriptor named by
        `--collection` (default `web`), `--action` (default `GET HEAD PUT
        POST`), `--reason`, and `controller` set to the agent's did:key.
        `referenceId` is omitted: it is optional in
        `ICapabilityQueryDetail`, and no consumer reads it back (grants
        correlate positionally by `invocationTarget`)
  - [x] The key is minted inside the command, not passed in. `--save
        --handle <name>` persists the key and the received zcaps under one
        handle, and is required for the demo path: `di was put
        --capability` resolves its signer out of the local key store, so a
        key held only for the run cannot sign the write that follows.
        `--save` defaults on (with `--no-save` to decline), rather than
        performing the first write in-process. The agent's context never
        sees key bytes; stdout carries the handle, the interaction URL,
        and the result
  - [x] POSTs the VPR to the server's exchange facet (`--server`), prints
        the interaction URL, and polls until complete or the exchange
        expires, with a clear timeout message
  - [ ] Prints a wallet deep link when `--wallet <url>` is given.
        Blocked: FW-227 section 8 question 1 (the route path and query
        parameter) is unsigned-off, so `--wallet` has nothing to print,
        and the flag is therefore not declared yet
  - [x] Parses the response VP (unsigned, zcap-only) and stores or prints
        the zcaps in the `z...` base58btc form `--capability` already
        accepts. The zcaps sit at
        `body.response.verifiablePresentation.zcap`
  - [x] Uses was-client handles, nothing re-derived locally. The ecosystem
        rule applies: WAS calls go through was-client handles, not raw
        ezcap `read()`/`write()` (those send `action: read/write`, which
        WAS rejects). Satisfied trivially here: this command makes no WAS
        calls of its own, only unauthenticated exchange-facet requests
  - [x] The exchange create and poll helpers come from wallet-core rather
        than being hand-rolled, which means adding `@interop/wallet-core`
        as a dependency of this package. WC-129 has not landed, so the
        helpers are consumed under their pre-move names from the
        `enrollment` subpath (`createOnboardingExchange` /
        `pollOnboardingExchange`); CLI-17 tracks the switch. The poll's
        existing `signal` option supplies the deadline WC-129 would add.
        There is no generic zcap-only VPR builder upstream, so this
        command owns one
  - [x] Command tests with a stubbed exchange; docs in README and
        ARCHITECTURE's command list

Relationship to App Connect: this is the standalone capability-query path,
not App Connect (which needs a CHAPI-attested origin a CLI does not have).
An optional `--name` (the self-declared agent name) lands with freewallet
FW-231 once its VPR member is signed off.

Landed so far: the VPR builder, the exchange create/poll, the key minting,
the response parsing, and the zcap store write, with command tests over a
stubbed exchange. What remains is the deep link, which is gated, so the item
stays open.

`--collection` is passed through unvalidated, deliberately. There is no
WAS-wide collection-id naming rule to check against: the spec requires only
that an id be URL-safe and not collide with a reserved segment, and leaves
format to the implementer. The narrower `/^[a-z0-9][a-z0-9-]{0,63}$/` in
freewallet is that wallet's own grant-time policy for which descriptor names
it will honor, and wallet-core mints `gen-<base64url>` collection ids that
fail it. Checking it here would reject names other wallets grant, so the
wallet stays the authority and an unsatisfiable request comes back granting
nothing, which the command reports.

Scope correction from FW-227's 2026-08-21 CLI-lens review: this command is
larger than "a new command plus the existing `put`". The grant that comes
back is collection-scoped, and `di was put --capability` refuses anything
that is not resource depth. CLI-13 has since landed, so the final write is
`di was put <file> --capability <zcap> --resource <id>`. WC-129 lands before
or with this item, since it is what this command consumes.
The deep-link output is also gated: FW-227 section 8 question 1 (the route
path and query parameter) is unsigned-off, so `--wallet <url>` has nothing
to print until it is decided. The interaction URL is unblocked, so only part
of this item is parallel with FW-228. The terminal QR is not part of this
item at all -- it is optional, and CLI-14 carries it on its own schedule.

### CLI-9: Claude Code skill + demo README

- status: todo
- priority: high
- labels: agents, docs
- touches:
  - freewallet -- FW-227 umbrella; the skill's wording of the consent step
    matches the FW-228 page
- acceptance:
  - [ ] A skill in this repo that walks an agent through the demo: draft
        `index.html`, `di was request-grant --wallet <url> --save --handle
        agent`, tell the user to approve in the wallet, `di was put
        <space>/web/index.html --capability agent --content-type text/html`,
        print the public URL
  - [ ] The skill states the persistence choice (`--save` or not) and never
        asks the agent to print or read key material
  - [ ] T2 guidance: when the user has no account, the skill points at the
        wallet's signup and resumes afterwards
  - [ ] A demo README with the script and the prerequisites (a Freewallet
        deployment, a teaching server with the exchange facet)

### CLI-10: Integration test for `request-grant` against the exchange facet

- status: todo
- priority: medium
- labels: was, testing, agents
- acceptance:
  - [ ] A node integration test runs `request-grant` against a local
        teaching server, with a scripted "wallet" that begins the exchange,
        delegates a public-collection zcap from a root key, and posts the
        VP back; the test then PUTs `index.html` with the stored handle and
        fetches it anonymously as `text/html`
  - [ ] Runs in the existing integration tier (server spun up the same way
        as the other `was` integration tests)

### CLI-11: `di zcap import`

- status: todo
- priority: low
- labels: zcap
- acceptance:
  - [ ] Stores a received zcap (JSON file or `z...` string) under a handle,
        so a capability obtained outside `request-grant` can be named by
        `--capability <handle>`
  - [ ] Validates the shape before storing

Split out of CLI-7, whose `--save` covers the demo.

### CLI-14: Terminal QR for `request-grant`

- status: todo
- priority: low
- labels: agents, ux, optional
- acceptance:
  - [ ] A QR dependency is chosen and added (this package has none today)
  - [ ] The rendered code fits a default 80x24 terminal, or the command
        says why it cannot and offers the interaction URL alone. The
        interaction URL runs about 95 to 110 bytes with a real host, which
        is byte mode at a version whose module count plus a four-module
        quiet zone exceeds 24 rows at two module rows per terminal row.
        Levers: error-correction level, a narrower quiet zone
  - [ ] A `--no-qr` escape, and no QR when stdout is not a TTY

Split out of CLI-7 by FW-227's 2026-08-21 CLI-lens review: the QR was
described as costing nothing, but it needs a dependency and a sizing
decision.

Optional, and not a blocker for CLI-7 or the demo: `request-grant` prints the
interaction URL, which is the whole payload a QR would encode. The QR only
saves the user a copy-paste onto a phone, so this lands if and when that
matters.

### CLI-15: Keep the server base path when resolving a capability

- status: todo
- priority: medium
- labels: was, zcap, bug
- touches:
  - freewallet -- FW-244 is the other half of the same end-to-end break
- acceptance:
  - [ ] `resolveCapabilityTarget` derives the server base URL from the
        capability's `invocationTarget` without discarding its path
        prefix, so a sub-path deployment (`https://host/was`) resolves to
        `https://host/was` rather than `https://host`
  - [ ] `fromCapability` then parses the target against the full base, and
        a sub-path target no longer misparses
  - [ ] A test covers a capability issued on a sub-path deployment

Discovered by FW-227's 2026-08-21 CLI-lens review. Today the server is
taken as `new URL(invocationTarget).origin`, which drops any base path
before was-client strips that same base path to classify the target. Paired
with freewallet's FW-244; both must land for the agent demo to claim
sub-path deployments, and FW-227 section 8 question 10 is where the "or
state bare-origin only" alternative is decided.

### CLI-17: Switch `request-grant` to the re-homed exchange helpers

- status: todo
- priority: low
- labels: was, agents, cross-repo
- blocked-by: CLI-7
- touches:
  - wallet-core -- WC-129 is the move this item consumes
- acceptance:
  - [ ] `src/was/request-grant.ts` imports the exchange create and poll
        helpers from wallet-core's `request` subpath under their post-move
        names, instead of `createOnboardingExchange` /
        `pollOnboardingExchange` from `enrollment`
  - [ ] If WC-129's poll ships its own deadline option, the local
        `AbortSignal.timeout` wrapper gives way to it
  - [ ] If WC-129 lands a zcap-only VPR builder, `buildCapabilityRequest`
        gives way to it, keeping only the collection-name check and the
        action normalization this CLI needs

discovered-from: CLI-7. WC-129 had not landed when `request-grant` was
written, so it consumes the helpers under their pre-move names. They are
reachable today (the `enrollment` subpath is in wallet-core's export map) and
the poll already takes an `AbortSignal`, so nothing was hand-rolled and
nothing is blocked -- the names are simply wrong for a caller that is not
onboarding a wallet. This is a rename to follow, not a rewrite.

## Someday / Maybe

Items with no current trigger; parked here so the active sections stay
actionable.

### CLI-4: Local-filesystem EDV transport

- status: draft (parking record)
- priority: low
- labels: someday, edv
- acceptance: none yet -- revisit if offline `find` is needed

A local-filesystem transport as an intermediate step, so `find`/index queries
can be exercised without a live server.

### CLI-5: Richer symmetric-key storage for HMAC secrets

- status: draft (parking record)
- priority: low
- labels: someday, keys
- acceptance: none yet -- revisit if the key store grows a richer
  symmetric-key story

Wallet storage shape for the raw HMAC secret and the `key create --type hmac`
ergonomics (current shape works).

### CLI-12: MCP server over the `was` library

- status: draft (parking record)
- priority: low
- labels: someday, agents
- acceptance: none yet -- revisit if a harness without shell access wants
  the demo

Expose `request-grant` / `put` / `publish` as MCP tools over the same
library the CLI uses; the CLI and skill (CLI-7, CLI-9) stay the primary
surface.

### CLI-16: Atomic writes assume a single writer

- status: draft
- priority: low
- labels: someday, storage, parking-record
- acceptance: none yet -- revisit if two `di` processes are expected to
  write the same wallet concurrently

`writeFileAtomic` in `src/storage.ts` writes to a fixed sibling name,
`${filePath}.tmp`, then renames. The rename is atomic and readers always see
a complete file, so concurrent *readers* are safe. Concurrent *writers* of
the same artifact are not: two `di` processes saving the same DID or key
race for the one temp path. The temp file is now unlinked and reopened with
`wx`, so the loser of the race fails with `EEXIST` instead of interleaving
its writes into the winner's file -- a visible error rather than a file that
is neither process's content, but still not a solution.

Nothing enforces the assumption today; it is simply that a single user runs
one command at a time. `di was shell` keeps a single process, and the agent
demo (CLI-7, CLI-9) is one agent against one wallet, so no current path
reaches it.

If promoted, the fix is a per-write unique temp name (pid plus a counter, or
`mkstemp`-style) so writers cannot collide on the same path, plus a decision
about stale temp files left by crashed runs -- the current fixed name is
self-cleaning by reuse, and a unique name is not. Last-write-wins between the
two renames is still the outcome and that is acceptable; the corruption is
what is not.

Not covered here: durability. Neither the file nor its parent directory is
`fsync`-ed, so the guarantee holds against a process dying, not against the
machine losing power. That is a separate question from the writer count.

discovered-from: CLI-8, which changed `writeFileAtomic` to set a file mode
and put the temp path under review.
