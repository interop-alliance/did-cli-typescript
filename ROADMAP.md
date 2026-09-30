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

### CLI-22: `did webvh move`: portable domain move

- status: todo
- priority: medium
- labels: webvh, was-server-identity
- blocked-by: CLI-20
- acceptance:
  - [ ] `di did webvh move <did> --url <new url>` appends a domain-move entry
        via `updateDID`'s `address` (same SCID, new DID string), refusing when
        the DID was created with `--no-portable`
  - [ ] The stored artifacts (document, log, keys, update-keys, metadata) are
        renamed to the new DID string, and the handle keeps pointing at them
  - [ ] Tests resolve the moved log and assert the new DID and unchanged SCID
  - [ ] Runs the CLI-23 fast-forward check before signing (through
        `resolveWebvhForUpdate`) and accepts `--offline`

Needed by WAS-164's `SERVER_URL` move runbook. `did create webvh` already
defaults to `portable: true`, but nothing exposes the move.

---

## Agent storage demo (requesting side)

The requesting half of the agent storage demo (freewallet FW-227, designed
in freewallet's `designs/FW-227-agent-storage-demo.md`): a CLI LLM agent
asks the user's wallet for a scoped grant on a public `web` collection and
publishes `index.html` with the existing `di was put ... --capability`.
The agent is a zcap grantee with its own did:key; it never logs into the
wallet. The delegating side (`di was grant`) already exists; these items add
the inverse.

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
a complete file, so concurrent _readers_ are safe. Concurrent _writers_ of
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
