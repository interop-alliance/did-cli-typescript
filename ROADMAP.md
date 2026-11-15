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
(`@interop/edv-client`), and `@interop/pws-client` ships a documents-only
`PwsTransport` (plus `EDV_CONTENT_TYPE`) on its `/edv` subpath, mapping
`insert`/`update`/`get` onto ordinary WAS Resource CRUD (vault = Collection,
EDV doc id = WAS resource id).

### CLI-1: `di edv insert | get | update` over `PwsTransport`

- status: todo
- priority: medium
- labels: edv, was
- acceptance:
  - [ ] `di edv insert | get | update` subcommands wire `EdvClientCore` +
        `PwsTransport`
  - [ ] Existing plumbing reused: `resolveWasTarget` (`src/was/client.ts`) for
        the `SPACE/COLLECTION[/DOCID]` address + signed `PwsClient`;
        `resolveRecipient` / `resolveRecipientFile` (`src/edv/recipients.ts`)
        for `--recipient`; `loadKeyAgreementKey` / `autoSelectKeyAgreementKey`
        for the decrypt key
  - [ ] Command tests follow the command-test conventions with a stubbed
        `PwsClient` (`setWasClientFactory`), as in the existing `was` tests

Canonical wiring (mirrors pws-client's own
`test/integration/edv-roundtrip.test.ts`):
`new EdvClientCore({ keyAgreementKey, keyResolver })` +
`new PwsTransport({ pws, spaceUrl, collectionId })`, then
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
  - [x] `@interop/pws-client` is at a version whose `PwsTransport` ships
        `find` and the chunk operations (every release since the rename)
  - [ ] `di edv find` subcommand wiring `EdvClientCore.find` (blinded-index
        query) through the transport
  - [ ] Chunked-stream insert/get wired through the transport's chunk
        operations

Formerly server-blocked; no longer. The WAS server now ships all the needed
affordances (blinded `/query`, chunk addressing, conditional writes), and
`PwsTransport` (added as `WasTransport` in was-client 0.18.0) implements `find`
and chunk read/write, gated on the collection's backend advertising the
`blinded-index-query` / `chunked-streams` feature tokens (it throws
`NotSupportedError` only when the token is absent). The remaining work is
entirely CLI-side.

## `did webvh` and `did vh`

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

Needed by WSS-164's `SERVER_URL` move runbook. `did create webvh` already
defaults to `portable: true`, but nothing exposes the move.

### CLI-29: Witness proofs for did:vh

- status: draft
- priority: medium
- labels: vh, webvh

discovered-from: CLI-28. `did create vh` rejects `--witness` and
`--witness-threshold`, because the CLI neither collects nor stores witness
proofs. The did:vh library entry
points fetch nothing, so a witnessed did:vh would fail `did show` and every
update with "Witness threshold not met". A did:webvh has the same gap, hidden behind the
fetch of the served `did-witness.json`. Draft because the stored witness file
(name and placement beside the log) and the way proofs are collected from
witnesses are not designed yet.

### CLI-30: Fast-forward check for did:vh

- status: todo
- priority: low
- labels: vh
- acceptance:
  - [ ] The did:vh update commands accept a log location (for example
        `--src <url>`) and run the fast-forward check against the log served
        there before signing
  - [ ] Without a location the commands behave as today (no check)
  - [ ] Tests cover a served log that is ahead of, and one that has diverged
        from, the local log

discovered-from: CLI-28. A did:vh DID names no location, so
`resolveWebvhForUpdate` skips `assertFastForward` for it. A controller who
publishes the log at a known location has the same stale-local-log risk as
did:webvh.

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

## Dependency upkeep

### CLI-26: Drop the transitive `@interop/was-client`

- status: draft
- priority: low
- labels: deps

discovered-from: the `@interop/pws-client` rename. `@interop/wallet-request`
0.6.0 still depends on `@interop/was-client` `^0.103.0`, and
`@interop/wallet-core` 0.111.0 still has it as a peer dependency, so 0.103.0
stays in the install tree beside `pws-client`. Blocked until both packages
publish versions that depend on `@interop/pws-client`. Nothing in `src/`
imports `@interop/wallet-core`, so its dependency may be removable instead.

### CLI-27: Adopt the next breaking `@interop/did-method-webvh` release

- status: todo
- priority: medium
- labels: deps, webvh
- acceptance:
  - [ ] `@interop/did-method-webvh` is bumped to the release that follows
        5.18.2 and carries the changes below
  - [ ] Code and tests compile against `meta.ttl` as a string, and against
        `didDocumentMetadata.ttl` and `didDocumentMetadata.witness.threshold`
        as strings in `resolveDID` output
  - [ ] `--witness-threshold` still sends a JSON integer to `createDID`
  - [ ] Stored fixture logs and test logs resolve under the stricter parameter
        check

discovered-from: a port of three upstream `didwebvh-ts` changes into the
library. Wait for the library to be published to npm before starting.

The release changes four behaviors:

- `deactivateDID` writes `updateKeys: []` and throws while pre-rotation is
  active. The caller must first call `updateDID` with `nextKeyHashes: []`.
- Resolution rejects a log entry with a parameter that did:webvh 1.0 does not
  define, including the legacy `witnesses`/`witnessThreshold` pair.
- A witness `threshold` must be a JSON integer. A string such as `"2"` is
  rejected in a log and in `createDID`/`updateDID` input.
- `ttl` is a string in resolution metadata, and `witness.threshold` is a
  string in the `resolveDID` result. `DEFAULT_TTL_SECONDS` is `'3600'`.

A first look found little exposure. The CLI has no deactivate command, reads
neither `ttl` nor `witness.threshold` from metadata, and `create` already
parses `--witness-threshold` to an integer. A future `did webvh deactivate`
command must stop pre-rotation with its own log entry before it deactivates.

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
