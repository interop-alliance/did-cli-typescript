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
