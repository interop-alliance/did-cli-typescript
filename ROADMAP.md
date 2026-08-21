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

- status: todo
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
    needs), CLI-14 (the QR dependency), CLI-8 (key file modes)
- acceptance:
  - [ ] `di was request-grant` builds a zcap-only VPR (no
        `DIDAuthentication`, no `domain`) with one
        `AuthorizationCapabilityQuery` entry: a
        `https://w3id.org/byoe#public-collection` descriptor named by
        `--collection` (default `web`), `--action` (default `GET HEAD PUT
        POST`), `--reason`, and `controller` set to the agent's did:key
  - [ ] The key is minted inside the command, not passed in. `--save
        --handle <name>` persists the key and the received zcaps under one
        handle, and is required for the demo path: `di was put
        --capability` resolves its signer out of the local key store, so a
        key held only for the run cannot sign the write that follows.
        Either default `--save` on, or perform the first write in-process.
        The agent's context never sees key bytes; stdout carries the
        handle, the interaction URL, the deep link, and the result
  - [ ] POSTs the VPR to the server's exchange facet (`--server`, or
        derived from `--wallet`'s configured server), prints the
        interaction URL, a wallet deep link when `--wallet <url>` is given,
        and a half-block terminal QR (CLI-14); polls until complete or the
        exchange expires, with a clear timeout message
  - [ ] Parses the response VP (unsigned, zcap-only) and stores or prints
        the zcaps in the `z...` base58btc form `--capability` already
        accepts. The zcaps sit at
        `body.response.verifiablePresentation.zcap`
  - [ ] Uses was-client handles, nothing re-derived locally. The ecosystem
        rule applies: WAS calls go through was-client handles, not raw
        ezcap `read()`/`write()` (those send `action: read/write`, which
        WAS rejects)
  - [ ] The exchange create and poll helpers come from wallet-core rather
        than being hand-rolled, which means adding `@interop/wallet-core`
        as a dependency of this package and consuming the re-homed helpers
        from WC-129. There is no generic zcap-only VPR builder upstream
        today, so either WC-129 supplies one or this command owns it
  - [ ] Command tests with a stubbed exchange; docs in README and
        ARCHITECTURE's command list

Relationship to App Connect: this is the standalone capability-query path,
not App Connect (which needs a CHAPI-attested origin a CLI does not have).
An optional `--name` (the self-declared agent name) lands with freewallet
FW-231 once its VPR member is signed off.

Scope correction from FW-227's 2026-08-21 CLI-lens review: this command is
larger than "a new command plus the existing `put`". The grant that comes
back is collection-scoped, and `di was put --capability` refuses anything
that is not resource depth, so CLI-13 has to land for the demo to complete;
WC-129 lands before or with this item, since it is what this command
consumes.
The deep-link output is also gated: FW-227 section 8 question 1 (the route
path and query parameter) is unsigned-off, so `--wallet <url>` has nothing
to print until it is decided. The interaction URL and the QR are unblocked,
so only part of this item is parallel with FW-228.

### CLI-8: Write key files with mode 0600

- status: todo
- priority: high
- labels: keys, security
- acceptance:
  - [ ] `src/storage.ts` writes `keys/<id>.json` (and any file carrying a
        secret) with mode `0600`; the atomic temp+rename path keeps the mode
  - [ ] Existing files are not migrated (greenfield stance); a one-line
        note in README
  - [ ] A test asserts the mode on a freshly saved key

Today keys are plaintext Multikey docs at the default 0644. Wanted
regardless of the demo; the demo makes it pressing because an agent's
saved key sits on the same machine as the agent.

Scope note from FW-227's 2026-08-21 CLI-lens review: this is a change to
the shared storage layer, not to one command. Nothing in `src/storage.ts`
sets a file mode today -- every write goes through the one
`writeFileAtomic` under the ambient umask -- so the change reaches every
stored DID, key, zcap, and space record. The greenfield stance above is
what settles the already-on-disk question; state it in the README note.

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

### CLI-13: Write at a resource id through a collection-depth capability

- status: todo
- priority: high
- labels: was, zcap, agents
- touches:
  - freewallet -- none; the wallet's grant is correct as issued. The
    mismatch is entirely on this side
- acceptance:
  - [ ] `di was put` accepts a collection-depth `--capability` together
        with a resource id, and writes at that id beneath the capability's
        collection. Either a positional resource id alongside
        `--capability`, or a `--resource <id>` flag; the choice is
        FW-227 section 8 question 9
  - [ ] `assertOneAddressing` stops treating a path plus a `--capability`
        as an error for this case, and `disambiguatePayloadArgs` no longer
        silently reads the single positional as the payload file when a
        capability is present
  - [ ] The other resource verbs (`get`, `meta`) get the same treatment or
        an explicit refusal message naming the supported form
  - [ ] A test PUTs `index.html` under a collection-scoped delegated zcap
        and fetches it back

Discovered by FW-227's 2026-08-21 CLI-lens review, which found the agent
demo's final step unrunnable. A `#public-collection` grant's
`invocationTarget` is a collection URL, but `resolveResourceHandle` refuses
a capability whose depth is not `resource` ("the capability targets a
collection; put needs a resource capability"). `resource add` does accept a
collection capability, but its id is server-generated, so it cannot produce
`index.html`.

Asking the wallet for a resource-scoped grant instead is not an option: a
resource-level target is only expressible as a plain URL under the user's
own Space, and the CLI does not know the Space URL before consent. A
descriptor naming a resource would be a new wire convention needing
sign-off. was-client already supports the right shape --
`Collection.resource(id)` inherits the bound capability and `Resource.put`
takes a content type and upserts -- so this is CLI-side only.

### CLI-14: Terminal QR for `request-grant`

- status: todo
- priority: medium
- labels: agents, ux
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
