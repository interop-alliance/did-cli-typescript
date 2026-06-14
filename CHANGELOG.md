# History

## Unreleased - TBD

### Added

- Add an `edv` command group with `encrypt` and `decrypt` subcommands
  (Layer 1: raw JWE). `edv encrypt [file]` encrypts stdin or a file to one or
  more X25519 recipients and emits a single flattened JWE (the `jwe` field of
  an EDV Document) to stdout or an `-o` file (convention `*.jwe.json`);
  `edv decrypt [file]` reverses it. Encryption is public-key (key-agreement)
  only, via `@interop/minimal-cipher` with its default algorithm
  (`ECDH-ES+A256KW` key wrap, `XC20P` content encryption). A recipient
  (`-r/--recipient`, repeatable) is a raw X25519 `publicKeyMultibase`, a wallet
  key fingerprint/handle, or a DID / DID URL (its `keyAgreement` key, typed
  either `X25519KeyAgreementKey2020` or `Multikey`); `--recipient-file` reads a
  key-document JSON. `--json` switches both commands
  to object semantics. On decrypt, the secret key is given with `-k/--key` or
  auto-selected from the wallet by matching a recipient `kid`; a non-recipient
  key exits non-zero with a clear error. The full EDV Document envelope,
  chunked streams, and HMAC-blinded indexing are deferred to Layer 2.
- Add EDV Document support to `edv` (Layer 2, Phase 1). `edv encrypt --document`
  wraps the JWE in a full EDV Document envelope `{ id, sequence, indexed, jwe }`
  (convention `*.edvdoc.json`), encrypting the input as the document `content`
  with an optional `--meta <json>` object alongside it (both encrypted inside the
  `jwe`); `id` is a fresh identity-multihash multibase value and `sequence`
  starts at `0`, byte-faithful to `@interop/edv-client`'s `EdvClientCore` without
  taking that dependency. `--update <file>` versions an existing document
  (reusing its `id`, incrementing `sequence`, and merging its recipients).
  `edv decrypt` detects an envelope automatically and emits its decrypted
  `content` (reporting `meta`/`stream` on stderr); `--document` requires one.
  Chunked streams and HMAC-blinded indexing remain deferred to later phases.
- Add chunked-stream support to `edv` (Layer 2, Phase 2). `edv encrypt --stream`
  encrypts the input as a sequence of fixed-size chunks (`--chunk-size <bytes>`,
  default 1 MiB) and writes a bundle directory (convention `*.edvdoc/`, so `-o`
  is required): a `document.json` EDV Document carrying a cleartext
  `stream: { sequence, chunks }` descriptor, plus one `chunks/<index>.jwe.json`
  per chunk (`{ sequence, index, offset, jwe }`), mirroring how an EDV / WAS
  server stores stream bytes separately from the document. `--meta` and
  `--update` (a file or bundle) work as for `--document`. `edv decrypt`
  recognizes a bundle directory, reassembles the chunks in order, and writes the
  original bytes to `-o`/stdout (reporting `content`/`meta`/`stream` on stderr).
  HMAC-blinded indexing remains deferred to Layer 2, Phase 3.
- Add HMAC-blinded indexing to `edv` (Layer 2, Phase 3). In
  `--document`/`--stream` mode, `--index <attribute>` (repeatable; a dotted path
  into `content`/`meta`) populates the envelope's `indexed` array with entries
  whose attribute names and values are HMAC-blinded, so a document is searchable
  the way an EDV / WAS server indexes it without the server learning the
  cleartext. `--unique` marks every `--index` attribute unique; `--hmac <ref>`
  selects the blinding key (auto-selected when the wallet holds exactly one). The
  same key over the same value yields a stable blinded entry, matchable across
  documents. The EDV Document envelope and its blinded `indexed` array are now
  assembled and unwrapped by `@interop/edv-client`'s `EdvClientCore` (a new
  dependency), converging on the reference implementation rather than the
  hand-rolled envelope used in Phases 1-2.
- Add `key create --type hmac`, generating a `Sha256HmacKey2019` HMAC key (a
  32-byte symmetric secret used to blind EDV index attributes) via
  `@interop/data-integrity-core`'s `SHA256HMACKey`. The key has no public half;
  it is serialized with its secret as an `oct` JWK and identified by a random
  `urn:uuid:` id. HMAC keys list with an `hmac` type label, and `key show`
  prints only their `id`/`type` (never the secret). Like ecdsa/x25519, HMAC
  generation is non-deterministic, so `--with-seed` / `SECRET_KEY_SEED` are not
  supported.

## 0.8.0 - 2026-06-13

### Added

- Add `key create --type x25519` support, generating an
  `X25519KeyAgreementKey2020` (Curve25519 Diffie-Hellman) key pair via
  `@interop/x25519-key-agreement-key`. Saved x25519 keys list with an `x25519`
  type label and `key show` re-exports the public key only. Like ecdsa, x25519
  generation is non-deterministic, so `--with-seed` / `SECRET_KEY_SEED` are not
  supported.
- Add `did add-key --type x25519` support for `did:web`, adding an
  `X25519KeyAgreementKey2020` to the DID document. Because x25519 keys are key
  agreement (encryption) keys, they are wired into the `keyAgreement`
  verification relationship only; a `--purpose` other than `keyAgreement` is
  rejected, and (as with ecdsa) `--with-seed` is not supported.
- Add `was resource-meta get` and `was resource-meta put` (group alias
  `meta`), surfacing the Resource Metadata endpoint (`GET`/`PUT .../meta`).
  `get` prints the whole metadata object (server-managed `contentType`,
  `size`, and timestamps plus the user-writable `custom` name/tags); a
  missing/not-visible resource is reported as not-found. `put` updates
  `custom`: `--name` and `--tag key=value` (repeatable) are non-destructive on
  their own (they preserve the other field via the client's `setName` /
  `setTags`), while passing both, or the `--json` escape hatch (inline JSON or
  a file path), is a full `custom` replacement. Both verbs also accept
  `--capability` targeting the resource.
- Add `was collection backend` and `was collection quota`, surfacing the
  `GET /space/:spaceId/:collectionId/backend` and
  `GET /space/:spaceId/:collectionId/quota` endpoints (the storage backend a
  collection is stored on, and the collection's storage usage scoped to that
  backend). Both render a table by default and take `--json` for the raw
  response; a missing/not-visible collection is reported as not-found, and a
  server (or backend) that does not implement the endpoint (a 501) as an error.
- Add `was space backends` and `was space quotas`, surfacing the
  `GET /space/:spaceId/backends` and `GET /space/:spaceId/quotas` endpoints
  (the storage backends available within a space, and the space's storage
  report grouped by backend). Both render a table by default and take `--json`
  for the raw response; a server that does not implement the endpoint (a 501)
  is reported as an error.
- Add `ARCHITECTURE.md`, a codebase map (entry point, command-factory pattern,
  module layout, and the command surface) for contributors, linked from
  `CLAUDE.md` and the README.
- Add `CONTRIBUTING.md` as the canonical home for code-style and contribution
  conventions (moved out of `CLAUDE.md`, which now imports it).
- Add `AGENTS.md` (an inline copy of `CONTRIBUTING.md`) so non-Claude coding
  agents pick up the same project guidance.
- Add an Environment Variables table to the README consolidating `WALLET_DIR`,
  `DIDS_DIR`, `SECRET_KEY_SEED`, `WAS_DID`, `WAS_SERVER_URL`, and
  `ZCAP_CONTROLLER_KEY_SEED`.

### Changed

- `zcap delegate --capability` now also accepts the id or metadata handle of
  a zcap saved in local wallet storage, in addition to a multibase string or
  a JSON file path (the same resolution the `was` commands' `--capability`
  flag uses; the shared resolver lives in `src/zcap/resolve.ts`).
- Split the `was` command module into `src/commands/was/` submodules (by noun:
  `space`, `collection`, `resource`, `tree`, `policy`, `publish`, plus shared
  helpers); `src/commands/was.ts` now holds only `makeWasCommand()`. Internal
  refactor with no behavior change.
- Rename the `was resource list` positional from `<path>` to `<collection>`,
  matching the sibling `was collection list <space>` and clarifying that the
  argument is the parent collection being enumerated.

## 0.7.0-0.7.1 - 2026-06-11

### Changed

- **BREAKING**: Move the default wallet storage directory from `~/.wallet/` to
  `~/.config/did-cli-wallet/` (honoring `$XDG_CONFIG_HOME` when set), to avoid
  colliding with other tools that use the generic `~/.wallet` name. Existing
  data can be moved with `mv ~/.wallet ~/.config/did-cli-wallet`. The
  `WALLET_DIR` and `DIDS_DIR` environment variables still override the default
  as before.
- `di --version` now reports the version from `package.json` instead of a
  hardcoded string.
- Relax the `engines` requirement from Node `>=24` to `>=22` (the oldest
  currently supported LTS line).

## 0.6.0 - 2026-06-11

### Added

- Add a `was` command group: a CLI for Wallet Attached Storage (WAS) servers
  via `@interop/was-client`, signing every request with a locally stored
  `did:key` DID (Ed25519 keys only for now). Commands take a single positional
  WAS path -- `SPACE[/COLLECTION[/RESOURCE]]` -- where the space part is a
  local registry handle, a bare space id, or a full space https URL.
  - Add `was space create/list/show/update/delete/forget/add` subcommands
    (`update` aliases `configure`; `delete` aliases `rm`; `show` aliases
    `view`/`cat`). `create --save` and `add` register the space in a local
    space registry (`~/.wallet/was-spaces/`, with the usual `.meta.json`
    handle/description sidecars); `space list` reads the registry (servers do
    not implement List Spaces yet; `--remote` asks the server anyway), and
    `forget` removes only the registry entry while `delete` deletes the space
    on the server.
  - Add `was collection create/list/show/update/delete` subcommands (group
    alias `coll`; `update` aliases `configure`, `delete` aliases `rm`) and
    `was resource add/put/get/list/delete` subcommands (group alias `res`,
    same `delete` alias). Resource payloads come from a file argument or
    stdin: `*.json` files (and content that parses to a JSON object/array)
    are sent as JSON, anything else as binary `application/octet-stream`,
    and an explicit `--content-type` sends the bytes as-is with that type.
    `resource get` pretty-prints JSON to stdout and writes binary raw
    (`--output <file>` to save either to a file).
  - Add top-level shorthand verbs that dispatch on the path depth:
    `was ls <path>` (collections of a space, or resources of a collection),
    `was get` / `was put` (resource shorthands), and `was rm <path>`
    (uniform delete of whatever the path points at).
  - Add `was grant <path> --to <did> --action <verb...>` to delegate access
    to a space, collection, or resource. Actions are HTTP verbs (lowercase
    accepted); expiration via `--ttl` (default `1y`) or an explicit
    `--expires`. Prints `{ delegatedCapability, encoded }` (the same shape
    as `zcap delegate`); `--save` (with `--handle` / `--description`)
    stores the capability in the existing zcap store (`~/.wallet/zcaps/`).
  - Add `--capability <ref>` to `was ls`/`get`/`put`/`rm` and
    `was resource add/get/put` for the receiving side of delegation: the
    ref is a multibase-encoded capability string, a capability JSON file,
    or the id/handle of a stored zcap. The capability's invocation target
    supplies the server URL and the operation depth (no path argument
    needed), and the signing DID falls back from `--did` / `WAS_DID` to the
    capability's controller (the delegatee).
  - Add `was policy show/set/clear` to manage access-control policies at
    space, collection, or resource depth (`set` takes `--type <type>` for a
    simple type-only policy, or a policy JSON file), plus the
    `was publish <path>` / `was unpublish <path>` sugar: `publish` makes
    the path world-readable (`PublicCanRead`) and prints its public URL;
    `unpublish` reverts it to capability-only access.
  - Add `was space export <space> [--output <file.tar>]` (tar to a file or
    raw to stdout) and `was space import <space> [file.tar]` (tar from a
    file or stdin; prints the import stats summary).
  - Add an env-gated end-to-end integration test of the whole `was` flow
    (space/collection/resource round-trip, delegation, capability read,
    publish + unauthenticated fetch); it is skipped unless
    `WAS_TEST_SERVER_URL` points at a running WAS server.
  - Registered spaces supply the server URL and signing controller DID
    defaults; otherwise they resolve from `--server` / `WAS_SERVER_URL` and
    `--did` / `WAS_DID` (or the origin of a full space URL address).
  - Exit codes: `0` success, `1` operation error (typed WAS errors,
    not-found/not-visible reads), `2` input error (bad path syntax, unknown
    handle/DID, missing server URL).
- Bring `zcap` storage features in line with the `key` and `did` commands:
  - Add metadata support for locally stored zcaps, persisted as `.meta.json`
    sidecar files next to the stored capability
    (`~/.wallet/zcaps/<storageId>.meta.json`). `zcap create --save` and
    `zcap delegate --save` now write a sidecar with the `created` timestamp,
    and accept `--handle` / `--description` (exit `1` without `--save`).
  - Add `zcap show <id>` (aliases: `view`, `cat`) to print a stored capability
    by capability id or metadata handle, with `--meta` to display its metadata
    (plus controller, invocation target, and expiration) as a field/value
    table, or as JSON with `--meta --json`.
  - Add `zcap meta <id>` to show or edit the metadata of a stored zcap (no
    options prints the current metadata; an empty string value clears a field;
    metadata edits never rewrite the stored capability file).
  - Add `zcap remove <id>` (aliases: `delete`, `rm`) to remove a stored zcap
    and its metadata sidecar. Note that removal does not revoke a delegated
    capability that has already been handed out.
  - `zcap show`, `zcap meta`, and `zcap remove` accept a metadata handle in
    place of a capability id (exit `1` when the handle is ambiguous).
- Add local wallet storage for Verifiable Credentials
  (`~/.wallet/credentials/`, with the usual `.meta.json` handle/description
  sidecars), mirroring the zcap storage features:
  - Add a `vc import` command that stores an existing credential, read from a
    file argument, an http(s) URL, or stdin. The input's `type` must include
    `VerifiableCredential`; it is stored as-is (not verified on import). The
    file is named after the credential's `id`; an id-less credential is
    stored under a digest of its content, so re-importing it overwrites
    rather than duplicates. Exit codes: `0` imported, `1` not a credential,
    `2` fetch/read/parse error.
  - Add `--save` to `vc issue` to store the freshly issued credential;
    `--handle` / `--description` tag it (exit `1` without `--save`).
  - Add `vc list` (`--json` / `--plain`) to render a metadata table of the
    stored credentials (`HANDLE | TYPE | ISSUER | CREATED | ID |
    DESCRIPTION`), `vc show <id>` (aliases: `view`, `cat`; `--meta` for the
    metadata, `--meta --json` for it as JSON), `vc meta <id>` to edit the
    metadata sidecar, and `vc remove <id>` (aliases: `delete`, `rm`). All
    accept a credential id, a storage id (for id-less credentials), or a
    metadata handle.
  - `vc verify` and `vc issue` also accept an http(s) URL as the credential
    source now, in addition to a file argument or stdin.

### Changed

- **BREAKING**: Saved DIDs now live under the wallet directory:
  `~/.wallet/dids/<method>/` instead of `~/.dids/<method>/`. Existing data can
  be moved with `mv ~/.dids ~/.wallet/dids`. The `DIDS_DIR` environment
  variable still overrides the DIDs location when set; its default is now
  derived from `WALLET_DIR` (`$WALLET_DIR/dids`).
- **BREAKING**: `zcap list` now prints a metadata table by default
  (`HANDLE | TYPE | CREATED | ID | DESCRIPTION`, where TYPE is `root` or
  `delegated`), matching `did list`. Pass the new `--plain` flag for the
  previous one-id-per-line output.
- **BREAKING**: `zcap list --json` now outputs an array of objects with
  metadata (`{id, type, created?, handle?, description?}`) instead of an
  array of plain id strings.

## 0.5.0 - 2026-06-11

### Added

- Add `key remove <id>` and `did remove <did>` commands (aliases: `delete`,
  `rm`) to remove a locally stored key or DID from wallet storage, looked up
  by fingerprint/DID or by metadata handle. `key remove` deletes the key file
  and its `.meta.json` metadata sidecar; `did remove` deletes the DID
  document, its `.keys.json` key file, and its `.meta.json` metadata sidecar,
  and also scrubs the removed DID from the cached `dids` associations of any
  matching wallet keys (the inverse of the caching done by
  `did create --save` and `did add-key`).
- Add metadata support for locally stored keys and DIDs, persisted as
  `.meta.json` sidecar files next to the stored item (`~/.wallet/keys/
  <storageId>.meta.json` and `~/.dids/<method>/<did>.meta.json`, following the
  existing `.keys.json` sidecar pattern). Metadata fields: `created` (ISO 8601
  timestamp written at `--save` time), `handle` (a short user-defined tag),
  `description` (longer free text), and -- for keys -- `dids`, a cache of the
  stored DIDs whose documents reference the key. Stored key files and DID
  documents remain spec-pure Multikey / DID document JSON; a missing sidecar
  means "no metadata" (no migration needed) and orphaned sidecars are ignored.
- Add `--handle` / `--description` options to `key create --save` and
  `did create --save` (exit `1` without `--save`), and new `key meta <id>` /
  `did meta <did>` commands to show or edit metadata after the fact (no
  options prints the current metadata; an empty string value clears a field;
  metadata edits never rewrite the stored key/DID file). `key meta` backfills
  `created` from the storage file name's date prefix for keys saved before
  metadata support.
- `key show`, `key meta`, `did show`, and `did meta` now also accept a
  metadata handle in place of a fingerprint/DID (exit `1` when the handle is
  ambiguous -- handles are not required to be unique).
- Add `--meta` to `key show` and `did show` to display the item's metadata as
  a vertical field/value table (or as JSON with `--meta --json`). The DIDs
  shown for a key are always derived by scanning the locally stored DID
  documents for the key's `publicKeyMultibase`, so they cannot go stale; the
  cached `dids` list is refreshed by `did create --save`, `did add-key`, and
  every `key meta` write.
- Add `did show <did>` and `key show <id>` commands to display a locally stored
  DID document or key (aliases: `view`, `cat`). `did show` prints the stored DID
  document (which holds no secret material). `key show` looks up a stored key by
  its `publicKeyMultibase` fingerprint and prints the public key object only --
  it re-imports the stored key pair and re-exports the public half, so the secret
  key never appears in the output. These are distinct from a future `get`
  command, which will resolve DIDs/keys rather than read local storage.

### Changed

- **BREAKING**: `key list` and `did list` now print a metadata table by
  default (`HANDLE | TYPE | CREATED | FINGERPRINT | DIDS | DESCRIPTION` for
  keys; `HANDLE | METHOD | CREATED | DID | DESCRIPTION` for DIDs), ordered by
  storage file name (chronological for keys) instead of by fingerprint. Pass
  the new `--plain` flag for the previous one-item-per-line output.
- **BREAKING**: `key list --json` and `did list --json` now output an array of
  objects with metadata (`{fingerprint, storageId, type, curve?, created?,
  handle?, description?, dids}` for keys; `{did, method, created?, handle?,
  description?}` for DIDs) instead of an array of plain strings.

## 0.4.0 - 2026-06-09

### Added

- Add ECDSA key support via `@interop/ecdsa-multikey`, selected with
  `--type ecdsa`, to `key create`, `did create key`, `did create web`, and
  `did add-key`. The curve is chosen with `--curve` (defaults to `p256`;
  supported: `p256`, `p384`, `p521`, each also accepted in hyphenated `p-256`
  and SECG `secp256r1` spellings, case-insensitively). Keys are serialized as
  Multikey, the same as Ed25519. ECDSA key generation is non-deterministic, so
  `--with-seed` / `SECRET_KEY_SEED` are rejected (exit `1`) with `--type ecdsa`.
  ECDSA `did:key`s are minted via the driver's `fromKeyPair()` (no suite
  registration required).
- Support issuing Verifiable Credentials with ECDSA keys in `vc issue`. The
  signing key's type is detected from its `publicKeyMultibase` header, and ECDSA
  keys sign with the `ecdsa-rdfc-2019` cryptosuite (via `@interop/ecdsa-signature`).
  `--suite` now defaults per key type (`eddsa-rdfc-2022` for ed25519,
  `ecdsa-rdfc-2019` for ecdsa) instead of always defaulting to `eddsa-rdfc-2022`.
- Warn at key creation time (`key create`, `did create key`, `did create web`,
  `did add-key`) when a `p521` ECDSA key is generated: P-521 keys can be created
  but cannot issue Verifiable Credentials, because the `ecdsa-rdfc-2019`
  cryptosuite supports P-256 and P-384 only.
- `vc verify` now verifies ECDSA (`ecdsa-rdfc-2019`) credentials, completing the
  ECDSA issue/verify round trip. This required upstream support in
  `@interop/verifier-core` `^3.2.0` (ECDSA `did:key` resolution and the
  `ecdsa-rdfc-2019` suite in its defaults), so the previous CLI-side crypto-suite
  injection was removed in favor of verifier-core's defaults.

### Changed

- Update to the `@interop/data-integrity-core` `^7.0.0` chain, in which
  `AbstractKeyPair.export()` is now `async`: `@interop/data-integrity-core`
  `^7.0.0`, `@interop/data-integrity-proof` `^3.3.0`, `@interop/did-method-key`
  `^7.3.1`, `@interop/did-web-resolver` `^6.2.1`, `@interop/ecdsa-multikey`
  `^2.3.0`, and `@interop/ed25519-verification-key` `^8.0.0`. All
  `keyPair.export(...)` call sites now `await` the result.

## 0.3.0 - 2026-06-09

### Added

- Add `did:web` support to `did create` (`./di did create web --url <url>`):
  generates a `did:web` DID with a single Ed25519 verification key (wired into
  `authentication`, `assertionMethod`, `capabilityDelegation`, and
  `capabilityInvocation`) via `@interop/did-web-resolver`'s `driver().generate()`.
  `--url` is required (a `did:web` DID is tied to a domain). The key is derived
  from a seed exactly as `did:key` is (`SECRET_KEY_SEED` env var or `--with-seed`).
  `--save` writes the DID document and key material to `~/.dids/web/`, with the
  key file stored as an object keyed by verification method id so additional keys
  can be appended later.
- Add `did add-key <did>` command: adds a new verification key to an existing,
  locally stored `did:web` DID via `@interop/did-web-resolver`'s
  `addVerificationMethod()`, updating both the stored DID document and its
  key file (keyed by verification method id) in place. The key is derived from a
  seed (`SECRET_KEY_SEED` env var or `--with-seed`). `--purpose <purpose...>`
  selects the verification relationships to wire the key into (defaults to
  `authentication`, `assertionMethod`, `capabilityDelegation`, and
  `capabilityInvocation`). Only `did:web` DIDs are supported; exits `1`
  on an unknown DID, a non-`did:web` DID, or an unsupported purpose.

### Fixed

- `vc issue --did <did:web:...>` now works. Issuance read the `<did>.keys.json`
  file as a single exported key pair (the `did:key` shape), but `did:web` stores
  keys as a map keyed by verification method id, so the secret-key lookup always
  failed with "No stored secret key found". The issuer now resolves the signing
  key from either storage shape.

## 0.2.0 - 2026-06-08

### Changed

- **BREAKING**: Rename the CLI binary from `did` to `di` (bin script and `package.json`
  `bin` entry), so commands now read `./di key create`, `./di vc verify`, etc.
- **BREAKING**: Rename the `id` command group to `did`, so DID commands now read
  `./di did create` and `./di did list`.
- Bump `@interop/verifier-core` to `^3.1.0`, which reports an explicit
  `ISSUER_PROOF_MISMATCH` problem (title `Issuer / Proof Mismatch`) when a
  credential's `issuer` does not match the controller of its proof's
  verification method, instead of a generic `INVALID_SIGNATURE`.

### Added

- Implement `zcap create` command: builds an unsigned root Authorization
  Capability (zcap) for an invocation target via `@interop/zcap`'s
  `createRootCapability`, printing `{ rootCapability, encoded }` to stdout (the
  `encoded` field is the capability JSON as a multibase base58btc string). Takes
  a required `--controller` (the controller DID) and `--url` (the
  `invocationTarget`); `--save` writes the capability to local wallet storage
  (`~/.wallet/zcaps/`). Exits `0` / `1` for success / error.
- Implement `zcap delegate` command: signs a delegated capability via
  `@interop/ezcap`'s `ZcapClient`, printing `{ delegatedCapability, encoded }`
  to stdout. Supports a first-level delegation from the root capability for a
  `--url`, or a further (attenuated) delegation of an existing `--capability`
  (a multibase string or a JSON file path), narrowed with `--invocation-target`.
  Takes a required `--delegatee` (the delegated capability's controller),
  optional `--allow <action...>` (defaults to inheriting the parent's actions),
  and either `--ttl` (duration, default `1y`) or an `--expires` ISO 8601
  override. The signing key is sourced from a stored DID (`--did`) or, as a
  fallback, the `ZCAP_CONTROLLER_KEY_SEED` env var together with `--controller`
  (the seed-derived `did:key` is verified against `--controller`). `--save`
  writes the capability to `~/.wallet/zcaps/`. Exits `0` / `1` for success /
  error.
- Implement `vc issue` command: reads an unsigned Verifiable Credential as JSON
  from a file or stdin and issues (signs) it with a locally-stored DID via
  `@interop/vc`, printing the issued credential to stdout (appending a proof if
  one already exists). The credential's `issuer` is set to the signing DID when
  absent, and must match the signing DID when present (otherwise issuance is
  aborted). Takes a required `--did`, an optional `--key` (a verification method
  id, validated against the DID's `assertionMethod` array; defaults to the first
  `assertionMethod` key), and an optional `--suite` (`eddsa-rdfc-2022` by
  default, or `Ed25519Signature2020`). Exits `0` / `1` / `2` for issued /
  issuance error / read error. Adds `loadDidDocument()` and `loadDidKeys()`
  storage helpers.
- Implement `key list` command: prints the fingerprints (multibase-encoded
  public keys) of key pairs saved in local wallet storage (one per line to
  stdout, nothing if empty), or as a JSON array with `--json`. Adds
  `listCollection()` and `loadFromCollection()` storage helpers.
- Implement `id list` command: prints the DIDs saved in local storage across all
  method subdirectories (one per line to stdout, nothing if empty), or as a JSON
  array with `--json`. Adds a `listDids()` storage helper.
- Implement `zcap list` command: prints the ids (the `urn:zcap:...` values) of
  capabilities saved in local wallet storage (`~/.wallet/zcaps/`), one per line
  to stdout (nothing if empty), or as a JSON array with `--json`. Reuses the
  `listCollection()` and `loadFromCollection()` storage helpers.
- Add `vc verify` command: reads a Verifiable Credential as JSON from a file or
  stdin and runs full verification via `@interop/verifier-core` plus
  `@digitalcredentials/issuer-registry-client` (cryptographic signature,
  expiration, revocation / status, and issuer registry recognition). Prints the
  full verifier-core result by default, or a compact object with `--summary`,
  and exits `0` / `1` / `2` for verified / not-verified / read error.

## 0.1.0 - 2026-06-01

### Changed

- Update to latest refactored `@interop/*` deps (`did-method-key@7.1.0`,
  `ed25519-verification-key@7.0.1`, which pull in `did-io@4.0.1` and
  `data-integrity-core@6.1.0`).

### Removed

- Remove unused `@digitalcredentials/ssi` dependency (no longer imported; the
  `@interop/*` forks now use `@interop/data-integrity-core` instead).

## 0.0.1 -

### Added

- Initial commits
