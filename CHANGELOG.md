# History

## Unreleased - TBD

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
