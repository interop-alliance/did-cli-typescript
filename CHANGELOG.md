# History

## 0.1.0 - TBD

### Added

- Implement `key list` command: prints the fingerprints (multibase-encoded
  public keys) of key pairs saved in local wallet storage (one per line to
  stdout, nothing if empty), or as a JSON array with `--json`. Adds
  `listCollection()` and `loadFromCollection()` storage helpers.
- Add `vc verify` command: reads a Verifiable Credential as JSON from a file or
  stdin and runs full verification via `@interop/verifier-core` plus
  `@digitalcredentials/issuer-registry-client` (cryptographic signature,
  expiration, revocation / status, and issuer registry recognition). Prints the
  full verifier-core result by default, or a compact object with `--summary`,
  and exits `0` / `1` / `2` for verified / not-verified / read error.

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
