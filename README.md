# DID CLI wallet _(@interop/did-cli)_

> A command line client for managing DIDs, VCs, zCaps, and corresponding cryptographic key pairs, written in Typescript.

## Table of Contents

- [Background](#background)
- [Install](#install)
- [Usage](#usage)
- [Contribute](#contribute)
- [License](#license)

## Background

## Install

## Usage

Help is available with the `--help/-h` command line option:

```
./did -h
./did COMMAND -h
```

### Key Management

#### Create a key pair

Generate a random Ed25519 key pair (ed25519 is the default type):

```
./did key create
```

If you'd like to also generate a secret key seed (to help deterministically
generate the same key pair in the future), pass in the `--with-seed` flag:

```
./did key create --with-seed
{
  "secretKeySeed": "z1AXVyT6G1Qk3E9cMPkDYY6wVRpZjVGWAZ3TfrAgFZkX6bv",
  "keyPair": {
    "@context": "https://w3id.org/security/multikey/v1",
    "type": "Multikey",
    "publicKeyMultibase": "z6MkrLBubwzwEvwmsyEKd2kJ6pt91E6MHdf3EeQMnCsdX2hM",
    "secretKeyMultibase": "zruzykbtvWUgV8Tp1LKVEuTmywLEa75qHsvWRVarVhdgHiCgiMYTSDXTavJVh47Cwes4mKgdAY5PTizbRvHXcA7XcLF"
  }
}
```

Generate a deterministic key pair by setting the `SECRET_KEY_SEED` environment
variable to a multibase-encoded seed (e.g. from `@digitalcredentials/bnid`):

```
SECRET_KEY_SEED=z1AXVyT6G1Qk3E9cMPkDYY6wVRpZjVGWAZ3TfrAgFZkX6bv ./did key create
{
  "@context": "https://w3id.org/security/multikey/v1",
  "type": "Multikey",
  "publicKeyMultibase": "z6MkrLBubwzwEvwmsyEKd2kJ6pt91E6MHdf3EeQMnCsdX2hM",
  "secretKeyMultibase": "zruzykbtvWUgV8Tp1LKVEuTmywLEa75qHsvWRVarVhdgHiCgiMYTSDXTavJVh47Cwes4mKgdAY5PTizbRvHXcA7XcLF"
}
```

Specify an explicit key type with `--type` (defaults to `ed25519`):

```
SECRET_KEY_SEED=z1Aaj5A4UCsd... ./did key create --type ed25519
```

Output is a JSON-LD Multikey document with both the public and secret key in
multibase encoding:

```json
{
  "@context": "https://w3id.org/security/multikey/v1",
  "type": "Multikey",
  "publicKeyMultibase": "z6Mk...",
  "secretKeyMultibase": "zrv..."
}
```

#### List key pairs

List the fingerprints (multibase-encoded public keys) of the key pairs saved in
local wallet storage (via `key create --save`), one per line:

```
./did key list
z6Mkr...
z6Mks...
```

If no keys are stored, nothing is printed. Pass `--json` to output the
fingerprints as a JSON array instead:

```
./did key list --json
[
  "z6Mkr...",
  "z6Mks..."
]
```

### DID Management

#### Create a DID

Generate a random Ed25519 `did:key` DID (method defaults to `key`):

```
./did id create
{
  "id": "did:key:z6Mkr...",
  "didDocument": { ... }
}
```

Or pass the method explicitly:

```
./did id create key
```

To also include the secret key seed in the output (useful for re-deriving the
same DID later), pass `--with-seed`:

```
./did id create --with-seed
{
  "id": "did:key:z6MkrLBubwzwEvwmsyEKd2kJ6pt91E6MHdf3EeQMnCsdX2hM",
  "secretKeySeed": "z1AXVyT6G1Qk3E9cMPkDYY6wVRpZjVGWAZ3TfrAgFZkX6bv",
  "didDocument": {
    "@context": [ ... ],
    "id": "did:key:z6MkrLBubwzwEvwmsyEKd2kJ6pt91E6MHdf3EeQMnCsdX2hM",
    "verificationMethod": [ ... ],
    ...
  }
}
```

Generate a deterministic DID by setting the `SECRET_KEY_SEED` environment
variable to a multibase-encoded seed (e.g. from `@digitalcredentials/bnid`):

```
SECRET_KEY_SEED=z1AXVyT6G1Qk3E9cMPkDYY6wVRpZjVGWAZ3TfrAgFZkX6bv ./did id create
```

Save the DID document and key material to local storage with `--save`
(written to `~/.dids/` by default, or `$DIDS_DIR` if set):

```
./did id create --save
DID saved to /home/user/.dids/key/did:key:z6Mkr....json
{
  "id": "did:key:z6Mkr...",
  "didDocument": { ... }
}
```

#### List DIDs

List the DIDs saved in local storage (via `id create --save`), one per line:

```
./did id list
did:key:z6Mkr...
did:key:z6Mks...
```

If no DIDs are stored, nothing is printed. Pass `--json` to output the DIDs as
a JSON array instead:

```
./did id list --json
[
  "did:key:z6Mkr...",
  "did:key:z6Mks..."
]
```

### Verifiable Credentials

#### Verify a credential

Run full verification on a Verifiable Credential (JSON). Beyond the
cryptographic signature check, this also verifies expiration, revocation /
status, and whether the issuer DID is recognized in any trusted registry
(via `@interop/verifier-core` and `@digitalcredentials/issuer-registry-client`).

The credential is read from a file argument or, if none is given, from stdin:

```
./did vc verify credential.json
cat credential.json | ./did vc verify
```

By default it prints the full `@interop/verifier-core` verification result
(top-level `verified`, a per-suite `summary`, and the flat `results` of every
check). Pass `--summary` for a compact, human-friendly object instead:

```
./did vc verify credential.json --summary
{
  "verified": true,
  "checks": {
    "signature": true,
    "revoked": false,
    "issuerRecognized": true
  },
  "matchingIssuers": [ ... ]
}
```

A check is omitted from `checks` when it was skipped (for example `expired` is
absent when the credential has no expiration date).

The exit code is scriptable: `0` when the credential verified, `1` when it did
not, and `2` on a read/parse error or a structurally malformed credential.

The trusted registry list is fetched from the DCC
[known-did-registries](https://digitalcredentials.github.io/dcc-known-registries/known-did-registries.json)
at runtime, falling back to a bundled list of DCC registries when the network
is unavailable.

#### Issue a credential

Issue (sign) an unsigned Verifiable Credential with a locally-stored DID, acting
as a command-line wallet and issuer. The credential is read from a file argument
or, if none is given, from stdin, and the issued credential is printed to
stdout. If the input already carries a proof, issuing appends an additional one.

The DID to issue with is required (`--did`); it must have been saved locally (see
`did id create --save`):

```
./did vc issue credential.json --did did:key:z6Mk...
cat credential.json | ./did vc issue --did did:key:z6Mk...
```

The credential's `issuer` is set to the signing DID when the input has none.
When the input already names an `issuer`, it must match the signing DID,
otherwise issuance is aborted -- a credential cannot be issued by a DID other
than the one named as its issuer.

By default the first key in the DID's `assertionMethod` relationship is used.
Pass `--key` to choose a specific verification method; it must be authorized by
the DID's `assertionMethod` array, otherwise issuance fails:

```
./did vc issue credential.json --did did:key:z6Mk... --key did:key:z6Mk...#z6Mk...
```

The signature suite defaults to `eddsa-rdfc-2022` (a W3C Data Integrity proof).
Pass `--suite Ed25519Signature2020` for the classic Ed25519Signature2020 proof:

```
./did vc issue credential.json --did did:key:z6Mk... --suite Ed25519Signature2020
```

The exit code is scriptable: `0` when the credential was issued, `1` on an
issuance error (an unauthorized key, an unknown suite, a missing DID / key
file, or an issuer that does not match the signing DID), and `2` on a
read/parse error.

## Contribute

PRs accepted.

If editing the Readme, please conform to the
[standard-readme](https://github.com/RichardLitt/standard-readme) specification.

## License

[MIT](LICENSE.md) © 2026 Interop Alliance
