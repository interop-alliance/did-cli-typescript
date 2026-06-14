# DID CLI wallet _(@interop/did-cli)_

[![Node.js CI](https://github.com/interop-alliance/did-cli-typescript/workflows/CI/badge.svg)](https://github.com/interop-alliance/did-cli-typescript/actions?query=workflow%3A%22CI%22)
[![NPM Version](https://img.shields.io/npm/v/@interop/did-cli.svg)](https://npm.im/@interop/did-cli)

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
./di -h
./di COMMAND -h
```

### Environment Variables

These environment variables configure storage locations and provide defaults
or secret-key seeds for individual commands. Each is also documented inline in
the relevant command section below.

| Variable | Used by | Purpose |
| --- | --- | --- |
| `WALLET_DIR` | all | Wallet collections directory (`keys/`, `zcaps/`, `credentials/`, `was-spaces/`). Defaults to `~/.config/did-cli-wallet/` (honors `XDG_CONFIG_HOME`). |
| `DIDS_DIR` | `did` | DID-documents directory. Defaults to `<WALLET_DIR>/dids/`. |
| `SECRET_KEY_SEED` | `key create`, `did create` | Multibase-encoded seed for deterministic key/DID generation. Not supported with `--type ecdsa` or `--type x25519`. |
| `WAS_DID` | `was` | Default signing DID (or stored-DID handle) when `--did` is omitted. |
| `WAS_SERVER_URL` | `was` | Default WAS server base URL when `--server` is omitted. |
| `ZCAP_CONTROLLER_KEY_SEED` | `zcap` | Controller signing-key seed for delegating capabilities. |

### Key Management

#### Create a key pair

Generate a random Ed25519 key pair (ed25519 is the default type):

```
./di key create
```

If you'd like to also generate a secret key seed (to help deterministically
generate the same key pair in the future), pass in the `--with-seed` flag:

```
./di key create --with-seed
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
SECRET_KEY_SEED=z1AXVyT6G1Qk3E9cMPkDYY6wVRpZjVGWAZ3TfrAgFZkX6bv ./di key create
{
  "@context": "https://w3id.org/security/multikey/v1",
  "type": "Multikey",
  "publicKeyMultibase": "z6MkrLBubwzwEvwmsyEKd2kJ6pt91E6MHdf3EeQMnCsdX2hM",
  "secretKeyMultibase": "zruzykbtvWUgV8Tp1LKVEuTmywLEa75qHsvWRVarVhdgHiCgiMYTSDXTavJVh47Cwes4mKgdAY5PTizbRvHXcA7XcLF"
}
```

Specify an explicit key type with `--type` (defaults to `ed25519`; supported:
`ed25519`, `ecdsa`, `x25519`):

```
SECRET_KEY_SEED=z1Aaj5A4UCsd... ./di key create --type ed25519
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

Generate an ECDSA key with `--type ecdsa`. The curve is chosen with `--curve`
(defaults to `p256`; supported: `p256`, `p384`, `p521`, each also accepted in
hyphenated `p-256` and SECG `secp256r1` spellings, case-insensitively):

```
./di key create --type ecdsa --curve p384
```

ECDSA keys are serialized as Multikey, the same as Ed25519. Note that ECDSA key
generation is non-deterministic (it cannot be derived from a seed), so
`--with-seed` and `SECRET_KEY_SEED` are not supported with `--type ecdsa`.

Generate an X25519 (Curve25519) key agreement key -- for Diffie-Hellman key
exchange / encryption, not signing -- with `--type x25519`:

```
./di key create --type x25519
```

It is serialized as an `X25519KeyAgreementKey2020` document with the public and
private key in multibase encoding:

```json
{
  "type": "X25519KeyAgreementKey2020",
  "publicKeyMultibase": "z6LS...",
  "privateKeyMultibase": "z3we..."
}
```

Like ECDSA, X25519 key generation is non-deterministic, so `--with-seed` and
`SECRET_KEY_SEED` are not supported with `--type x25519`.

Save the key to local wallet storage (`~/.config/did-cli-wallet/keys/` by default, or
`$WALLET_DIR/keys/` if set) with `--save`. A `.meta.json` metadata sidecar is
written next to the key, recording the creation timestamp; `--handle` (a short
tag for telling keys apart) and `--description` add user-defined metadata to
it (both require `--save`):

```
./di key create --save --handle issuer-signing --description 'Demo issuer signing key'
Key saved to /home/user/.config/did-cli-wallet/keys/2026-06-10-ed25519-z6Mkr....json
```

#### List key pairs

List the key pairs saved in local wallet storage (via `key create --save`) as
a table of their metadata. The DIDS column shows the locally stored DIDs whose
documents reference the key, derived by scanning the saved DID documents:

```
./di key list
HANDLE          TYPE     CREATED     FINGERPRINT                   DIDS                 DESCRIPTION
--------------  -------  ----------  ----------------------------  -------------------  -----------------------
issuer-signing  ed25519  2026-06-10  z6MkrLBubwzwEv...MnCsdX2hM    did:key:z6MkrL...    Demo issuer signing key
```

If no keys are stored, nothing is printed. Pass `--json` to output the list as
a JSON array of objects with metadata:

```
./di key list --json
[
  {
    "fingerprint": "z6Mkr...",
    "storageId": "2026-06-10-ed25519-z6Mkr...",
    "type": "ed25519",
    "created": "2026-06-10T17:22:31.123Z",
    "handle": "issuer-signing",
    "description": "Demo issuer signing key",
    "dids": ["did:key:z6Mkr..."]
  }
]
```

Or pass `--plain` to print just the fingerprints (multibase-encoded public
keys), one per line, sorted:

```
./di key list --plain
z6Mkr...
z6Mks...
```

#### Show a key pair

Display a key saved in local wallet storage, looked up by its fingerprint
(`publicKeyMultibase`, as printed by `key list`) or by its metadata handle.
Only the public key object is shown -- the stored secret key is never included
in the output:

```
./di key show z6Mkr...
{
  "@context": "https://w3id.org/security/multikey/v1",
  "id": "...",
  "type": "Multikey",
  "controller": "...",
  "publicKeyMultibase": "z6Mkr..."
}
```

Aliases: `view`, `cat`.

Pass `--meta` to show the key's metadata instead of the public key object,
including the DIDs the key participates in (derived from the locally stored
DID documents):

```
./di key show issuer-signing --meta
FIELD        VALUE
-----------  ------------------------------------------------
Fingerprint  z6Mkr...
Type         ed25519
Created      2026-06-10T17:22:31.123Z
Handle       issuer-signing
Description  Demo issuer signing key
DIDs         did:key:z6Mkr...
```

`--meta --json` prints the same metadata as a JSON object.

#### Edit key metadata

Show or edit the metadata of a stored key with `key meta` (looked up by
fingerprint or handle). With no options it prints the current metadata; with
`--handle` / `--description` it updates the metadata sidecar (the key file
itself is never rewritten). Passing an empty string clears a field:

```
./di key meta z6Mkr... --handle issuer-signing --description 'Demo issuer signing key'
Metadata saved to /home/user/.config/did-cli-wallet/keys/2026-06-10-ed25519-z6Mkr....meta.json
{
  "created": "2026-06-10T17:22:31.123Z",
  "handle": "issuer-signing",
  "description": "Demo issuer signing key"
}

./di key meta issuer-signing --description ''
```

Keys saved before metadata support get a sidecar created on first edit, with
`created` backfilled from the date prefix of the key's file name.

#### Remove a key pair

Remove a stored key with `key remove` (aliases: `delete`, `rm`), looked up by
fingerprint or handle. Both the key file and its `.meta.json` metadata sidecar
are deleted:

```
./di key remove issuer-signing
Removed /home/user/.config/did-cli-wallet/keys/2026-06-10-ed25519-z6Mkr....json
Removed /home/user/.config/did-cli-wallet/keys/2026-06-10-ed25519-z6Mkr....meta.json
```

### DID Management

#### Create a DID

Generate a random Ed25519 `did:key` DID (method defaults to `key`):

```
./di did create
{
  "id": "did:key:z6Mkr...",
  "didDocument": { ... }
}
```

Or pass the method explicitly:

```
./di did create key
```

By default the DID's verification key is Ed25519. Pass `--type ecdsa` (with an
optional `--curve`, defaulting to `p256`) to mint a DID backed by an ECDSA key
instead. This works for both `did:key` and `did:web`:

```
./di did create key --type ecdsa --curve p384
./di did create web --type ecdsa --url https://example.com
```

ECDSA works for `did create web --type ecdsa` and `did add-key --type ecdsa`
too. Because ECDSA keys are not seed-derivable, `--with-seed` and
`SECRET_KEY_SEED` are not supported with `--type ecdsa`.

To also include the secret key seed in the output (useful for re-deriving the
same DID later), pass `--with-seed`:

```
./di did create --with-seed
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
SECRET_KEY_SEED=z1AXVyT6G1Qk3E9cMPkDYY6wVRpZjVGWAZ3TfrAgFZkX6bv ./di did create
```

Save the DID document and key material to local storage with `--save`
(written to `~/.config/did-cli-wallet/dids/` by default, or `$DIDS_DIR` if set). A `.meta.json`
metadata sidecar is written next to the DID document, recording the creation
timestamp; `--handle` and `--description` add user-defined metadata to it
(both require `--save`):

```
./di did create --save --handle demo-issuer
DID saved to /home/user/.config/did-cli-wallet/dids/key/did:key:z6Mkr....json
{
  "id": "did:key:z6Mkr...",
  "didDocument": { ... }
}
```

If the DID's verification key also exists in the local wallet (e.g. both were
derived from the same seed), saving the DID records the association in that
key's metadata sidecar as well.

#### Create a did:web DID

Generate a `did:web` DID. Unlike `did:key`, a `did:web` DID is tied to a domain,
so `--url` (the HTTPS url of the DID document) is required:

```
./di did create web --url https://example.com
{
  "id": "did:web:example.com",
  "didDocument": { ... }
}
```

This generates a single Ed25519 verification key, wired into the
`authentication`, `assertionMethod`, `capabilityDelegation`, and
`capabilityInvocation` relationships. Additional keys can be added later.

As with `did:key`, pass `--with-seed` to include the secret key seed in the
output (useful for re-deriving the same DID later):

```
./di did create web --url https://example.com --with-seed
{
  "id": "did:web:example.com",
  "secretKeySeed": "z1AXVyT6G1Qk3E9cMPkDYY6wVRpZjVGWAZ3TfrAgFZkX6bv",
  "didDocument": { ... }
}
```

Or set the `SECRET_KEY_SEED` environment variable to a multibase-encoded seed to
generate the DID deterministically:

```
SECRET_KEY_SEED=z1AXVyT6G1Qk3E9cMPkDYY6wVRpZjVGWAZ3TfrAgFZkX6bv \
  ./di did create web --url https://example.com
```

Save the DID document and key material to local storage with `--save` (written
to `~/.config/did-cli-wallet/dids/web/` by default, or `$DIDS_DIR` if set). The key file is an
object keyed by verification method id, so further keys can be appended later:

```
./di did create web --url https://example.com --save
DID saved to /home/user/.config/did-cli-wallet/dids/web/did:web:example.com.json
{
  "id": "did:web:example.com",
  "didDocument": { ... }
}
```

#### Add a key to a did:web DID

Add another verification key to an existing, locally stored `did:web` DID (the
DID must have been saved with `did create web --save`). The new key is generated,
added to the DID document, and both the document and key file in storage are
updated in place:

```
./di did add-key did:web:example.com
DID saved to /home/user/.config/did-cli-wallet/dids/web/did:web:example.com.json
{
  "id": "did:web:example.com",
  "didDocument": { ... }
}
```

By default the new key is wired into the `authentication`, `assertionMethod`,
`capabilityDelegation`, and `capabilityInvocation` relationships. Pass
`--purpose` (repeatable) to choose specific relationships:

```
./di did add-key did:web:example.com --purpose authentication --purpose assertionMethod
```

By default the new key is Ed25519; pass `--type ecdsa` (with an optional
`--curve`, defaulting to `p256`) to add an ECDSA key instead:

```
./di did add-key did:web:example.com --type ecdsa --curve p384
```

Pass `--type x25519` to add an X25519 (Curve25519) key agreement key. X25519
keys are encryption/key-exchange keys, not signing keys, so they are wired into
the `keyAgreement` relationship only -- a `--purpose` other than `keyAgreement`
is rejected:

```
./di did add-key did:web:example.com --type x25519
```

For Ed25519 keys, the new key is derived from a seed (as with `did create`):
pass `--with-seed` to generate (and print) a fresh seed, or set `SECRET_KEY_SEED`
to derive the key deterministically. ECDSA and X25519 keys are not
seed-derivable, so `--with-seed` is not supported with `--type ecdsa` or
`--type x25519`:

```
./di did add-key did:web:example.com --with-seed
```

#### List DIDs

List the DIDs saved in local storage (via `did create --save`) as a table of
their metadata:

```
./di did list
HANDLE       METHOD  CREATED     DID                                           DESCRIPTION
-----------  ------  ----------  --------------------------------------------  -----------
demo-issuer  key     2026-06-10  did:key:z6MkrLBubwzwEvwms...6MHdf3EeQMnCsdX2hM
```

If no DIDs are stored, nothing is printed. Pass `--json` to output the list as
a JSON array of objects with metadata:

```
./di did list --json
[
  {
    "did": "did:key:z6Mkr...",
    "method": "key",
    "created": "2026-06-10T17:22:31.123Z",
    "handle": "demo-issuer"
  }
]
```

Or pass `--plain` to print just the DIDs, one per line, sorted:

```
./di did list --plain
did:key:z6Mkr...
did:key:z6Mks...
```

#### Show a DID

Display the DID document saved in local storage (via `did create --save`),
looked up by DID or by its metadata handle. The stored DID document holds no
secret key material -- signing keys live in a separate key file -- so it is
printed as-is:

```
./di did show did:key:z6Mkr...
{
  "@context": [ ... ],
  "id": "did:key:z6Mkr...",
  "verificationMethod": [ ... ],
  ...
}
```

Aliases: `view`, `cat`.

Pass `--meta` to show the DID's metadata instead of the DID document:

```
./di did show demo-issuer --meta
FIELD        VALUE
-----------  ----------------------------------------------
DID          did:key:z6Mkr...
Method       key
Handle       demo-issuer
Created      2026-06-10T17:22:31.123Z
Description
Keys         1
```

`--meta --json` prints the same metadata as a JSON object.

#### Edit DID metadata

Show or edit the metadata of a stored DID with `did meta` (looked up by DID or
handle). With no options it prints the current metadata; with `--handle` /
`--description` it updates the metadata sidecar (the DID document itself is
never rewritten). Passing an empty string clears a field:

```
./di did meta did:key:z6Mkr... --handle demo-issuer --description 'Issuer DID for the demo'
Metadata saved to /home/user/.config/did-cli-wallet/dids/key/did:key:z6Mkr....meta.json
{
  "created": "2026-06-10T17:22:31.123Z",
  "handle": "demo-issuer",
  "description": "Issuer DID for the demo"
}
```

#### Remove a DID

Remove a stored DID with `did remove` (aliases: `delete`, `rm`), looked up by
DID or handle. The DID document, its `.keys.json` key file, and its
`.meta.json` metadata sidecar are all deleted, and the DID is scrubbed from
the cached `dids` associations of any matching wallet keys:

```
./di did remove demo-issuer
Removed /home/user/.config/did-cli-wallet/dids/key/did:key:z6Mkr....json
Removed /home/user/.config/did-cli-wallet/dids/key/did:key:z6Mkr....keys.json
Removed /home/user/.config/did-cli-wallet/dids/key/did:key:z6Mkr....meta.json
```

### Verifiable Credentials

#### Verify a credential

Run full verification on a Verifiable Credential (JSON). Beyond the
cryptographic signature check, this also verifies expiration, revocation /
status, and whether the issuer DID is recognized in any trusted registry
(via `@interop/verifier-core` and `@digitalcredentials/issuer-registry-client`).

The credential is read from a file argument, an http(s) URL, or, if neither
is given, from stdin:

```
./di vc verify credential.json
./di vc verify https://example.com/credentials/123.json
cat credential.json | ./di vc verify
```

By default it prints the full `@interop/verifier-core` verification result
(top-level `verified`, a per-suite `summary`, and the flat `results` of every
check). Pass `--summary` for a compact, human-friendly object instead:

```
./di vc verify credential.json --summary
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
as a command-line wallet and issuer. The credential is read from a file
argument, an http(s) URL, or, if neither is given, from stdin, and the issued
credential is printed to stdout. If the input already carries a proof, issuing
appends an additional one.

The DID to issue with is required (`--did`); it must have been saved locally (see
`di did create --save`):

```
./di vc issue credential.json --did did:key:z6Mk...
cat credential.json | ./di vc issue --did did:key:z6Mk...
```

The credential's `issuer` is set to the signing DID when the input has none.
When the input already names an `issuer`, it must match the signing DID,
otherwise issuance is aborted -- a credential cannot be issued by a DID other
than the one named as its issuer.

By default the first key in the DID's `assertionMethod` relationship is used.
Pass `--key` to choose a specific verification method; it must be authorized by
the DID's `assertionMethod` array, otherwise issuance fails:

```
./di vc issue credential.json --did did:key:z6Mk... --key did:key:z6Mk...#z6Mk...
```

The signature suite defaults to the signing key's type. An Ed25519 DID signs
with `eddsa-rdfc-2022` (a W3C Data Integrity proof) by default; pass
`--suite Ed25519Signature2020` for the classic Ed25519Signature2020 proof:

```
./di vc issue credential.json --did did:key:z6Mk... --suite Ed25519Signature2020
```

An ECDSA DID (see `did create --type ecdsa`) signs with `ecdsa-rdfc-2019`. The
suite is selected automatically from the key, so no `--suite` flag is needed:

```
./di vc issue credential.json --did did:key:zDna...
```

Only the P-256 and P-384 curves can issue credentials -- the `ecdsa-rdfc-2019`
cryptosuite does not support P-521 (key creation warns about this). A suite that
does not match the key type (e.g. `--suite eddsa-rdfc-2022` for an ECDSA key) is
rejected. ECDSA credentials round-trip through `vc verify` (below).

Pass `--save` to also store the issued credential in local wallet storage
(`~/.config/did-cli-wallet/credentials/` by default, or `$WALLET_DIR` if set); `--save`
records the creation timestamp in a `.meta.json` metadata sidecar, and
`--handle` / `--description` (which require `--save`) tag the saved credential
the same way `zcap create --save` does:

```
./di vc issue credential.json --did did:key:z6Mk... --save --handle alumni
Credential saved to /home/user/.config/did-cli-wallet/credentials/sha256-1f4a....json
```

The exit code is scriptable: `0` when the credential was issued, `1` on an
issuance error (an unauthorized key, an unknown suite, a missing DID / key
file, or an issuer that does not match the signing DID), and `2` on a
read/parse error.

#### Import a credential

Store an existing Verifiable Credential in local wallet storage with
`vc import`. The credential is read from a file argument, an http(s) URL, or,
if neither is given, from stdin. The input must structurally look like a
credential (its `type` must include `VerifiableCredential`); it is stored
as-is and is *not* verified on import (run `vc verify` for that). `--handle` /
`--description` tag the saved credential:

```
./di vc import credential.json --handle alumni --description 'Alumni credential'
./di vc import https://example.com/credentials/123.json
cat credential.json | ./di vc import
Credential saved to /home/user/.config/did-cli-wallet/credentials/urn_uuid_9b1deb4d....json
```

The credential file is named after the credential's `id`; a credential
without an `id` (the property is optional) is stored under a digest of its
content, so re-importing it overwrites rather than duplicates. Re-importing a
credential preserves the metadata its sidecar already carries.

The exit code is scriptable: `0` when the credential was imported, `1` when
the input is not a Verifiable Credential, and `2` on a fetch/read/parse error.

#### List credentials

List the credentials saved in local wallet storage (via `vc import` or
`vc issue --save`) as a table of their metadata. The TYPE column shows the
credential's most specific type (its first `type` entry other than the
generic `VerifiableCredential`):

```
./di vc list
HANDLE  TYPE                 ISSUER                          CREATED     ID                           DESCRIPTION
------  -------------------  ------------------------------  ----------  ---------------------------  -----------------
alumni  OpenBadgeCredential  did:key:z6MkExa...ampleIssuer    2026-06-11  urn:uuid:9b1deb4d-3b7d-4ba8  Alumni credential
```

If no credentials are stored, nothing is printed. Pass `--json` to output the
list as a JSON array of objects with metadata:

```
./di vc list --json
[
  {
    "id": "urn:uuid:9b1deb4d-3b7d-4ba8",
    "type": "OpenBadgeCredential",
    "issuer": "did:key:z6MkExampleIssuer",
    "created": "2026-06-11T17:22:31.123Z",
    "handle": "alumni",
    "description": "Alumni credential"
  }
]
```

Or pass `--plain` to print just the credential ids, one per line, sorted. A
credential without an `id` is listed by its storage id (the `sha256-...` file
name), which `show` / `meta` / `remove` accept in place of a credential id.

#### Show a credential

Display a credential saved in local wallet storage, looked up by its
credential id (as printed by `vc list`), its storage id, or its metadata
handle:

```
./di vc show alumni
{
  "@context": ["https://www.w3.org/ns/credentials/v2"],
  "id": "urn:uuid:9b1deb4d-3b7d-4ba8",
  "type": ["VerifiableCredential", "OpenBadgeCredential"],
  ...
}
```

Aliases: `view`, `cat`.

Pass `--meta` to show the credential's metadata instead, along with its
issuer, validity start, and expiration:

```
./di vc show alumni --meta
FIELD        VALUE
-----------  ----------------------------
ID           urn:uuid:9b1deb4d-3b7d-4ba8
Type         OpenBadgeCredential
Handle       alumni
Created      2026-06-11T17:22:31.123Z
Description  Alumni credential
Issuer       did:key:z6MkExampleIssuer
Valid From   2026-01-01T00:00:00Z
Expires
```

`--meta --json` prints the same metadata as a JSON object.

#### Edit credential metadata

Show or edit the metadata of a stored credential with `vc meta` (looked up by
credential id, storage id, or handle). With no options it prints the current
metadata; with `--handle` / `--description` it updates the metadata sidecar
(the stored credential itself is never rewritten). Passing an empty string
clears a field:

```
./di vc meta urn:uuid:9b1deb4d-3b7d-4ba8 \
  --handle alumni --description 'Alumni credential'
Metadata saved to /home/user/.config/did-cli-wallet/credentials/urn_uuid_9b1deb4d-3b7d-4ba8.meta.json
{
  "created": "2026-06-11T17:22:31.123Z",
  "handle": "alumni",
  "description": "Alumni credential"
}

./di vc meta alumni --description ''
```

#### Remove a credential

Remove a stored credential with `vc remove` (aliases: `delete`, `rm`), looked
up by credential id, storage id, or handle. Both the credential file and its
`.meta.json` metadata sidecar are deleted:

```
./di vc remove alumni
Removed /home/user/.config/did-cli-wallet/credentials/urn_uuid_9b1deb4d-3b7d-4ba8.json
Removed /home/user/.config/did-cli-wallet/credentials/urn_uuid_9b1deb4d-3b7d-4ba8.meta.json
```

### Authorization Capabilities (zCaps)

An Authorization Capability (zCap) grants its
controller permission to invoke an action against a resource (the
`invocationTarget`). Authority starts at an unsigned _root_ capability and is
handed down a chain of signed _delegated_ capabilities, each one optionally
narrowing the allowed actions or the target.

Both commands print the capability as JSON together with an `encoded` field --
the capability serialized and `base58btc`-encoded with a multibase `z` prefix --
which is the compact form you pass to `zcap delegate --capability` to delegate it
further. Pass `--save` to also write the capability to local wallet storage
(`~/.config/did-cli-wallet/zcaps/` by default, or `$WALLET_DIR` if set); `--save` records the
creation timestamp in a `.meta.json` metadata sidecar, and `--handle` /
`--description` (which require `--save`) tag the saved capability the same way
`key create --save` and `did create --save` do. The exit code is `0` on
success and `1` on a creation / delegation or input error.

#### Create a root capability

Build the root capability for an invocation target. The `--controller` is the DID
that holds root authority over the target, and `--url` is the `invocationTarget`.
Root capabilities are unsigned, so no key is needed:

```
./di zcap create \
  --controller did:key:z6Mkfeco2NSEPeFV3DkjNSabaCza1EoS3CmqLb1eJ5BriiaR \
  --url https://example.com/api
{
  "rootCapability": {
    "@context": "https://w3id.org/zcap/v1",
    "id": "urn:zcap:root:https%3A%2F%2Fexample.com%2Fapi",
    "controller": "did:key:z6Mkfeco2NSEPeFV3DkjNSabaCza1EoS3CmqLb1eJ5BriiaR",
    "invocationTarget": "https://example.com/api"
  },
  "encoded": "z3g9TJBrQTdKemE9BC43N9WsT8snKvQzwCpCWs8o..."
}
```

The root capability's `id` is always `urn:zcap:root:<url-encoded invocationTarget>`,
and a root capability grants all actions (it has no `allowedAction`).

#### Note about the `encoded` field

The multibase- (that's the `z` prefix) and base58btc-encoded JSON of the zcap
is returned, for convenience, in the `encoded` field.

This is done for easier "double-click to copy" and pasting into other tools,
such as password managers, server env secrets, etc.

#### Delegate a capability

Delegate authority to another DID (`--delegatee`, which becomes the delegated
capability's controller). The delegation is signed with the delegator's
`capabilityDelegation` key, sourced one of two ways:

- **A locally-stored DID (`--did`)** -- the DID must have been saved with
  `di did create --save`; this is the preferred mode and mirrors `vc issue`.
- **A secret key seed (`ZCAP_CONTROLLER_KEY_SEED` + `--controller`)** -- the
  `did:key` is re-derived from the seed and checked against `--controller`.

To delegate from the root capability for a target, pass `--url` (the same
`invocationTarget` the root was created for) and the action(s) to allow with
`--allow` (repeatable; if omitted the delegatee inherits the parent's actions):

```
./di zcap delegate \
  --did did:key:z6Mkfeco2NSEPeFV3DkjNSabaCza1EoS3CmqLb1eJ5BriiaR \
  --delegatee did:key:z6MknBxrctS4KsfiBsEaXsfnrnfNYTvDjVpLYYUAN6PX2EfG \
  --url https://example.com/documents \
  --allow read
{
  "delegatedCapability": {
    "@context": [
      "https://w3id.org/zcap/v1",
      "https://w3id.org/security/suites/ed25519-2020/v1"
    ],
    "id": "urn:uuid:e03d4f97-2e70-42e8-ae5d-51e92e903afa",
    "controller": "did:key:z6MknBxrctS4KsfiBsEaXsfnrnfNYTvDjVpLYYUAN6PX2EfG",
    "parentCapability": "urn:zcap:root:https%3A%2F%2Fexample.com%2Fdocuments",
    "invocationTarget": "https://example.com/documents",
    "expires": "2027-06-07T17:30:00Z",
    "allowedAction": ["read"],
    "proof": {
      "type": "Ed25519Signature2020",
      "created": "2026-06-07T17:30:00Z",
      "verificationMethod": "did:key:z6Mkfeco...#z6Mkfeco...",
      "proofPurpose": "capabilityDelegation",
      "capabilityChain": ["urn:zcap:root:https%3A%2F%2Fexample.com%2Fdocuments"],
      "proofValue": "z5tuwwdJE6VXLhf1v8SNAquBmMcJCD7zJ4bXDi6rh1Fk..."
    }
  },
  "encoded": "zkL8vet8M2mn7akSpHEVvgFUCTVq4VSGs1s8Zsq9bYba..."
}
```

The same delegation, signed via a secret key seed instead of a stored DID:

```
ZCAP_CONTROLLER_KEY_SEED=z1AZK4h5w5YZkKYEgqtcFfvSbWQ3tZ3ZFgmLsXMZsTVoeK7 \
  ./di zcap delegate \
  --controller did:key:z6Mkfeco2NSEPeFV3DkjNSabaCza1EoS3CmqLb1eJ5BriiaR \
  --delegatee did:key:z6MknBxrctS4KsfiBsEaXsfnrnfNYTvDjVpLYYUAN6PX2EfG \
  --url https://example.com/documents \
  --allow read
```

To delegate an _existing_ capability further down the chain, pass it as
`--capability` instead of `--url` -- the `encoded` string from a previous
delegation, a path to a JSON file containing the capability, or the id or
metadata handle of a zcap saved in local wallet storage. Use
`--invocation-target` to attenuate (narrow) the parent's target to a sub-path:

```
./di zcap delegate \
  --did did:key:z6MknBxr... \
  --delegatee did:key:z6Mks... \
  --capability zkL8vet8M2mn7akSpHEVvgFUCTVq4VSGs1s8Zsq9bYba... \
  --invocation-target https://example.com/documents/reports \
  --allow read
```

The delegated capability expires after `--ttl` (a duration such as `1y`, `30d`,
`24h`, `15m`; default `1y`). Pass `--expires` with an explicit ISO 8601 date to
override it:

```
./di zcap delegate --did did:key:z6Mk... --delegatee did:key:z6Mkn... \
  --url https://example.com/documents --allow read --ttl 30d

./di zcap delegate --did did:key:z6Mk... --delegatee did:key:z6Mkn... \
  --url https://example.com/documents --allow read --expires 2027-01-01T00:00:00Z
```

#### List capabilities

List the capabilities saved in local wallet storage (via `zcap create --save`
or `zcap delegate --save`) as a table of their metadata. The TYPE column shows
whether the capability is a `root` or a `delegated` one:

```
./di zcap list
HANDLE    TYPE  CREATED     ID                                            DESCRIPTION
--------  ----  ----------  --------------------------------------------  -------------
api-root  root  2026-06-11  urn:zcap:root:https%3...%2Fexample.com%2Fapi  Demo API root
```

If no capabilities are stored, nothing is printed. Pass `--json` to output the
list as a JSON array of objects with metadata:

```
./di zcap list --json
[
  {
    "id": "urn:zcap:root:https%3A%2F%2Fexample.com%2Fapi",
    "type": "root",
    "created": "2026-06-11T17:22:31.123Z",
    "handle": "api-root",
    "description": "Demo API root"
  }
]
```

Or pass `--plain` to print just the capability ids, one per line, sorted:

```
./di zcap list --plain
urn:zcap:root:https%3A%2F%2Fexample.com%2Fa
urn:zcap:root:https%3A%2F%2Fexample.com%2Fb
```

#### Show a capability

Display a capability saved in local wallet storage, looked up by its
capability id (as printed by `zcap list`) or by its metadata handle:

```
./di zcap show api-root
{
  "@context": "https://w3id.org/zcap/v1",
  "id": "urn:zcap:root:https%3A%2F%2Fexample.com%2Fapi",
  "controller": "did:key:z6Mkfeco2NSEPeFV3DkjNSabaCza1EoS3CmqLb1eJ5BriiaR",
  "invocationTarget": "https://example.com/api"
}
```

Aliases: `view`, `cat`.

Pass `--meta` to show the capability's metadata instead, along with its
controller, invocation target, and (for delegated capabilities) expiration:

```
./di zcap show api-root --meta
FIELD        VALUE
-----------  --------------------------------------------------------
ID           urn:zcap:root:https%3A%2F%2Fexample.com%2Fapi
Type         root
Handle       api-root
Created      2026-06-11T17:22:31.123Z
Description  Demo API root
Controller   did:key:z6Mkfeco2NSEPeFV3DkjNSabaCza1EoS3CmqLb1eJ5BriiaR
Target       https://example.com/api
Expires
```

`--meta --json` prints the same metadata as a JSON object.

#### Edit capability metadata

Show or edit the metadata of a stored capability with `zcap meta` (looked up
by capability id or handle). With no options it prints the current metadata;
with `--handle` / `--description` it updates the metadata sidecar (the stored
capability itself is never rewritten). Passing an empty string clears a field:

```
./di zcap meta urn:zcap:root:https%3A%2F%2Fexample.com%2Fapi \
  --handle api-root --description 'Demo API root'
Metadata saved to /home/user/.config/did-cli-wallet/zcaps/urn_zcap_root_https_3A_2F_2Fexample.com_2Fapi.meta.json
{
  "created": "2026-06-11T17:22:31.123Z",
  "handle": "api-root",
  "description": "Demo API root"
}

./di zcap meta api-root --description ''
```

#### Remove a capability

Remove a stored capability with `zcap remove` (aliases: `delete`, `rm`),
looked up by capability id or handle. Both the capability file and its
`.meta.json` metadata sidecar are deleted:

```
./di zcap remove api-root
Removed /home/user/.config/did-cli-wallet/zcaps/urn_zcap_root_https_3A_2F_2Fexample.com_2Fapi.json
Removed /home/user/.config/did-cli-wallet/zcaps/urn_zcap_root_https_3A_2F_2Fexample.com_2Fapi.meta.json
```

Note that removing a capability from local storage does not revoke it -- a
delegated capability that has already been handed to its delegatee remains
valid until it expires (see `--ttl` / `--expires`).

### Wallet Attached Storage (WAS)

The `was` command group is a client for
[Wallet Attached Storage](https://digitalcredentials.github.io/wallet-attached-storage-spec/)
servers, which organize content as `Space > Collection > Resource` behind
zcap-authorized HTTP. Every request is signed with a `did:key` DID stored in
the local wallet (saved with `did create --save`; Ed25519 keys only for now).

Commands address content with a single positional **WAS path**:

```
SPACE[/COLLECTION[/RESOURCE]]
```

where `SPACE` is one of:

- a **registry handle** (e.g. `home`) of a space registered in the local
  wallet (`~/.config/did-cli-wallet/was-spaces/`), which also supplies the server URL and
  signing DID defaults;
- a **bare space id** (a server-generated uuid or urn), combined with
  `--server` / `WAS_SERVER_URL`;
- a **full space URL** (e.g. `https://was.example/space/8124...cf2e`), which
  is self-contained -- the server URL is its origin. Collection and resource
  segments can be appended to any of the three forms.

The signing DID resolves from `--did` (a DID or stored-DID handle), the
`WAS_DID` environment variable, or the controller recorded in the registry
entry. Exit codes: `0` success, `1` operation error (a typed WAS error or a
not-found/not-visible read -- the spec returns 404 for both), `2` input error
(bad path, unknown handle/DID, missing server URL).

#### Create a space

Create a space on a WAS server (`--name`, a display name, is optional). Pass
`--save` to register it in the local wallet, with the usual `--handle` /
`--description` metadata; the handle is what makes every later command short:

```
./di was space create --name 'Home space' \
  --server http://localhost:3002 --did did:key:z6Mkfeco... \
  --save --handle home
Space registered in /home/user/.config/did-cli-wallet/was-spaces/81246131-69a4-45ab-9bff-9c946b59cf2e.json
{
  "id": "81246131-69a4-45ab-9bff-9c946b59cf2e",
  "url": "http://localhost:3002/space/81246131-69a4-45ab-9bff-9c946b59cf2e",
  "name": "Home space",
  "controller": "did:key:z6Mkfeco..."
}
```

Without `--save`, address the space later by its full URL (or register it
afterwards with `was space add`).

#### List, show, and manage spaces

`was space list` lists the locally registered spaces (WAS servers do not
implement server-side space listing yet; `--remote` asks anyway and surfaces
the 501). `--json` and `--plain` work as in the other list commands:

```
./di was space list
HANDLE  NAME        SPACE ID                              SERVER                 CREATED
------  ----------  ------------------------------------  ---------------------  ----------
home    Home space  81246131-69a4-45ab-9bff-9c946b59cf2e  http://localhost:3002  2026-06-11
```

`was space show` (aliases: `view`, `cat`) prints the Space Description from
the server, or the local registry record with `--meta`:

```
./di was space show home
{
  "id": "81246131-69a4-45ab-9bff-9c946b59cf2e",
  "type": ["Space"],
  "name": "Home space",
  "controller": "did:key:z6Mkfeco..."
}
```

`was space update` (alias: `configure`) upserts description fields
(`--name`), also refreshing the registry entry. `was space add` registers an
*existing* remote space (a full space URL, or a bare id plus `--server`) in
the local registry, verifying it with a describe first. The local/remote
delete pair:

- `was space delete <space>` (alias: `rm`) deletes the space **on the
  server** (idempotent) and removes the registry entry;
- `was space forget <space>` removes only the local registry entry.

`was space backends` lists the storage backends available within a space, and
`was space quotas` shows the space's storage report grouped by backend (usage,
limit, and any restricted actions). Both render a table by default and take
`--json` for the raw response:

```
./di was space backends home
ID       NAME        MANAGED BY  STORAGE MODE     PERSISTENCE
default  Filesystem  server      document, blob   durable

./di was space quotas home
BACKEND             STATE  USAGE (B)  LIMIT (B)  RESTRICTED
default (Filesystem) ok    2048       1048576
```

A server that does not implement these endpoints (a 501) is reported as an
error.

#### Manage collections

The `collection` group (alias: `coll`) manages collections within a space.
`create` takes a space address plus an optional `--name` and `--id` (the id
is server-generated otherwise); `show`/`update`/`delete` take a
`SPACE/COLLECTION` path:

```
./di was collection create home --name Credentials --id credentials
{
  "id": "credentials",
  "url": "http://localhost:3002/space/8124...cf2e/credentials",
  "name": "Credentials"
}

./di was collection list home
ID           NAME         URL
-----------  -----------  ---------------------------------------------------
credentials  Credentials  http://localhost:3002/space/8124...cf2e/credentials

./di was collection delete home/credentials
Deleted http://localhost:3002/space/8124...cf2e/credentials on the server.
```

`was collection backend` shows the storage backend a collection is stored on,
and `was collection quota` shows the collection's storage usage scoped to that
backend (state, usage, limit, and any restricted actions). Both render a table
by default and take `--json` for the raw response:

```
./di was collection backend home/credentials
FIELD         VALUE
------------  --------------
ID            default
Name          Filesystem
Managed By    server
Storage Mode  document, blob
Persistence   durable

./di was collection quota home/credentials
FIELD        VALUE
-----------  --------------------
Backend      default (Filesystem)
Managed By   server
State        ok
Usage (B)    2048
Limit (B)    1048576
Restricted
Measured At  2026-06-13T00:00:00Z
```

A missing or not-visible collection is reported as not-found; a server (or
backend) that does not implement these endpoints (a 501) is reported as an
error.

#### Add and read resources

The `resource` group (alias: `res`) manages the content itself. Payloads come
from a file argument or stdin: `*.json` files (and any input that parses to a
JSON object or array) are sent as JSON, anything else as binary
`application/octet-stream`, and an explicit `--content-type` sends the bytes
as-is with that type (useful for e.g. `application/ld+json` or images).

`add` posts to a collection and lets the server pick the resource id; `put`
creates or replaces at a known id:

```
./di was resource add home/credentials vc.json
{
  "id": "d3c9...",
  "url": "http://localhost:3002/space/8124...cf2e/credentials/d3c9...",
  "contentType": "application/json"
}

./di was resource put home/credentials/vc-1 vc.json
cat vc.json | ./di was resource put home/credentials/vc-1
./di was resource put home/photos/pic-1 photo.png --content-type image/png
```

`get` pretty-prints JSON to stdout and writes binary raw (use `--output` for
files); a missing or not-visible resource prints
`Not found (or not visible to you): <url>` and exits `1`:

```
./di was resource get home/credentials/vc-1
{
  "name": "Alice"
}

./di was resource get home/photos/pic-1 --output photo.png
```

`list` renders the resources of a collection (`ID | CONTENT TYPE | URL`), and
`delete` (alias: `rm`) removes one (idempotent).

#### Resource metadata (name and tags)

The `resource-meta` group (alias: `meta`) reads and updates a resource's
metadata. `get` prints the whole metadata object -- the server-managed
`contentType`, `size`, and timestamps plus the user-writable `custom` (its
`name` and `tags`):

```
./di was resource-meta get home/credentials/vc-1
```

`put` updates the user-writable `custom`. `--name` sets the display name shown
in collection listings and `--tag key=value` (repeatable) sets annotations;
used on their own each is non-destructive -- `--name` preserves existing tags
and `--tag` preserves the existing name:

```
./di was resource-meta put home/credentials/vc-1 --name 'Diploma'
./di was resource-meta put home/credentials/vc-1 --tag year=2026 --tag status=verified
```

Giving both `--name` and `--tag` together replaces `custom` wholesale (any
field you do not pass is cleared). The `--json` escape hatch takes the full
`custom` object as inline JSON or a JSON file path, for the same full
replacement (pass `--json '{}'` to clear everything):

```
./di was resource-meta put home/credentials/vc-1 \
  --json '{"name":"Diploma","tags":{"year":"2026"}}'
./di was resource-meta put home/credentials/vc-1 --json custom.json
```

After a successful update the command prints the resulting metadata.

#### Shorthand verbs

For day-to-day use, the top-level verbs dispatch on the path depth:

```
./di was ls home                        # collections of a space
./di was ls home/credentials            # resources of a collection
./di was get home/credentials/vc-1      # = resource get
./di was put home/credentials/vc-1 vc.json   # = resource put
./di was rm home/credentials/vc-1       # delete whatever the path points at
./di was rm home                        # ... including a whole space
```

#### Delegate access (grant)

`was grant` delegates access to a space, collection, or resource. Actions are
HTTP verbs (`GET`, `PUT`, `POST`, `DELETE`; lowercase accepted), expiration
comes from `--ttl` (default `1y`) or an explicit `--expires`, and the output
is the signed capability plus its `encoded` multibase form -- the same shape
as `zcap delegate`. `--save` (with `--handle` / `--description`) stores it in
the zcap store (`~/.config/did-cli-wallet/zcaps/`):

```
./di was grant home/credentials --to did:key:z6MkBob... --action GET PUT
{
  "delegatedCapability": {
    "@context": [...],
    "id": "urn:uuid:e03d4f97-...",
    "controller": "did:key:z6MkBob...",
    "invocationTarget": "http://localhost:3002/space/8124...cf2e/credentials",
    "allowedAction": ["GET", "PUT"],
    "expires": "2027-06-11T17:30:00Z",
    "proof": { ... }
  },
  "encoded": "zkL8vet8M2mn..."
}
```

Hand the `encoded` string (or the JSON) to the delegatee out-of-band.

#### Use a received capability

On the receiving side, `ls` / `get` / `put` / `rm` (and `resource
add/get/put`) accept `--capability` instead of a path. The reference is one
of:

- the `encoded` multibase string from the grant output (`zkL8vet...`),
- a path to a JSON file holding the capability, or
- the capability id or metadata **handle of a zcap** stored in
  `~/.config/did-cli-wallet/zcaps/`.

Note that a `--capability` reference is *not* a WAS path -- no space,
collection, or resource address is given (or needed). The capability itself
records what it grants access to in its `invocationTarget`, and that is what
the command operates on:

- a capability granted on a **resource** drives `get` / `put` / `rm`;
- one granted on a **collection** drives `ls`, `resource add`, and `rm`;
- one granted on a whole **space** drives `ls` and `rm`.

A depth mismatch (e.g. `get` with a collection-scoped capability) is an
input error. The server URL is taken from the invocation target's origin,
and the signing DID defaults to the capability's controller (the delegatee)
when that DID is stored locally -- so usually no flags are needed at all.

In the examples below, `bob-share` is the metadata handle of a *stored zcap*
(not a space or collection handle): say Alice granted Bob `GET`/`PUT` on the
single resource `home/credentials/vc-1`, and the capability was saved with
`--save --handle bob-share` (on Alice's machine via `was grant --save`; on
Bob's machine he can pass the encoded string or a JSON file directly):

```
# Alice delegates one resource to Bob, keeping a tagged copy:
./di was grant home/credentials/vc-1 --to did:key:z6MkBob... \
  --action GET PUT --save --handle bob-share

# Bob, with the encoded string he received out-of-band -- this reads the
# resource the capability targets (home/credentials/vc-1):
./di was get --capability zkL8vet8M2mn...
{
  "name": "Alice"
}

# The same via a capability JSON file, or a stored zcap's handle:
./di was get --capability ./bob-share.json
./di was get --capability bob-share

# A resource-scoped capability also allows writing (it grants PUT):
./di was put data.json --capability bob-share

# Had the grant been on the whole collection (home/credentials), ls would
# list it and `resource add` could post new resources into it:
./di was ls --capability zkL8vet8M2mn...
```

#### Policies and public sharing

By default all operations on a space requires a capability invocation. A
**policy** can override this per space, collection, or resource; the common
case is `PublicCanRead` -- the "share via public link" model. `was publish`
is the sugar for it and prints the public URL; `was unpublish` reverts to
capability-only access:

```
./di was publish home/credentials/vc-1
Published (world-readable): http://localhost:3002/space/8124...cf2e/credentials/vc-1
http://localhost:3002/space/8124...cf2e/credentials/vc-1

curl http://localhost:3002/space/8124...cf2e/credentials/vc-1   # no auth needed
```

The generic primitives work at any depth: `was policy show <path>` prints the
policy document (or `No policy set (or not visible to you)` with exit `1`),
`was policy set <path> --type PublicCanRead` (or a policy JSON file for
richer, server-defined policies), and `was policy clear <path>`.

#### Export and import a space

`was space export` downloads a whole space as a tar archive (to `--output`
or raw to stdout); `was space import` merges a tar into a space (from a file
or stdin) and prints the import stats:

```
./di was space export home --output home.tar
Wrote 10240 bytes to home.tar

./di was space import other-space home.tar
{
  "collectionsCreated": 1,
  "collectionsSkipped": 0,
  "resourcesCreated": 2,
  "resourcesSkipped": 0,
  "policiesCreated": 0,
  "policiesSkipped": 0
}
```

#### End-to-end smoke test

To exercise the whole flow against a local server, start the reference
[was-teaching-server](https://github.com/digitalcredentials/was-teaching-server)
(the server URL must match byte-for-byte, including the port, since zcap
invocation targets embed it):

```
SERVER_URL='http://localhost:3002' PORT=3002 pnpm dev
```

Then, in another shell:

```
export WAS_SERVER_URL=http://localhost:3002

./di did create --save --handle alice
./di was space create --name Demo --did alice --save --handle demo
./di was collection create demo --name Docs --id docs
echo '{"hello": "world"}' | ./di was put demo/docs/doc-1
./di was get demo/docs/doc-1

./di did create --save --handle bob          # the delegatee
./di was grant demo/docs/doc-1 --to <bob's did> --action GET --did alice \
  --save --handle bob-share
./di was get --capability bob-share --did bob

./di was publish demo/docs/doc-1             # prints the public URL
curl <public url>                            # readable without auth

./di was rm demo                             # clean up (deletes the space)
```

The same flow runs as an env-gated integration test: `npm test` skips it
unless `WAS_TEST_SERVER_URL` points at a running server:

```
WAS_TEST_SERVER_URL=http://localhost:3002 npm run test:node
```

## Contribute

PRs accepted. Please follow the code-style and contribution conventions in
[CONTRIBUTING.md](CONTRIBUTING.md).

For a map of the codebase -- the module layout, the command-factory pattern,
and the build/test commands -- see [ARCHITECTURE.md](ARCHITECTURE.md). Storage
layout is documented in [STORAGE.md](STORAGE.md).

If editing the Readme, please conform to the
[standard-readme](https://github.com/RichardLitt/standard-readme) specification.

## License

[MIT](LICENSE.md) © 2026 Interop Alliance
