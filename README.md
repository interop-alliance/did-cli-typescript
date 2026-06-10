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
./di -h
./di COMMAND -h
```

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
`ed25519`, `ecdsa`):

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

#### List key pairs

List the fingerprints (multibase-encoded public keys) of the key pairs saved in
local wallet storage (via `key create --save`), one per line:

```
./di key list
z6Mkr...
z6Mks...
```

If no keys are stored, nothing is printed. Pass `--json` to output the
fingerprints as a JSON array instead:

```
./di key list --json
[
  "z6Mkr...",
  "z6Mks..."
]
```

#### Show a key pair

Display a key saved in local wallet storage, looked up by its fingerprint
(`publicKeyMultibase`, as printed by `key list`). Only the public key object is
shown -- the stored secret key is never included in the output:

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
(written to `~/.dids/` by default, or `$DIDS_DIR` if set):

```
./di did create --save
DID saved to /home/user/.dids/key/did:key:z6Mkr....json
{
  "id": "did:key:z6Mkr...",
  "didDocument": { ... }
}
```

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
to `~/.dids/web/` by default, or `$DIDS_DIR` if set). The key file is an object
keyed by verification method id, so further keys can be appended later:

```
./di did create web --url https://example.com --save
DID saved to /home/user/.dids/web/did:web:example.com.json
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
DID saved to /home/user/.dids/web/did:web:example.com.json
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

For Ed25519 keys, the new key is derived from a seed (as with `did create`):
pass `--with-seed` to generate (and print) a fresh seed, or set `SECRET_KEY_SEED`
to derive the key deterministically. ECDSA keys are not seed-derivable, so
`--with-seed` is not supported with `--type ecdsa`:

```
./di did add-key did:web:example.com --with-seed
```

#### List DIDs

List the DIDs saved in local storage (via `id create --save`), one per line:

```
./di did list
did:key:z6Mkr...
did:key:z6Mks...
```

If no DIDs are stored, nothing is printed. Pass `--json` to output the DIDs as
a JSON array instead:

```
./di did list --json
[
  "did:key:z6Mkr...",
  "did:key:z6Mks..."
]
```

#### Show a DID

Display the DID document saved in local storage (via `did create --save`). The
stored DID document holds no secret key material -- signing keys live in a
separate key file -- so it is printed as-is:

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

### Verifiable Credentials

#### Verify a credential

Run full verification on a Verifiable Credential (JSON). Beyond the
cryptographic signature check, this also verifies expiration, revocation /
status, and whether the issuer DID is recognized in any trusted registry
(via `@interop/verifier-core` and `@digitalcredentials/issuer-registry-client`).

The credential is read from a file argument or, if none is given, from stdin:

```
./di vc verify credential.json
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
as a command-line wallet and issuer. The credential is read from a file argument
or, if none is given, from stdin, and the issued credential is printed to
stdout. If the input already carries a proof, issuing appends an additional one.

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

The exit code is scriptable: `0` when the credential was issued, `1` on an
issuance error (an unauthorized key, an unknown suite, a missing DID / key
file, or an issuer that does not match the signing DID), and `2` on a
read/parse error.

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
(`~/.wallet/zcaps/` by default, or `$WALLET_DIR` if set). The exit code is `0` on
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
`--capability` instead of `--url` -- either the `encoded` string from a previous
delegation or a path to a JSON file containing the capability. Use
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

List the ids of the capabilities saved in local wallet storage (via
`zcap create --save` or `zcap delegate --save`), one per line:

```
./di zcap list
urn:zcap:root:https%3A%2F%2Fexample.com%2Fa
urn:zcap:root:https%3A%2F%2Fexample.com%2Fb
```

If no capabilities are stored, nothing is printed. Pass `--json` to output the
ids as a JSON array instead:

```
./di zcap list --json
[
  "urn:zcap:root:https%3A%2F%2Fexample.com%2Fa",
  "urn:zcap:root:https%3A%2F%2Fexample.com%2Fb"
]
```

## Contribute

PRs accepted.

If editing the Readme, please conform to the
[standard-readme](https://github.com/RichardLitt/standard-readme) specification.

## License

[MIT](LICENSE.md) © 2026 Interop Alliance
