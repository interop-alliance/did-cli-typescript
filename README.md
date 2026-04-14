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

Generate a deterministic key pair by setting the `SECRET_KEY_SEED` environment
variable to a multibase-encoded seed (e.g. from `@digitalcredentials/bnid`):

```
SECRET_KEY_SEED=z1Aaj5A4UCsd... ./did key create
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

## Contribute

PRs accepted.

If editing the Readme, please conform to the
[standard-readme](https://github.com/RichardLitt/standard-readme) specification.

## License

[MIT](LICENSE.md) © 2026 Interop Alliance
