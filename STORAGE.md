## Setting Up Storage

To work with DIDs, you'll need storage for keys, local DID docs, and
notes.

**By default, everything is stored under `~/.config/did-cli-wallet/` -- DIDs in
`~/.config/did-cli-wallet/dids/<method>/`, other wallet items (keys, zcaps, credentials) in
`~/.config/did-cli-wallet/<collection>/`.**

The wallet directory can be relocated with the `WALLET_DIR` environment
variable; the DIDs subtree alone can be overridden with `DIDS_DIR` (its
default is `$WALLET_DIR/dids`).

DIDs are essentially repositories of public keys on various networks / ledgers.
Any non-trivial operations that involve them, such as registering, updating,
authenticating and so on, necessarily involve working with corresponding private
keys.

To aid with experimentation and development of DID-related prototypes, this app
uses a simple filesystem-based JSON blob storage system to store private keys,
local copies of DID documents, and DID metadata on one's local machine.

Keys from DID Documents (as well as related metadata) you control will be stored
in the `~/.config/did-cli-wallet/dids/<method>/` folder by default, and will be organized by
DID.

For example, for a DID of "did:method:abcd", the following files would be
potentially created:

- `~/.config/did-cli-wallet/dids/method/did:method:abcd.json` -- the DID document
- `~/.config/did-cli-wallet/dids/method/did:method:abcd.keys.json` -- the signing key material
- `~/.config/did-cli-wallet/dids/method/did:method:abcd.meta.json` -- the metadata sidecar

You can override the storage mechanism for each ledger method (to store JSON
files in a different directory, or to use an in-memory `MockStore` for unit
testing).

## Metadata Sidecars

User-editable metadata about stored keys, DIDs, zcaps, and credentials lives
in `.meta.json` sidecar files, next to the item they describe. This keeps the
stored items themselves spec-pure (key files are plain Multikey documents,
DID files are plain DID documents, zcap files are plain capability JSON,
credential files are plain Verifiable Credentials), and means metadata edits
never rewrite a file that holds secret key material.

- Keys: `~/.config/did-cli-wallet/keys/<storageId>.meta.json` (next to `<storageId>.json`)
- DIDs: `~/.config/did-cli-wallet/dids/<method>/<did>.meta.json` (next to `<did>.json`)
- zCaps: `~/.config/did-cli-wallet/zcaps/<storageId>.meta.json` (next to `<storageId>.json`)
- Credentials: `~/.config/did-cli-wallet/credentials/<storageId>.meta.json` (next to
  `<storageId>.json`). The storage id is the credential's `id` (sanitized for
  the filesystem), or a `sha256-...` digest of its content when the
  credential has no `id`.

A key sidecar looks like:

```json
{
  "created": "2026-06-10T17:22:31.123Z",
  "handle": "issuer-signing",
  "description": "Production signing key for the demo issuer",
  "dids": ["did:web:example.com"]
}
```

A DID or zcap sidecar is the same, minus the `dids` field. All fields are
optional and omitted when unset:

- `created` -- ISO 8601 timestamp written when the item is saved. Items saved
  before metadata support have no sidecar; `key meta` backfills a date-only
  `created` from the `YYYY-MM-DD` prefix of the key's file name on first edit.
- `handle` -- a short user-defined tag for telling items apart (set with
  `--handle` on create, or via the `key meta` / `did meta` / `zcap meta`
  commands). Handles are not required to be unique; commands that accept a
  handle exit with an error when it is ambiguous.
- `description` -- longer free-text description.
- `dids` (keys only) -- a cache of the locally stored DIDs whose documents
  reference the key. The value actually *displayed* by `key list` / `key show`
  is always re-derived by scanning the saved DID documents for the key's
  `publicKeyMultibase`, so the cache being stale is harmless. It is refreshed
  whenever `did create --save` / `did add-key` saves a matching key, and on
  every `key meta` write.

A missing sidecar simply means "no metadata"; an orphaned sidecar (whose item
was deleted by hand) is ignored. Note that CLI versions predating metadata
support will mis-list a storage directory that contains `.meta.json` files.
