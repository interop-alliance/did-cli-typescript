---
name: publish-page
description: Publish a page to the user's own Wallet Attached Storage space -- ask their wallet for a scoped grant with `di was request-grant`, then write the file through the delegated capability and hand back the public URL. Use when the user asks to publish or host an HTML page, put a file in their WAS space or wallet storage, or when a `di was put` needs a capability you do not hold yet.
---

# Publish a page to the user's storage

You publish as yourself: you mint your own `did:key`, ask the user's wallet for
a narrow grant on one public collection, and write through that grant. You
never log into the wallet, never hold the user's key, and never see a
passphrase.

## Before anything

Two URLs are needed. Ask for whichever the user has not already given:

- their wallet's base URL (a Freewallet deployment, e.g. `https://wallet.example`)
- the base URL of the WAS server that hosts the request exchange (e.g.
  `https://was.example`), or `WAS_SERVER_URL` already exported in the
  environment

Check the CLI is reachable: `di --version`. If `di` is not on PATH, use
`npx -y @interop/did-cli` in place of `di` throughout.

If the user has no wallet account yet, send them to `<wallet>/signup` to create
one, wait for them to say they are signed up and logged in, then continue at
step 1. A brand-new account works the same. The wallet provisions the storage
space and the public collection when it approves the grant.

## Key material

Refer to your key and your grant by their handle (`agent`) only. Do not read,
print, `cat`, copy, or move anything under `~/.config/did-cli-wallet/`, and do
not ask the user for a passphrase, seed, or private key. The CLI mints the key
straight into local storage for exactly this reason: nothing secret has to pass
through your context.

## 1. Draft the page

Write the page to `./index.html` in the working directory. Show it to the user
and iterate until they are happy with it. Nothing has been sent anywhere yet,
so this is the cheap place to revise.

## 2. Ask the wallet for a grant

```
di was request-grant --exchange <was url> --wallet <wallet url> \
  --name "<what you call yourself>" --reason "Publish <what the page is>" \
  --save --handle agent
```

`--save` is the default and this flow depends on it: `di was put --capability`
resolves its signing key out of local storage, so a key held only for the run
cannot sign the write in step 4. Pass `--save --handle agent` explicitly rather
than relying on the default, so the handle you use later is the handle the run
filed. (`--no-save` exists for inspecting a grant you do not intend to use; it
is the wrong choice here.)

Drop `--exchange` when `WAS_SERVER_URL` is already set. `--reason` and `--name`
are shown to the user at the consent step, so write them for that reader.

If the command refuses because the handle is taken, a previous run already
saved a key under it. That key is your identity to the wallet, so reuse it
rather than minting another: replace `--handle agent` with `--did agent`. The
wallet then lists the new grant on your existing entry. The new grant is
filed under the next free handle (`agent-2`, `agent-3`, ...), and the command
prints it in its `--capability` example. Use that handle for `--capability`
in step 4, and keep `--did agent`.

## 3. Have the user approve

The command prints an approval link to stderr and then waits (up to ten
minutes, the exchange's lifetime). Tell the user, in your own words:

- to open the printed wallet link (the second link, when `--wallet` was given)
  in a browser, or the interaction URL if their wallet is on another device
- what the wallet will show them: your `did:key` and the reason you gave, and a
  request for read and write access to one collection named `web` in their
  space
- that approving grants access to that one collection only, expires on its own,
  and can be revoked

Then wait for the command to return. Let it run to completion. A second run
while one is outstanding mints a new key and a new link, and the user then
approves the wrong one.

Three ways it can end without a grant:

- declined or expired: run step 2 again for a fresh link
- timed out while the user was away: run step 2 again, optionally with
  `--timeout <seconds>`
- "the collection could not be granted": the user already has a private
  collection named `web`. A public collection is only ever created public,
  never converted, so ask for a different one with `--collection <name>`. The
  rest of the flow is unchanged: step 4 invokes whatever collection the grant
  came back for, and step 5 reads the page's URL out of the command's output.

## 4. Publish the page

```
di was put ./index.html --capability agent --did agent \
  --resource index.html --content-type text/html
```

Every flag is load-bearing: `--capability agent` invokes the grant,
`--did agent` signs with the key that grant was issued to (rather than any
`WAS_DID` in the environment), `--resource index.html` names the resource id
inside the granted collection, and `--content-type text/html` makes the server
serve it as a page instead of a download.

## 5. Hand back the URL

The command prints `{ "id": ..., "url": ... }` on stdout. That `url` is the
public address of the page. Confirm it serves anonymously:

```
curl -I <url>
```

A `200` with `content-type: text/html` means it is live. Give the user the URL.

Re-publishing later is step 4 again -- a plain overwrite, no new grant needed,
until the grant expires (about a week for write access).
