# Agent storage demo

A CLI LLM agent drafts an `index.html` and publishes it to the web, out of the
user's own Wallet Attached Storage space, in about a minute.

The agent acts as itself. It mints its own `did:key`, asks the user's wallet
for a narrow grant on one public collection, and writes through the delegated
capability. It never logs into the wallet, never holds the user's key, and
never sees a passphrase. The capability chain is the provenance record: this
page was written by agent X, under a grant from user Y, expiring at T.

The agent-facing version of this script is the
[`publish-page` skill](../../.claude/skills/publish-page/SKILL.md).

## Prerequisites

- **A Freewallet deployment** the user has an account on, reachable in a
  browser. Its `/external/request` route is what the approval link opens. A
  user with no account signs up at `<wallet>/signup` first; the wallet
  provisions the space and the public collection when it approves the grant.
- **A WAS server** serving the ephemeral-exchange routes
  (`/workflows/ephemeral/exchanges`), which carry the request to the wallet and
  the signed capability back. The reference
  [was-teaching-server](https://github.com/digitalcredentials/was-teaching-server)
  serves them with no extra configuration:

  ```
  SERVER_URL='http://localhost:3002' PORT=3002 pnpm dev
  ```

  The URL must match byte-for-byte, port included -- zcap invocation targets
  embed it. Use a bare origin: a sub-path deployment
  (`https://host/was`) does not resolve capabilities correctly yet (CLI-15).

- **`@interop/did-cli`** on PATH as `di` (or `npx -y @interop/did-cli`), and
  the wallet the user will approve in open in a browser.

## The script

```
export WAS_SERVER_URL=http://localhost:3002
WALLET=https://wallet.example
```

Draft the page:

```
cat > index.html <<'HTML'
<!doctype html>
<title>Hello</title>
<h1>Published from a terminal.</h1>
HTML
```

Ask the wallet for a grant on the `web` collection:

```
di was request-grant --wallet "$WALLET" \
  --name "demo-publisher" --reason "Publish a demo page" \
  --save --handle agent
```

```
Requesting "web" access for did:key:z6MkAgent...

Open this in your wallet to approve:

  http://localhost:3002/workflows/ephemeral/exchanges/abc-123/protocols?iuv=1

Or open your wallet directly:

  https://wallet.example/#/external/request?url=http%3A%2F%2Flocalhost%3A3002%2F...

Waiting for approval...
```

The user opens the wallet link, sees the agent's DID and reason, and approves
read/write access to one collection named `web`. The command then files the
minted key and the received capability under the handle `agent`:

```
Capability saved to ~/.config/did-cli-wallet/zcaps/urn_uuid_....json
Granted. Use it with --capability agent, for example:
  di was put ./index.html --capability agent --did agent --resource index.html --content-type text/html
ueyJAY29udGV4dCI6...
```

Saving is what makes the grant usable -- `--capability` resolves its signing
key out of the local DID store, so the key and the capability have to persist
together. `--no-save` prints the capability without keeping either half, for
inspecting a grant you do not intend to invoke.

Publish, and read back the public URL:

```
di was put ./index.html --capability agent --did agent \
  --resource index.html --content-type text/html
{
  "id": "index.html",
  "url": "http://localhost:3002/space/8124...cf2e/web/index.html"
}

curl -I http://localhost:3002/space/8124...cf2e/web/index.html
```

A `200` with `content-type: text/html` means the page is live, readable by
anyone, with no authentication. Re-publishing is the same `put` -- a plain
overwrite, until the write grant expires (seven days).

## What the flags do

- `--collection <name>` requests a name other than `web`. A public collection
  is only ever created public: if the user already has a private collection by
  that name, the wallet cannot satisfy the request and the approval comes back
  granting nothing.
- `--action <verb...>` narrows or widens the request (default
  `GET HEAD PUT POST`). The wallet caps what it grants by what the collection
  allows, so asking for more does not get more.
- `--timeout <seconds>` waits longer than the default ten minutes -- though the
  server drops the exchange at ten minutes either way, so a longer wait only
  helps if the server's TTL is configured higher.
- `--did agent` on the `put` matters whenever `WAS_DID` is set: without it the
  write is signed by whatever DID that names, and the server rejects an
  invocation from a DID the capability was not issued to.

## Where the pieces live

- `di was request-grant` -- `src/commands/was/request-grant.ts` (the command)
  and `src/was/request-grant.ts` (the VPR, the exchange, the response parsing).
- The wallet side -- Freewallet's `/external/request` page, which begins the
  exchange, renders the consent panel, and posts the signed capability back.
- The transport -- the WAS server's ephemeral-exchange facet. The routes are
  unauthenticated by design: the exchange URL is itself the secret, and it
  travels point-to-point from the terminal to the user.
