# `@interop/did-cli` Roadmap -- archived (completed) items

Completed items from [ROADMAP.md](ROADMAP.md), moved here verbatim when they
are marked done so that item-number references (CLI-N) in the active roadmap,
commit messages, and design docs keep resolving. Append-only: newest at the
bottom; do not rewrite or summarize items on the way in. Ids remain permanent
and are never reused. CHANGELOG.md stays the record of *what* landed; this
file preserves each item's acceptance criteria and context.

---

### CLI-6: Pass `priorMeta` to `updateDID` in the update runners

- status: done
- done: 2026-08-09
- priority: low
- labels: webvh, performance
- acceptance:
  - [x] `rotate-keys` and the service-update runner pass the `meta` they just
        resolved via `resolveWebvhForUpdate` as `priorMeta` to `updateDID`,
        skipping its internal full log re-resolution
  - [x] Command tests still pass (regression cover)

`@interop/did-method-webvh@5.2.0` added an opt-in `priorMeta` option on
`updateDID`/`deactivateDID`: trusted prior resolution state that skips the full
log re-verification (O(n) signature checks per update). Both CLI update runners
already resolve the log themselves immediately before calling `updateDID`, so
each command was verifying the whole log twice. Only pass a `meta` resolved
from the same `log` object in the same run -- `priorMeta` is trusted input.

---

### CLI-13: Write at a resource id through a collection-depth capability

- status: done
- done: 2026-08-21
- priority: high
- labels: was, zcap, agents
- touches:
  - freewallet -- none; the wallet's grant is correct as issued. The
    mismatch is entirely on this side
- acceptance:
  - [x] `di was put` accepts a collection-depth `--capability` together
        with a resource id, and writes at that id beneath the capability's
        collection. Either a positional resource id alongside
        `--capability`, or a `--resource <id>` flag; the choice is
        FW-227 section 8 question 9
  - [x] `assertOneAddressing` stops treating a path plus a `--capability`
        as an error for this case, and `disambiguatePayloadArgs` no longer
        silently reads the single positional as the payload file when a
        capability is present
  - [x] The other resource verbs (`get`, `meta`) get the same treatment or
        an explicit refusal message naming the supported form
  - [x] A test PUTs `index.html` under a collection-scoped delegated zcap
        and fetches it back

Discovered by FW-227's 2026-08-21 CLI-lens review, which found the agent
demo's final step unrunnable. A `#public-collection` grant's
`invocationTarget` is a collection URL, but `resolveResourceHandle` refuses
a capability whose depth is not `resource` ("the capability targets a
collection; put needs a resource capability"). `resource add` does accept a
collection capability, but its id is server-generated, so it cannot produce
`index.html`.

Asking the wallet for a resource-scoped grant instead is not an option: a
resource-level target is only expressible as a plain URL under the user's
own Space, and the CLI does not know the Space URL before consent. A
descriptor naming a resource would be a new wire convention needing
sign-off. was-client already supports the right shape --
`Collection.resource(id)` inherits the bound capability and `Resource.put`
takes a content type and upserts -- so this is CLI-side only.

Resolution of FW-227 section 8 question 9, settled here at implementation:
`--resource <id>`, not a positional. The first positional of
`was put [path] [file]` is a WAS address (`SPACE[/COLLECTION[/RESOURCE]]`),
and overloading it with a bare resource id would give one slot two grammars
switched by a flag elsewhere on the line. It also collides with the payload
disambiguation already in place, which reads a lone positional as the
payload file when `--capability` is given: `put --capability z... index.html`
would then have two honest readings, and in this very demo the payload file
and the resource id are the same string. A separate flag keeps every
existing command line meaning what it meant.

That choice makes the second acceptance criterion moot rather than met.
`assertOneAddressing` still rejects a path together with `--capability`, and
`disambiguatePayloadArgs` still reads the lone positional as the payload
file, because both are correct once the resource id has its own flag. The
criterion was written assuming the positional answer; what replaced it is a
set of guards in `resolveResourceHandle`: `--resource` without a capability
is refused, `--resource` alongside a resource-depth capability is refused,
and a collection capability with no `--resource` now names the supported
form instead of refusing flatly.

Also landed with it: `--resource` joins the shell dispatcher's `VALUE_FLAGS`,
without which its value was counted as the payload positional and the
stdin guard let a `put` with no file through to readline.

---

### CLI-8: Write key files with mode 0600

- status: done
- done: 2026-08-21
- priority: high
- labels: keys, security
- acceptance:
  - [x] `src/storage.ts` writes `keys/<id>.json` (and any file carrying a
        secret) with mode `0600`; the atomic temp+rename path keeps the mode
  - [x] Existing files are not migrated (greenfield stance); a one-line
        note in README
  - [x] A test asserts the mode on a freshly saved key

Today keys are plaintext Multikey docs at the default 0644. Wanted
regardless of the demo; the demo makes it pressing because an agent's
saved key sits on the same machine as the agent.

Scope note from FW-227's 2026-08-21 CLI-lens review: this is a change to
the shared storage layer, not to one command. Nothing in `src/storage.ts`
sets a file mode today -- every write goes through the one
`writeFileAtomic` under the ambient umask -- so the change reaches every
stored DID, key, zcap, and space record. The greenfield stance above is
what settles the already-on-disk question; state it in the README note.

### CLI-17: Switch `request-grant` to the re-homed exchange helpers

- status: done
- done: 2026-08-21
- priority: low
- labels: was, agents, cross-repo
- blocked-by: CLI-7
- touches:
  - wallet-core -- WC-129 is the move this item consumes
- acceptance:
  - [x] `src/was/request-grant.ts` imports the exchange create and poll
        helpers from wallet-core's `request` subpath under their post-move
        names, instead of `createOnboardingExchange` /
        `pollOnboardingExchange` from `enrollment`
  - [x] If WC-129's poll ships its own deadline option, the local
        `AbortSignal.timeout` wrapper gives way to it
  - [x] If WC-129 lands a zcap-only VPR builder, `buildCapabilityRequest`
        gives way to it, keeping only the collection-name check and the
        action normalization this CLI needs

discovered-from: CLI-7. WC-129 had not landed when `request-grant` was
written, so it consumes the helpers under their pre-move names. They are
reachable today (the `enrollment` subpath is in wallet-core's export map) and
the poll already takes an `AbortSignal`, so nothing was hand-rolled and
nothing is blocked -- the names are simply wrong for a caller that is not
onboarding a wallet. This is a rename to follow, not a rewrite.

Landed against wallet-core 0.50.0: `createEphemeralExchange` /
`pollEphemeralExchange` and `composeCapabilityRequest` from the `request`
subpath, with the poll's own `timeoutMs` replacing the local
`AbortSignal.timeout` and the gone/timeout dispatch moving to
`EphemeralExchangeGoneError` / `EphemeralExchangeTimeoutError`.
`DEFAULT_TIMEOUT_MS` is now `EPHEMERAL_EXCHANGE_TTL_MS`. The
public-collection descriptor and the action normalization stay local, since
upstream composes queries but does not define this CLI's request shape.

### CLI-7: `di was request-grant`

- status: done
- done: 2026-08-23
- priority: high
- labels: was, zcap, agents
- touches:
  - freewallet -- FW-228 is the wallet entry point this command talks to
    (the interaction-URL handler and the deep-link route); the VPR shape
    and the deep-link path/parameter are signed off in FW-227's design doc
    before either side codes them
  - was-teaching-server -- the ephemeral-exchanges facet
    (`/workflows/ephemeral/exchanges`, 10-minute TTL) as shipped; no
    change
  - wallet-core -- WC-129 re-homes the requester-side exchange helpers and
    supplies the zcap-only VPR builder this command consumes
  - this repo -- CLI-13 (the resource-depth write the returned grant
    needs; done), CLI-8 (key file modes)
- acceptance:
  - [x] `di was request-grant` builds a zcap-only VPR (no
        `DIDAuthentication`, no `domain`) with one
        `AuthorizationCapabilityQuery` entry: a
        `https://w3id.org/byoe#public-collection` descriptor named by
        `--collection` (default `web`), `--action` (default `GET HEAD PUT
        POST`), `--reason`, and `controller` set to the agent's did:key.
        `referenceId` is omitted: it is optional in
        `ICapabilityQueryDetail`, and no consumer reads it back (grants
        correlate positionally by `invocationTarget`)
  - [x] The key is minted inside the command, not passed in. `--save
        --handle <name>` persists the key and the received zcaps under one
        handle, and is required for the demo path: `di was put
        --capability` resolves its signer out of the local key store, so a
        key held only for the run cannot sign the write that follows.
        `--save` defaults on (with `--no-save` to decline), rather than
        performing the first write in-process. The agent's context never
        sees key bytes; stdout carries the handle, the interaction URL,
        and the result
  - [x] POSTs the VPR to the server's exchange facet (`--server`), prints
        the interaction URL, and polls until complete or the exchange
        expires, with a clear timeout message
  - [x] Prints a wallet deep link when `--wallet <url>` is given:
        `<wallet>/external/request?url=<percent-encoded interaction url>`,
        the route decided in FW-227 section 8 question 1 on 2026-08-22. A
        wallet URL that is not absolute http(s) is refused before an
        exchange is opened, and the interaction URL is still printed beside
        the link for a wallet on another device
  - [x] Parses the response VP (unsigned, zcap-only) and stores or prints
        the zcaps in the `z...` base58btc form `--capability` already
        accepts. The zcaps sit at
        `body.response.verifiablePresentation.zcap`
  - [x] Uses was-client handles, nothing re-derived locally. The ecosystem
        rule applies: WAS calls go through was-client handles, not raw
        ezcap `read()`/`write()` (those send `action: read/write`, which
        WAS rejects). Satisfied trivially here: this command makes no WAS
        calls of its own, only unauthenticated exchange-facet requests
  - [x] The exchange create and poll helpers come from wallet-core rather
        than being hand-rolled, which means adding `@interop/wallet-core`
        as a dependency of this package. WC-129 has not landed, so the
        helpers are consumed under their pre-move names from the
        `enrollment` subpath (`createOnboardingExchange` /
        `pollOnboardingExchange`); CLI-17 tracks the switch. The poll's
        existing `signal` option supplies the deadline WC-129 would add.
        There is no generic zcap-only VPR builder upstream, so this
        command owns one
  - [x] Command tests with a stubbed exchange; docs in README and
        ARCHITECTURE's command list

Relationship to App Connect: this is the standalone capability-query path,
not App Connect (which needs a CHAPI-attested origin a CLI does not have).
An optional `--name` (the self-declared agent name) lands with freewallet
FW-231 once its VPR member is signed off.

Landed: the VPR builder, the exchange create/poll, the key minting, the
response parsing, the zcap store write, and the `--wallet` deep link, with
command tests over a stubbed exchange.

`--collection` is passed through unvalidated, deliberately. There is no
WAS-wide collection-id naming rule to check against: the spec requires only
that an id be URL-safe and not collide with a reserved segment, and leaves
format to the implementer. The narrower `/^[a-z0-9][a-z0-9-]{0,63}$/` in
freewallet is that wallet's own grant-time policy for which descriptor names
it will honor, and wallet-core mints `gen-<base64url>` collection ids that
fail it. Checking it here would reject names other wallets grant, so the
wallet stays the authority and an unsatisfiable request comes back granting
nothing, which the command reports.

Scope correction from FW-227's 2026-08-21 CLI-lens review: this command is
larger than "a new command plus the existing `put`". The grant that comes
back is collection-scoped, and `di was put --capability` refuses anything
that is not resource depth. CLI-13 has since landed, so the final write is
`di was put <file> --capability <zcap> --resource <id>`. WC-129 lands before
or with this item, since it is what this command consumes.
The deep-link output was gated on FW-227 section 8 question 1 (the route
path and query parameter), decided 2026-08-22 as
`/external/request?url=<interaction url>` and implemented here on
2026-08-23. The terminal QR is not part of this item at all -- it is
optional, and CLI-14 carries it on its own schedule.

### CLI-9: Claude Code skill + demo README

- status: done
- done: 2026-08-23
- priority: high
- labels: agents, docs
- touches:
  - freewallet -- FW-227 umbrella; the skill's wording of the consent step
    matches the FW-228 page
- acceptance:
  - [x] A skill in this repo that walks an agent through the demo: draft
        `index.html`, `di was request-grant --wallet <url> --save --handle
        agent`, tell the user to approve in the wallet, `di was put
        <space>/web/index.html --capability agent --content-type text/html`,
        print the public URL
  - [x] The skill states the persistence choice (`--save` or not) and never
        asks the agent to print or read key material
  - [x] T2 guidance: when the user has no account, the skill points at the
        wallet's signup and resumes afterwards
  - [x] A demo README with the script and the prerequisites (a Freewallet
        deployment, a teaching server with the exchange facet)

Landed as `.claude/skills/publish-page/SKILL.md` (model-invoked, so the
agent reaches it when the user asks to publish a page) and
`demo/agent-storage/README.md`.

Two corrections to the acceptance text, both from what CLI-13 and CLI-7
actually shipped. The final write is
`di was put ./index.html --capability agent --did agent --resource
index.html --content-type text/html`: a path and a `--capability` cannot be
combined, so the resource id travels in `--resource`, and `--did` names the
minted key so a `WAS_DID` in the environment cannot sign the write instead.
And the no-account tier is FW-227's T1, not T2 (T2 was the bearer-URL
on-ramp, dropped); the skill sends the user to `<wallet>/signup` and resumes.

Persistence is stated as required rather than optional, since
`--capability` resolves its signer out of the local DID store.

### CLI-10: Integration test for `request-grant` against the exchange facet

- status: done (2026-09-14)
- priority: medium
- labels: was, testing, agents
- acceptance:
  - [x] A node integration test runs `request-grant` against a local
        teaching server, with a scripted "wallet" that begins the exchange,
        delegates a public-collection zcap from a root key, and posts the
        VP back; the test then PUTs `index.html` with the stored handle and
        fetches it anonymously as `text/html`
  - [x] Runs in the existing integration tier (server spun up the same way
        as the other `was` integration tests)

Landed as a second case in `src/commands/was.integration.test.ts`. The
scripted wallet uses the same `@interop/wallet-request` helpers freewallet
does (`openInteractionRequest`, `composeVp`, `deliverPresentation`) and
delegates from the space controller's key through the was-client `grant`
primitive. Running it surfaced CLI-18: the delegated write was refused until
the was-client dependency caught up with the server's v0.5 conventions.

Trying the same flow against freewallet.me and freewallet.cloud the same day
turned up three more defects, all fixed in the same pass: the `--wallet` deep
link used the path form where the wallet routes on the fragment, the printed
`encoded` form failed on a wallet-delegated chain (base58 is limited to 2048
bytes, so it is now base64url), and service discovery ran against an origin
that serves a static page (it now runs against the invocation target).

### CLI-18: Consume was-client 0.64 (server v0.5 conventions)

- status: done (2026-09-14)
- priority: high
- labels: was, deps
- acceptance:
  - [x] `@interop/was-client` is at `^0.64.0`, so the root capability id the
        CLI mints for a Space uses the canonical trailing-slash container URL
        and signed requests run service discovery first
  - [x] Both `was` integration tests pass against was-teaching-server 0.35

discovered-from: CLI-10. With was-client 0.60 every delegated invocation
(and the owner's `was rm` of a space) came back as a masked 404 from
was-teaching-server 0.35, because the client still rooted capabilities at
the slash-less `/space/{s}` id that server no longer recognizes. The public
freewallet.cloud deployment runs the same server version, so the bump is
what makes a grant from freewallet.me invocable. The bump itself needed no
source changes.
