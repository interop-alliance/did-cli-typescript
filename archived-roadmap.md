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
