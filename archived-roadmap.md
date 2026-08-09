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
