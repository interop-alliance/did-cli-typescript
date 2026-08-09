# Agent Guidelines

Agent-facing guide for `@interop/did-cli`. Code style, contribution, and
command-test conventions live in @CONTRIBUTING.md -- follow them.

For a map of the codebase -- entry point, the command-factory pattern, module
layout, and the command surface -- see [ARCHITECTURE.md](ARCHITECTURE.md).

For the on-disk wallet/DID layout (and `di did meta <did>`, which prints each
DID artifact's path at runtime), see [STORAGE.md](STORAGE.md).

## Roadmap & Task Conventions

All roadmap tracking lives in [ROADMAP.md](./ROADMAP.md): narrative context
(section preambles) plus structured work items. Never create a parallel task
list elsewhere (no `TODO.md`, no task lists in other docs).

Each work item follows this schema:

- A heading `### CLI-N: Title`, then a field block, then free prose context.
- Fields: `status` (`todo` / `in-progress` / `draft` / `done`), `priority`
  (`high` / `medium` / `low`), `labels` (comma-separated), optional `blocked-by`
  (other `CLI-N` ids), and an `acceptance:` checklist.
- `draft` marks items with no actionable done-state yet (blocked or parking
  records); a draft states _why_ instead of acceptance criteria and must gain
  acceptance criteria when promoted to `todo`.

Rules:

- Item ids are permanent and never reused. A new item takes the next unused
  number, regardless of which section it lands in.
- Every non-draft item needs acceptance criteria before it may be moved to
  `in-progress`.
- Statuses are edited in place (change the `status:` field); acceptance
  checkboxes are ticked as they are met.
- **Completing an item includes archiving it**: in the same pass that marks it
  `done`, move it verbatim (number, title, field block, prose, plus its `done`
  date) from ROADMAP.md to [archived-roadmap.md](./archived-roadmap.md),
  append-only at the bottom -- this keeps CLI-N references resolvable. A `done`
  item left in ROADMAP.md is an unfinished task. CHANGELOG.md remains the
  permanent record of what landed; do not rewrite or summarize items on the
  way in, and do not fix old references.
- Work discovered mid-implementation gets its own item immediately, noting
  `discovered-from: CLI-N` in its prose, plus a `blocked-by` link if it blocks
  anything.
- Reference item ids in commit messages and PR descriptions where relevant
  (e.g. `CLI-1: add edv insert command`).
- `blocked-by` links only express dependencies implied by the work itself; do
  not invent orderings.

## Recipes

### Host a did:webvh in a WAS space

A `did:webvh` resolver fetches the history log from `<url>/did.jsonl`, where
`<url>` is the address the DID was created for. WAS only serves a resource at a
three-segment path (`space/<id>/<collection>/<resource>`), so host the log by
creating the DID against a **collection** URL, not the bare space URL -- then
`<url>/did.jsonl` lands on a real resource:

```
di was space create --name Demo --did alice --save --handle demo   # -> space/<id>
di was collection create demo --name "DID log" --id did            # -> space/<id>/did

# Mint the DID for the collection URL; its log must then live at
# space/<id>/did/did.jsonl  (== <url>/did.jsonl).
di did create webvh --url https://<server>/space/<id>/did --save
LOG=$(di did meta <the new did> --json | node -p 'JSON.parse(require("fs").readFileSync(0)).files.log')

di was put demo/did/did.jsonl "$LOG"   # upload the log
di was publish demo/did/did.jsonl      # resolution is an unauthenticated GET
di did get <the new did>               # resolves the live did:webvh
```

Gotchas: the log resource must be **published** (an unpublished resource returns
404 to the resolver), and let `was put` auto-detect the content type for the log
(the reference server rejects an explicit `application/jsonl`).
