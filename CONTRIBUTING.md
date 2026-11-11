# Contributing and repository rules

This file defines the language policy for the repository's public surface.
It is part of the project specification and is enforced by `make spec-check`.

## Rule 1 — All interactions with GitHub must be in English

Every piece of content created on or sent to GitHub **MUST** be written in
English. This includes, but is not limited to:

- commit messages (subject and body),
- branch and tag names,
- pull request titles and descriptions,
- issues and issue comments,
- code review comments and suggestions,
- GitHub Discussions posts,
- release notes and release descriptions,
- workflow names, job/step labels and any other text rendered by the GitHub UI,
- repository description, topics and README badges text.

Rationale: GitHub is the project's public, searchable surface. A single
language keeps it consistent, greppable and reviewable by every contributor
and by automation.

## Rule 2 — `README.md` must be in English

The top-level `README.md` is the project's entry point on GitHub and **MUST**
be written in English. All future edits must keep it English. `make spec-check`
fails if CJK characters appear in it.

## Scope and exceptions

This policy covers **GitHub interactions and the README**, not the whole
repository. The following keep their original language and must **not** be
translated, because they are internal/historical records whose exact wording
is part of the specification:

- `docs/design.md` — the single authoritative implementation specification
  (v1.2 + 1.2.1 corrections); translating it would break §04.7 traceability
  and the archived-wording checks.
- `docs/archive/design-v1.1.html` — read-only snapshot with a fixed SHA-256.
- `docs/review-design-v1.1.md` — historical review conclusions.
- `docs/DELIVERY.md`, `CHANGELOG.md` — internal engineering records.
- Comments inside `conf/`, `systemd/` and `openwrt/` example files.

Code identifiers, log fields (`key=value`), CLI flags and structured log
messages are English by design (§10) and remain unchanged.

## Enforcement

```bash
make spec-check
```

The check verifies that `README.md` contains no CJK characters, that this
file exists, and that it states the English-only GitHub rule. CI should run
`make spec-check` together with `make verify-units` and `make test`.

## Technical contributions

- Read `docs/design.md` before changing behaviour; when the implementation
  disagrees with the spec, update the spec (§04.7) and add a revision entry.
- Run `make test`, `make test-asan` and `make dist` before opening a pull
  request.
- Keep the zero-write invariant intact: no write request when the IP is
  unchanged.
