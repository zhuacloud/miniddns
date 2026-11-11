# Release process

This document defines the packaging and publishing process for miniddns. It
is part of the project specification. All GitHub interactions, generated
changelog entries, release notes, tags and workflow steps are written in
English (see `CONTRIBUTING.md`). Internal specification documents keep their
original language.

## 1. Version scheme

A release version is a SemVer string with an optional release-candidate
suffix:

| Kind | Format | Example | GitHub Release |
| --- | --- | --- | --- |
| Stable | `X.Y.Z` | `0.0.1` | `prerelease=false`, marked **latest** |
| Release candidate | `X.Y.Z-rcN` | `0.0.1-rc1` | `prerelease=true`, never **latest** |

Strict validation pattern (enforced by `scripts/gen_changelog.py`):

```
^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(-rc[1-9]\d*)?$
```

Notes:

- The git tag is **exactly** the version string (no `v` prefix): `0.0.1`,
  `0.0.1-rc1`. Tags are annotated.
- RC ordering follows SemVer (`0.0.1-rc1` < `0.0.1-rc2` < `0.0.1`). A stable
  release is a separate workflow run with the plain `X.Y.Z` version; an RC is
  never silently promoted.
- `VERSION` is injected into `MN_VERSION` at compile time, so
  `miniddns --version`, the `User-Agent` header, the dist directory name, the
  tarball name and the release tag all agree. Check with `make version`.

## 2. How to trigger a release

GitHub → **Actions** → **Release** → **Run workflow**:

| Input | Required | Description |
| --- | --- | --- |
| `version` | yes | `0.0.1` or `0.0.1-rc1` |
| `dry_run` | no (default `false`) | Validate, build and preview notes **without** creating a tag, pushing commits or publishing a release. |

Requirements before triggering:

- Run from the `main` branch (the workflow refuses any other ref).
- CI must be green on `main` (`.github/workflows/ci.yml`).
- The tag must not already exist. If a run fails after the tag was pushed,
  delete the tag deliberately or use a new `-rcN` number; re-running the same
  version is rejected with an English error message.
- The repository must allow GitHub Actions to push commits
  (`permissions: contents: write`). If branch protection blocks the changelog
  commit, configure an exception for `github-actions[bot]`.

## 3. Pipeline (`.github/workflows/release.yml`)

The workflow performs exactly these steps, in order:

1. **Validate** the version input and derive the prerelease flag.
2. **Create and push the tag** (`git tag -a <version> -m "Release <version>"`).
3. **Auto build**: install `musl-tools`, then `make`, `make spec-check`,
   `make verify-units`, `make test`, `make test-asan`, and
   `make dist VERSION=<version>`. `make dist` produces the artifact tree and
   runs the artifact verification gate.
4. **Generate the changelog**: `scripts/gen_changelog.py` collects
   Conventional Commit subjects since the previous tag, groups them into
   Added / Fixed / Performance / Documentation / Internal / Changed, writes an
   English section into `CHANGELOG.md` (below the
   `<!-- generated-release-sections -->` marker) and writes
   `build/RELEASE_NOTES.md`. The changelog update is committed to `main` with
   an English `chore(release): update changelog for <version>` message. The
   tag intentionally points at the release source commit; the changelog commit
   is a docs-only follow-up.
5. **Package release assets**: tarball of the whole dist tree plus a
   `.sha256` checksum, `SHA256SUMS`, `RELEASE_NOTES.md`, `install.sh`,
   `miniddns.conf.example` and `miniddns.service` as individual assets.
6. **Publish** the GitHub Release with `gh release create --verify-tag`.
   `-rcN` versions get `--prerelease`; stable versions get `--latest`.
7. Write an English summary to the workflow run summary.

`dry_run=true` executes steps 1 and 3–5, prints the generated notes into the
run summary, and skips steps 2, 6 and the changelog commit/push.

## 4. Release artifact manifest

**The release tarball must contain the runnable binary, the configuration
example, the install script and the server configuration examples.** The
complete manifest is enforced by `scripts/verify_release_artifacts.py` (called
by `make dist` and again by the release workflow):

```
dist/miniddns-<version>-<arch>-musl/
├── bin/miniddns                         # static, stripped runnable binary
├── conf/
│   ├── miniddns.conf.example           # canonical configuration example
│   └── README.md                       # install / permission instructions
├── examples/
│   ├── README.md
│   ├── miniddns.conf.minimal.example
│   └── miniddns.conf.multi-instance.example
├── install.sh                          # idempotent installer
├── systemd/                            # server configuration examples
│   ├── miniddns.service                # generated unit, copy directly
│   ├── miniddns.service.in             # template with @BINDIR@/@CONFDIR@/@DOCDIR@
│   └── miniddns.service.d/user-nonroot.conf
├── openwrt/                            # server configuration example (procd)
│   ├── Makefile                        # DEPENDS:=+ca-bundle
│   └── files/miniddns.init
├── ca/
│   ├── ca-certificates.crt             # fallback CA snapshot
│   └── README                          # snapshot date + sha256 + source
├── doc/
│   ├── design.md                       # authoritative specification
│   └── design.html                     # optional (requires pandoc)
├── LICENSES/
│   ├── miniddns-MIT.txt
│   ├── THIRD_PARTY_NOTICES.md
│   ├── bearssl-MIT.txt
│   └── jsmn-MIT.txt
├── THIRD_PARTY_NOTICES.md
├── install.sh
└── SHA256SUMS                          # checksum of every file above
```

Verification asserts:

- every required file exists, is non-empty, and the binary / install script /
  procd script are executable;
- `bin/miniddns` is a **static** ELF (no `PT_INTERP`);
- `bin/miniddns --version` reports exactly the requested version;
- every file is listed in `SHA256SUMS` and every checksum matches;
- **no** `miniddns.conf`, `*.token`, `.git*` or `build/` directory is present;
- the `LICENSES/` MIT notices are present.

A real `miniddns.conf` and token files are never packaged: a bundled config
would shadow `/etc/miniddns/miniddns.conf` (§03) and credentials must never
leave the operator's machine.

## 5. Continuous integration (`.github/workflows/ci.yml`)

On every push/PR to `main` (and on manual dispatch), CI:

- installs `musl-tools`;
- builds with `make -j"$(nproc)"`;
- runs `make spec-check`, `make verify-units`, `make test` and
  `make test-asan`;
- runs `make dist VERSION=0.0.0-rc<run_number>` to verify that the full
  artifact tree can be produced and passes the manifest gate;
- uploads `dist/` as a build artifact (nothing is published).

## 6. Changelog policy

- Generated sections are English, per `CONTRIBUTING.md`. Historical sections
  keep their original language.
- New sections are inserted directly below the
  `<!-- generated-release-sections -->` marker, newest first.
- Re-running the generator for the same version replaces that version's
  section instead of duplicating it.
- The release body is `build/RELEASE_NOTES.md`; it includes a compare link
  (`<previous-tag>...<version>`) or a commits link for the first release.
- Commit subjects should follow Conventional Commits so the grouping is
  meaningful.

## 7. Local reproduction

```bash
make version-check VERSION=0.0.1        # stable
make version-check VERSION=0.0.1-rc1    # release candidate
make changelog VERSION=0.0.1            # writes CHANGELOG.md + build/RELEASE_NOTES.md
make dist VERSION=0.0.1 STATIC_CC=<musl-gcc>
make verify-artifacts VERSION=0.0.1
tar -czf miniddns-0.0.1-$(uname -m)-musl.tar.gz \
    -C dist miniddns-0.0.1-$(uname -m)-musl
```

## 8. Failure handling

| Failure | Action |
| --- | --- |
| Invalid version | Fix the input; nothing was created. |
| Tag already exists | Choose a new version or delete the tag deliberately. |
| Build/test failure | CI should have caught it; fix `main`, then release with a new `-rcN`. |
| Publish failure after tag | Re-run is blocked by the existing tag; fix the cause and either delete the tag deliberately or release a new `-rcN`. The dist tree can still be uploaded manually from the workflow artifact. |
| Changelog push blocked | Allow `github-actions[bot]` to push to `main` or commit the changelog manually with an English message; the release itself still succeeds. |
