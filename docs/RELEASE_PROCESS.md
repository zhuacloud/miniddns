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

## 2. Platform matrix

Every release produces **eight** Linux packages: four architectures times two
C libraries. Cross compilation is done with Zig (`zig cc -target ...`), which
supplies the kernel UAPI headers for all targets, so no QEMU or sysroot is
needed on the runner.

| Architecture | Label | musl target | glibc target | musl binary | glibc binary |
| --- | --- | --- | --- | --- | --- |
| x86 32-bit | `x86` | `x86-linux-musl` | `x86-linux-gnu` | static | dynamic (glibc) |
| x86 64-bit | `x64` | `x86_64-linux-musl` | `x86_64-linux-gnu` | static | dynamic (glibc) |
| ARM 32-bit | `arm32` | `arm-linux-musleabihf` | `arm-linux-gnueabihf` | static | dynamic (glibc) |
| ARM 64-bit | `arm64` | `aarch64-linux-musl` | `aarch64-linux-gnu` | static | dynamic (glibc) |

Artifact id / tarball name:

```
miniddns-<version>-linux-<arch>-<libc>.tar.gz
```

- **musl** packages are fully static (`ldd` reports "not a dynamic
  executable"); they are the recommended choice for embedded systems.
- **glibc** packages are dynamically linked against glibc and expect a
  compatible glibc on the target. `scripts/verify_release_artifacts.py`
  asserts that musl builds have no `PT_INTERP` and glibc builds do.

## 3. How to trigger a release

GitHub → **Actions** → **Release** → **Run workflow**:

| Input | Required | Description |
| --- | --- | --- |
| `version` | yes | `0.0.1` or `0.0.1-rc1` |
| `dry_run` | no (default `false`) | Validate and build all eight packages, preview notes, but do **not** create a tag, push commits or publish a release. |

Requirements before triggering:

- Run from the `main` branch (the workflow refuses any other ref).
- CI must be green on `main` (`.github/workflows/ci.yml`).
- The tag must not already exist. If a run fails after the tag was pushed,
  delete the tag deliberately or use a new `-rcN` number; re-running the same
  version is rejected with an English error message.
- The repository must allow GitHub Actions to push commits
  (`permissions: contents: write`). If branch protection blocks the changelog
  commit, configure an exception for `github-actions[bot]`.

## 4. Pipeline (`.github/workflows/release.yml`)

The workflow performs exactly these steps, in order:

1. **Validate** the version input and derive the prerelease flag.
2. **Create and push the tag** (`git tag -a <version> -m "Release <version>"`).
3. **Auto build**: download Zig, then `make`, `make spec-check`,
   `make verify-units`, `make test`, `make test-asan`, followed by
   `make dist` for each of the eight platform/libc combinations. Each
   `make dist` produces a self-contained prefix directory and runs the
   artifact verification gate; each directory is packed into a `.tar.gz`.
4. **Generate the changelog**: `scripts/gen_changelog.py` collects
   Conventional Commit subjects since the previous tag, groups them into
   Added / Fixed / Performance / Documentation / Internal / Changed, writes an
   English section into `CHANGELOG.md` (below the
   `<!-- generated-release-sections -->` marker) and writes
   `build/RELEASE_NOTES.md`. The changelog update is committed to `main` with
   an English `chore(release): update changelog for <version>` message. The
   tag intentionally points at the release source commit; the changelog commit
   is a docs-only follow-up.
5. **Aggregate checksums**: one `SHA256SUMS` covering all eight tarballs.
6. **Publish** the GitHub Release with `gh release create --verify-tag`.
   `-rcN` versions get `--prerelease`; stable versions get `--latest`.
   **Only the eight tarballs and `SHA256SUMS` are uploaded.** The install
   script, configuration examples and service configuration examples live
   exclusively inside each tarball; they are never loose release assets.
7. Write an English summary to the workflow run summary.

`dry_run=true` executes steps 1 and 3–5, prints the generated notes into the
run summary, and skips steps 2, 6 and the changelog commit/push.

## 5. Release artifact structure

Each tarball extracts to **one directory that is a complete install prefix**.
An operator only has to copy it to `/usr/local` or `/opt`, then configure it —
no additional files are needed:

```
miniddns-<version>-linux-<arch>-<libc>/
├── README.md                         # layout + quick start (copy to /opt)
├── bin/miniddns                      # runnable binary
├── conf/
│   ├── miniddns.conf.example         # configuration example
│   └── README.md                     # install / permission instructions
├── examples/                         # extra configuration examples
│   ├── README.md
│   ├── miniddns.conf.minimal.example
│   └── miniddns.conf.multi-instance.example
├── install.sh                        # idempotent installer
├── systemd/                          # server configuration examples
│   ├── miniddns.service              # generated unit, copy directly
│   ├── miniddns.service.in           # template with @BINDIR@/@CONFDIR@/@DOCDIR@
│   └── miniddns.service.d/user-nonroot.conf
├── openwrt/                          # server configuration example (procd)
│   ├── Makefile                      # DEPENDS:=+ca-bundle
│   └── files/miniddns.init
├── ca/
│   ├── ca-certificates.crt           # fallback CA snapshot
│   └── README                        # snapshot date + sha256 + source
├── doc/
│   ├── design.md                     # authoritative specification
│   └── design.html                   # optional (requires pandoc)
├── LICENSES/
│   ├── miniddns-MIT.txt
│   ├── THIRD_PARTY_NOTICES.md
│   ├── bearssl-MIT.txt
│   └── jsmn-MIT.txt
├── THIRD_PARTY_NOTICES.md
└── SHA256SUMS                        # checksum of every file above
```

Typical use:

```bash
tar -xzf miniddns-0.0.1-linux-x64-musl.tar.gz -C /opt
cp -a /opt/miniddns-0.0.1-linux-x64-musl /opt/miniddns
# or run the bundled installer
cd /opt/miniddns-0.0.1-linux-x64-musl && sudo ./install.sh --prefix /opt/miniddns
```

`ARTIFACT_README.md` in the repository is the source of the tarball's
`README.md`.

### Verification

`scripts/verify_release_artifacts.py` (called by `make dist`) asserts:

- the directory name is `miniddns-<version>-linux-<arch>-<libc>`;
- only the allowed top-level entries exist (no stray files);
- every required file exists, is non-empty, and the binary / install script /
  procd script are executable;
- musl builds are static ELF and glibc builds are dynamic ELF;
- `bin/miniddns --version` (native builds) or the embedded version string
  (cross builds) matches `VERSION`;
- every file is listed in `SHA256SUMS` and every checksum matches;
- **no** `miniddns.conf`, `*.token`, `.git*` or `build/` directory is present;
- the `LICENSES/` MIT notices are present.

A real `miniddns.conf` and token files are never packaged: a bundled config
would shadow `/etc/miniddns/miniddns.conf` (§03) and credentials must never
leave the operator's machine.

## 6. Continuous integration (`.github/workflows/ci.yml`)

On every push/PR to `main` (and on manual dispatch), CI:

- downloads Zig;
- builds with `make -j"$(nproc)"`;
- runs `make spec-check`, `make verify-units`, `make test` and
  `make test-asan`;
- builds the two native x64 packages (`musl` and `glibc`) with
  `make dist` to verify the artifact structure and manifest gate;
- uploads those tarballs as build artifacts (nothing is published).

## 7. Changelog policy

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

## 8. Local reproduction

```bash
make version-check VERSION=0.0.1        # stable
make version-check VERSION=0.0.1-rc1    # release candidate

# one package (native musl)
make dist VERSION=0.0.1 TARGET_ARCH=x64 LIBC=musl \
     ZIG_TARGET=x86_64-linux-musl ZIG=/path/to/zig

# all eight packages
for spec in \
  "x86 x86-linux-musl musl" "x86 x86-linux-gnu glibc" \
  "x64 x86_64-linux-musl musl" "x64 x86_64-linux-gnu glibc" \
  "arm32 arm-linux-musleabihf musl" "arm32 arm-linux-gnueabihf glibc" \
  "arm64 aarch64-linux-musl musl" "arm64 aarch64-linux-gnu glibc"; do
  set -- $spec
  make dist VERSION=0.0.1 TARGET_ARCH="$1" LIBC="$3" \
       ZIG_TARGET="$2" ZIG=/path/to/zig
done
```

Without `ZIG_TARGET`, `make dist` uses the host compiler (`cc` / `musl-gcc`)
and defaults to `TARGET_ARCH=x64 LIBC=musl`.

## 9. Failure handling

| Failure | Action |
| --- | --- |
| Invalid version | Fix the input; nothing was created. |
| Tag already exists | Choose a new version or delete the tag deliberately. |
| Build/test failure | CI should have caught it; fix `main`, then release with a new `-rcN`. |
| Publish failure after tag | Re-run is blocked by the existing tag; fix the cause and either delete the tag deliberately or release a new `-rcN`. The tarballs can still be recovered from the workflow run. |
| Changelog push blocked | Allow `github-actions[bot]` to push to `main` or commit the changelog manually with an English message; the release itself still succeeds. |
