# miniddns

A multi-provider dynamic DNS daemon with an extremely small footprint.
C99 + netlink + BearSSL; static binary ≤ 500 KB, resident RSS ≤ 2.5 MB.

> **Status: implemented (v1.2.0).** Unit, integration, ASan/UBSan and packaging
> gates all pass.
> The implementation follows [`docs/design.md`](docs/design.md)
> (v1.2 + the 1.2.1 BearSSL 0.6 API corrections). That specification is the
> single source of truth; when implementation and specification disagree, the
> actual behaviour is written back into the spec (§04.7).

## What it solves

The public IP of a home or edge device changes. A traditional DDNS client
"curls every 5 minutes", which wakes the CPU continuously and produces a
stream of pointless API requests.

miniddns instead:

- **Kernel edge trigger** — subscribes to rtnetlink address events; while the
  address is unchanged the process blocks in `ppoll` and does not poll.
- **Zero writes** — when the remote record already matches the local address,
  **no write request is sent at all** (an acceptance-grade invariant, not an
  optimisation).
- **No state on disk** — the remote record is the only source of truth; the
  process is stateless and can be restarted or replaced at any time.
- **Fail closed** — a certificate validation failure aborts immediately.
  There is no "skip verification" fallback, because the request carries the
  API token in its headers.

## Design targets

| Dimension | Target | Source |
| --- | --- | --- |
| Memory | resident RSS ≤ 2.5 MB, peak ≤ 6 MB | §01 / §14.5 |
| CPU | ≤ 2 s cumulative over 24 h (no idle spinning) | §01 / §14.5 |
| Size | static binary ≤ 500 KB | §13.2 |
| Latency | first request ≤ 3 s after an address change | §05.3 |
| Writes | 0 write requests in 24 h when the IP is unchanged | §14.4 |

## Documentation map

| What you need | Where to read |
| --- | --- |
| Decide whether the design is viable | [`docs/design.md`](docs/design.md) §01, §16 |
| Start implementing | `docs/design.md` §02–§09, §13.1, §14.1 |
| Packaging / operations | `docs/design.md` §03, §11, §12, §13.3, §14.5 |
| What changed since v1.1 | [`docs/review-design-v1.1.md`](docs/review-design-v1.1.md) |
| Verify the original wording | [`docs/archive/design-v1.1.html`](docs/archive/design-v1.1.html) (read-only snapshot) |
| Changelog | [`CHANGELOG.md`](CHANGELOG.md) |
| Implementation and acceptance report | [`docs/DELIVERY.md`](docs/DELIVERY.md) |
| Repository rules (language, contributions) | [`CONTRIBUTING.md`](CONTRIBUTING.md) |
| Third-party licenses | [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) |

## Build and verification

```bash
make                 # dynamic build (development / self-test)
make static          # static artifact; override the toolchain with STATIC_CC=<musl-gcc> for the ≤500 KB budget
make test            # unit tests + TLS mock integration tests
make test-asan       # unit tests under ASan/UBSan
make spec-check      # specification consistency (defaults / cross refs / symbols / install paths)
make verify-units    # systemd template vs. generated unit
make dist            # dist/miniddns-$(VERSION)-$(ARCH)-musl/
```

```bash
miniddns --print-ip                                    # detect only; no provider, no token
miniddns --check-config -c /etc/miniddns/miniddns.conf
miniddns --check-ca -c /etc/miniddns/miniddns.conf    # CA + TLS handshake self-test, zero request bytes
miniddns --dry-run -c /etc/miniddns/miniddns.conf     # full cycle, no remote writes
```

> File owner/mode validation follows §03: config and CA bundles must be owned
> by root and must not be group/world writable; token files must not be
> symlinks. On a development machine whose files are not root-owned, add
> `--allow-non-root-owner` to diagnostic commands (test only; it emits a warning).

Third-party code is vendored as source: `third_party/bearssl/`
(BearSSL 0.6, MIT) and `third_party/jsmn/` (MIT). Their license texts are
shipped in `LICENSES/` by `make dist`; see
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).

## Explicit non-goals

No periodic polling loop, no Web UI, no multithreading, no state file, no
MX/TXT/CAA management, no HTTP proxy support, no TLS 1.3. The complete list
is in §01 "Non-goals".

## Contributing / repository rules

**All interactions with GitHub must be in English** (commit messages, branch
names, pull requests, issues, comments, reviews, release notes), and
**this README must be written in English**. See
[`CONTRIBUTING.md`](CONTRIBUTING.md) for the full rule and its scope.

## License

MIT, see [`LICENSE`](LICENSE). The vendored BearSSL and jsmn are also MIT;
their copyright notices are in
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) and must be included in
any distributed artifact.
