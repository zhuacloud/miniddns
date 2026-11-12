# miniddns — release artifact

This directory is a **self-contained install prefix**. Everything needed to
run and configure the daemon is inside it: the binary, the configuration
example, the install script, the systemd/OpenWrt service configuration
examples, the fallback CA bundle, documentation and license notices. Nothing
else needs to be downloaded.

The directory name encodes the platform:

```
miniddns-<version>-linux-<arch>-<libc>/
    arch : x86 | x64 | arm32 | arm64
    libc : musl (fully static) | glibc (dynamically linked against glibc)
```

## Quick start (copy to /opt or /usr/local)

```bash
# Pick the tarball that matches your machine, then:
sudo tar -xzf miniddns-<version>-linux-<arch>-<libc>.tar.gz -C /opt
sudo cp -a /opt/miniddns-<version>-linux-<arch>-<libc> /opt/miniddns

# Configure
sudo mkdir -p /etc/miniddns
sudo install -m 0640 /opt/miniddns/conf/miniddns.conf.example \
                     /etc/miniddns/miniddns.conf
sudo sh -c 'echo YOUR_CLOUDFLARE_TOKEN > /etc/miniddns/cloudflare.token'
sudo chmod 0600 /etc/miniddns/cloudflare.token

# Verify
/opt/miniddns/bin/miniddns --check-config -c /etc/miniddns/miniddns.conf
/opt/miniddns/bin/miniddns --check-ca    -c /etc/miniddns/miniddns.conf
/opt/miniddns/bin/miniddns --dry-run     -c /etc/miniddns/miniddns.conf
```

Alternatively run the bundled installer (it never creates a config or token
file and never enables the service automatically):

```bash
cd /opt/miniddns-<version>-linux-<arch>-<libc>
sudo ./install.sh --prefix /opt/miniddns --sysconfdir /etc/miniddns
```

## Layout

| Path | Contents |
| --- | --- |
| `bin/miniddns` | The daemon binary. |
| `conf/miniddns.conf.example` | Canonical configuration example. |
| `conf/README.md` | Install instructions and the file-ownership matrix. |
| `examples/` | Minimal and multi-instance configuration examples. |
| `install.sh` | Idempotent installer for this prefix. |
| `systemd/miniddns.service` | Generated unit for the default prefix; copy directly. |
| `systemd/miniddns.service.in` | Unit template with `@BINDIR@`/`@CONFDIR@`/`@DOCDIR@`. |
| `systemd/miniddns.service.d/user-nonroot.conf` | Optional non-root drop-in (read §12.4 first). |
| `openwrt/` | OpenWrt source-feed recipe (`PKG_SOURCE`), README and procd service script. The recipe is not used to build this binary artifact. |
| `ca/ca-certificates.crt`, `ca/README` | Fallback CA snapshot and its provenance. |
| `doc/design.md` | Authoritative design specification. |
| `LICENSES/`, `THIRD_PARTY_NOTICES.md` | MIT license notices for miniddns, BearSSL and jsmn. |
| `SHA256SUMS` | Checksum of every file in this directory. |

Verify the download before use:

```bash
sha256sum -c SHA256SUMS
```

## Which package should I use?

- **musl** builds are fully static and portable across Linux distributions;
  they are the recommended choice for embedded/OpenWrt systems.
- **glibc** builds are dynamically linked and expect a compatible glibc on
  the target system; they are the natural choice on glibc distributions.

If unsure, check your libc with `ldd --version` (glibc) or `apk info musl`
(Alpine/musl).

A real `miniddns.conf` and any token file are intentionally **not** included:
a bundled config would shadow `/etc/miniddns/miniddns.conf`, and credentials
must never be distributed.
