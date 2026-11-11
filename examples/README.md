# Configuration and service examples

These files are examples only. None of them is installed as an active config
by `install.sh`, and none of them contains a real API token.

| File | Purpose |
| --- | --- |
| `miniddns.conf.minimal.example` | Smallest working config: one provider, one A record, IPv4 from an echo endpoint. |
| `miniddns.conf.multi-instance.example` | Two independent instances: separate `instance`, `lock_file` and config files. |
| `../conf/miniddns.conf.example` | Canonical template shipped in `conf/`; see `../conf/README.md`. |
| `../systemd/miniddns.service.in` | systemd unit template with `@BINDIR@`, `@CONFDIR@`, `@DOCDIR@`. |
| `../systemd/miniddns.service` | Generated unit for the default `/opt/miniddns` prefix; safe to copy directly. |
| `../systemd/miniddns.service.d/user-nonroot.conf` | Drop-in for running as a non-root user (read §12.4 first). |
| `../openwrt/files/miniddns.init` | OpenWrt procd service script. |
| `../install.sh` | Idempotent installer; never creates a config or token file. |

## Quick start

```bash
sudo mkdir -p /etc/miniddns
sudo install -m 0640 examples/miniddns.conf.minimal.example /etc/miniddns/miniddns.conf
sudo sh -c 'echo YOUR_TOKEN > /etc/miniddns/cloudflare.token'
sudo chmod 0600 /etc/miniddns/cloudflare.token
miniddns --check-config -c /etc/miniddns/miniddns.conf
miniddns --check-ca -c /etc/miniddns/miniddns.conf
miniddns --dry-run -c /etc/miniddns/miniddns.conf
```

## Multi-instance

Each instance needs its own config file, its own `instance` name and its own
lock file (the lock file name contains `instance`, see §04.2). Run one systemd
unit per instance, for example `miniddns@home.service`, each with
`--config /etc/miniddns/<name>.conf` and its own `RuntimeDirectory`. The stock
`miniddns.service` is not parameterised and manages a single instance.
