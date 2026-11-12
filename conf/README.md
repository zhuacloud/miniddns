# Configuration files

`miniddns.conf.example` is the canonical configuration template. It is the
**only** configuration file shipped in a release artifact: a real
`miniddns.conf` is deliberately never packaged, because a bundled
`conf/miniddns.conf` would shadow the operator's `/etc/miniddns/miniddns.conf`
(see `docs/design.md` §03).

## Install

```bash
install -Dm0640 miniddns.conf.example /etc/miniddns/miniddns.conf
# edit it, then verify
miniddns --check-config -c /etc/miniddns/miniddns.conf
```

## File ownership and permissions

| File | Mode | Owner |
| --- | --- | --- |
| `/etc/miniddns/` | `0750` | `root:root` |
| `/etc/miniddns/miniddns.conf` | `0640` | `root:root` |
| `/etc/miniddns/cloudflare.token` | `0600` | `root:root` |

The daemon refuses to start when the config, CA bundle or token file is
group/world writable, when it is not owned by root, or when the token file is
a symlink. `--allow-non-root-owner` relaxes only the owner check and is
intended for tests.

## Credentials

Prefer `token_file = /etc/miniddns/cloudflare.token`. With systemd credentials,
use `token_file = $CREDENTIALS_DIRECTORY/cloudflare.token` and enable the
commented `LoadCredential=` line in the unit. Diagnostic commands still work
when `$CREDENTIALS_DIRECTORY` is unset (they warn and skip credential checks).

## More examples

See `examples/` inside the release tarball for a minimal config and a
multi-instance config, and `systemd/` / `openwrt/` for service configuration
examples. Example files are never uploaded as individual release assets.
