#!/bin/sh
# miniddns installer (design.md §12.3). Idempotent; never clobbers user config
# or creates token files; never calls `systemctl enable --now`.
set -eu

PREFIX=/opt/miniddns
BINDIR=""
DOCDIR=""
SYSCONFDIR=/etc/miniddns
SYSTEMD_DIR=/etc/systemd/system
LINK_BIN=0
NO_SYSTEMD=0

usage() {
    cat <<'EOF'
usage: install.sh [options]
  --prefix DIR        install root (default /opt/miniddns)
  --bindir DIR        binary dir (default <prefix>/bin)
  --docdir DIR        documentation dir (default <prefix>/doc)
  --sysconfdir DIR    config dir (default /etc/miniddns)
  --systemd-dir DIR   systemd unit dir (default /etc/systemd/system)
  --link-bin          symlink /usr/local/bin/miniddns -> <bindir>/miniddns
  --no-systemd        do not daemon-reload / verify (for tests, containers)
  -h, --help          this help
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --prefix) PREFIX=$2; shift 2 ;;
        --bindir) BINDIR=$2; shift 2 ;;
        --docdir) DOCDIR=$2; shift 2 ;;
        --sysconfdir) SYSCONFDIR=$2; shift 2 ;;
        --systemd-dir) SYSTEMD_DIR=$2; shift 2 ;;
        --link-bin) LINK_BIN=1; shift ;;
        --no-systemd) NO_SYSTEMD=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "install.sh: unknown option: $1" >&2; usage; exit 1 ;;
    esac
done

[ -n "$BINDIR" ] || BINDIR="$PREFIX/bin"
[ -n "$DOCDIR" ] || DOCDIR="$PREFIX/doc"

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# artifact root (dist) vs. source checkout
if [ -f "$SCRIPT_DIR/bin/miniddns" ]; then
    ROOT=$SCRIPT_DIR
    BIN_SRC="$SCRIPT_DIR/bin/miniddns"
elif [ -f "$SCRIPT_DIR/build/miniddns" ]; then
    ROOT=$SCRIPT_DIR
    BIN_SRC="$SCRIPT_DIR/build/miniddns"
else
    echo "install.sh: cannot find bin/miniddns or build/miniddns next to this script" >&2
    exit 1
fi

echo "miniddns install: prefix=$PREFIX bindir=$BINDIR confdir=$SYSCONFDIR docdir=$DOCDIR"

install -Dm0755 "$BIN_SRC" "$BINDIR/miniddns"

# 1. NEVER install conf/miniddns.conf (it would shadow /etc/miniddns/miniddns.conf).
if [ -f "$ROOT/conf/miniddns.conf.example" ]; then
    install -Dm0644 "$ROOT/conf/miniddns.conf.example" "$PREFIX/conf/miniddns.conf.example"
fi
# 2. NEVER create or overwrite a token file.
if [ -f "$ROOT/ca/ca-certificates.crt" ]; then
    install -Dm0644 "$ROOT/ca/ca-certificates.crt" "$PREFIX/ca/ca-certificates.crt"
fi
if [ -f "$ROOT/ca/README" ]; then
    install -Dm0644 "$ROOT/ca/README" "$PREFIX/ca/README"
fi
if [ -f "$ROOT/doc/design.md" ]; then
    install -Dm0644 "$ROOT/doc/design.md" "$DOCDIR/design.md"
elif [ -f "$ROOT/docs/design.md" ]; then
    install -Dm0644 "$ROOT/docs/design.md" "$DOCDIR/design.md"
fi
if [ -f "$ROOT/doc/design.html" ]; then
    install -Dm0644 "$ROOT/doc/design.html" "$DOCDIR/design.html"
fi
if [ -f "$ROOT/THIRD_PARTY_NOTICES.md" ]; then
    install -Dm0644 "$ROOT/THIRD_PARTY_NOTICES.md" "$PREFIX/THIRD_PARTY_NOTICES.md"
fi

# 3. Generate the unit from the template with the chosen paths.
if [ -f "$ROOT/systemd/miniddns.service.in" ]; then
    install -Dd "$SYSTEMD_DIR"
    sed -e "s|@BINDIR@|$BINDIR|g" \
        -e "s|@CONFDIR@|$SYSCONFDIR|g" \
        -e "s|@DOCDIR@|$DOCDIR|g" \
        "$ROOT/systemd/miniddns.service.in" > "$SYSTEMD_DIR/miniddns.service.tmp"
    chmod 0644 "$SYSTEMD_DIR/miniddns.service.tmp"
    mv -f "$SYSTEMD_DIR/miniddns.service.tmp" "$SYSTEMD_DIR/miniddns.service"
elif [ -f "$ROOT/systemd/miniddns.service" ]; then
    install -Dm0644 "$ROOT/systemd/miniddns.service" "$SYSTEMD_DIR/miniddns.service"
fi
# NOTE: user-nonroot.conf is deliberately NOT installed (§12.3).

if [ "$LINK_BIN" -eq 1 ]; then
    if [ -w /usr/local/bin ] || [ "$(id -u)" = "0" ]; then
        ln -sfn "$BINDIR/miniddns" /usr/local/bin/miniddns
        echo "  linked /usr/local/bin/miniddns -> $BINDIR/miniddns"
    else
        echo "  WARN: /usr/local/bin not writable, skipped --link-bin" >&2
    fi
fi

echo ""
echo "installed:"
echo "  binary  : $BINDIR/miniddns"
echo "  config  : $PREFIX/conf/miniddns.conf.example (copy to $SYSCONFDIR/miniddns.conf)"
echo "  ca      : $PREFIX/ca/ca-certificates.crt"
echo "  docs    : $DOCDIR/design.md"
echo "  unit    : $SYSTEMD_DIR/miniddns.service"
echo ""
echo "next steps:"
echo "  1) mkdir -p $SYSCONFDIR && cp $PREFIX/conf/miniddns.conf.example $SYSCONFDIR/miniddns.conf"
echo "  2) write your API token to $SYSCONFDIR/cloudflare.token and chmod 600"
echo "     (install.sh never creates or overwrites token files)"
echo "  3) $BINDIR/miniddns --check-config -c $SYSCONFDIR/miniddns.conf"
echo "     $BINDIR/miniddns --check-ca -c $SYSCONFDIR/miniddns.conf"
echo "  4) systemctl daemon-reload && systemctl enable --now miniddns"
echo ""
if [ ! -f "$SYSCONFDIR/miniddns.conf" ]; then
    echo "WARN: $SYSCONFDIR/miniddns.conf does not exist yet — the service will fail with E_CFG until step 1 is done." >&2
fi
echo "NOTE: install.sh does NOT enable/start the service (config is not filled yet)."

if [ "$NO_SYSTEMD" -eq 0 ]; then
    if command -v systemd-analyze >/dev/null 2>&1; then
        systemd-analyze verify "$SYSTEMD_DIR/miniddns.service" >/dev/null 2>&1 \
            || echo "WARN: systemd-analyze verify reported issues (non-fatal)" >&2
    fi
    if command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reload >/dev/null 2>&1 \
            || echo "WARN: systemctl daemon-reload failed (non-fatal)" >&2
    fi
fi
