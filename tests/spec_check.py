#!/usr/bin/env python3
"""§14.6 spec self-check: defaults ∈ enums, cross refs, defined symbols, install paths."""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DESIGN = os.path.join(ROOT, "docs", "design.md")
HEADER = os.path.join(ROOT, "src", "miniddns.h")
MAKEFILE = os.path.join(ROOT, "Makefile")
UNIT = os.path.join(ROOT, "systemd", "miniddns.service.in")

problems = []
notes = []


def read(p):
    with open(p, "r", encoding="utf-8") as f:
        return f.read()


design = read(DESIGN)
header = read(HEADER)
makefile = read(MAKEFILE)

# 1. every documented default must be a member of its enum ------------------
enum_values = {
    "ipv4_mode": {"off", "iface", "external", "auto"},
    "ipv6_mode": {"off", "iface"},
    "log_level": {"error", "warn", "info", "debug"},
    "log_target": {"journald", "file"},
}
default_rows = re.findall(r"^\|\s*`?([a-z0-9_]+)`?\s*\|\s*([^|]+?)\s*\|", design, re.M)
for key, default in default_rows:
    if key in enum_values:
        d = default.strip().strip("`*").strip()
        if any(ord(ch) > 127 for ch in d):
            continue  # required / auto-detected, not an enum default
        if d.startswith("*"):
            continue  # empty / auto-detected
        if d not in enum_values[key]:
            problems.append("default %s=%s not in %s" % (key, d, sorted(enum_values[key])))
        else:
            notes.append("default %s=%s OK" % (key, d))
if not any(n.startswith("default ipv6_mode") for n in notes):
    problems.append("ipv6_mode default row not found")

# 2. §x.y cross references exist -------------------------------------------
headings = set()
for m in re.finditer(r"^#{2,4}\s+([0-9]{2}(?:\.[0-9]+)*|[A-Z](?:\.[0-9]+)*)\s", design, re.M):
    headings.add(m.group(1))
for m in re.finditer(r"§([0-9]{2}(?:\.[0-9]+)*|[A-Z](?:\.[0-9]+)*)", design):
    ref = m.group(1)
    if ref not in headings:
        problems.append("dangling cross reference §%s" % ref)
notes.append("headings=%d" % len(headings))

# 3. constants / error codes / types defined in the header ------------------
required = [
    "MN_IP_STRLEN", "MN_FQDN_MAX", "MN_ID_MAX", "MN_TOKEN_MAX",
    "MN_MAX_PROVIDERS", "MN_MAX_RECORDS", "MN_CA_MAX_ANCHORS",
    "MN_LIMIT_CA_FILE", "MN_LIMIT_CONF_FILE", "MN_LIMIT_TOKEN_FILE",
    "MN_LIMIT_DER", "MN_LIMIT_HEADER", "MN_LIMIT_BODY", "MN_TLS_IOBUF",
    "MN_MAX_REDIRECT", "MN_BACKOFF_MAX", "MN_LOG_LINE_MAX", "MN_LOG_FIELD_MAX",
    "E_CFG", "E_DNS", "E_CONNECT", "E_TIMEOUT", "E_TLS_HANDSHAKE",
    "E_TLS_CERT", "E_TLS_TIME", "E_HTTP_STATUS", "E_RATELIMIT", "E_PARSE",
    "E_API", "E_CA_LOAD", "E_NO_IP", "E_BUSY",
    "struct mn_provider", "struct mn_cfg", "struct mn_remote",
    "MN_CAP_PATCH_CONTENT", "MN_CAP_DISCOVER",
]
for name in required:
    if name not in header:
        problems.append("not defined in src/miniddns.h: %s" % name)
notes.append("checked %d symbols" % len(required))

# 4. paths in the unit are created by install.sh / make install -------------
unit = read(UNIT) if os.path.exists(UNIT) else ""
if unit:
    if "AF_NETLINK" not in unit:
        problems.append("systemd unit missing AF_NETLINK")
    if "PrivateNetwork=yes" in unit:
        problems.append("systemd unit must NOT set PrivateNetwork=yes")
    if "@BINDIR@/miniddns" not in unit:
        problems.append("unit ExecStart does not use @BINDIR@")
    for token in ("$(BINDIR)/miniddns", "$(PREFIX)/ca/ca-certificates.crt", "$(SYSTEMD)/miniddns.service"):
        if token not in makefile:
            problems.append("Makefile install does not create %s" % token)
    notes.append("unit/install paths OK")

# 5. repository language policy (CONTRIBUTING.md rules 1 and 2) -------------
readme = read(os.path.join(ROOT, "README.md"))
if re.search(r"[\u3400-\u9fff\u3040-\u30ff\uac00-\ud7af]", readme):
    problems.append("README.md must be written in English (found CJK characters)")
contrib_path = os.path.join(ROOT, "CONTRIBUTING.md")
if not os.path.exists(contrib_path):
    problems.append("CONTRIBUTING.md missing (repository language policy)")
else:
    contrib = read(contrib_path)
    if not re.search(r"all interactions with github must be in english", contrib, re.I):
        problems.append("CONTRIBUTING.md must state the English-only GitHub rule")
    if not re.search(r"README\.md`? must be in English", contrib, re.I):
        problems.append("CONTRIBUTING.md must state that README.md is English")
notes.append("language policy OK")

print("spec-check: %d notes" % len(notes))
for n in notes[:8]:
    print("  -", n)
if problems:
    for p in problems:
        print("  FAIL:", p, file=sys.stderr)
    print("spec-check: %d problem(s)" % len(problems), file=sys.stderr)
    sys.exit(1)
print("spec-check: OK")
