#!/usr/bin/env python3
"""Verify the generated CA fallback bundle and its provenance README.

The bundle is generated from the build host (`make ca-refresh`); this gate
does not require every anchor to be unexpired (expired roots are a normal
property of distro bundles), but it does require a plausible anchor count,
a bounded file size, and a matching sha256 recorded in ca/README.
"""
import argparse
import hashlib
import os
import re
import sys

MIN_SIZE = 32 * 1024
MAX_SIZE = 2 * 1024 * 1024


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def parse_readme(path):
    values = {}
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                m = re.match(r"^\s*([A-Za-z0-9_]+)\s*:\s*(.*?)\s*$", line)
                if m:
                    values[m.group(1)] = m.group(2)
    except OSError as exc:
        return None, str(exc)
    return values, ""


def check_bundle(bundle, readme, min_anchors=100):
    problems = []
    if not os.path.isfile(bundle):
        return ["missing CA bundle: %s" % bundle]
    size = os.path.getsize(bundle)
    if size < MIN_SIZE:
        problems.append("CA bundle suspiciously small: %d bytes" % size)
    if size > MAX_SIZE:
        problems.append("CA bundle too large: %d bytes (limit %d)" % (size, MAX_SIZE))
    try:
        with open(bundle, "rb") as f:
            data = f.read()
    except OSError as exc:
        return ["cannot read CA bundle: %s" % exc]
    anchors = data.count(b"-----BEGIN CERTIFICATE-----")
    if anchors < min_anchors:
        problems.append("CA bundle anchors=%d below minimum %d" % (anchors, min_anchors))
    if anchors != data.count(b"-----END CERTIFICATE-----"):
        problems.append("CA bundle has mismatched BEGIN/END CERTIFICATE markers")
    if not readme or not os.path.isfile(readme):
        problems.append("missing CA provenance file: %s" % readme)
        return problems
    values, err = parse_readme(readme)
    if values is None:
        problems.append("cannot read CA provenance file: %s" % err)
        return problems
    for key in ("taken_at", "source", "certificates", "sha256"):
        if not values.get(key):
            problems.append("CA provenance missing %s" % key)
    if values.get("sha256") and values["sha256"].lower() != sha256_file(bundle):
        problems.append("CA provenance sha256 does not match the bundle")
    if values.get("certificates"):
        try:
            if int(values["certificates"]) != anchors:
                problems.append("CA provenance certificates=%s does not match anchors=%d"
                                % (values["certificates"], anchors))
        except ValueError:
            problems.append("CA provenance certificates is not an integer")
    return problems


def main():
    ap = argparse.ArgumentParser(description="Verify miniddns CA bundle provenance")
    ap.add_argument("--bundle", default="ca/ca-certificates.crt")
    ap.add_argument("--readme", default="ca/README")
    ap.add_argument("--min-anchors", type=int, default=100)
    args = ap.parse_args()
    problems = check_bundle(args.bundle, args.readme, args.min_anchors)
    if problems:
        for p in problems:
            print("CA gate: ERROR: %s" % p, file=sys.stderr)
        return 1
    print("CA gate: OK bundle=%s anchors>=%d" % (args.bundle, args.min_anchors))
    return 0


if __name__ == "__main__":
    sys.exit(main())
