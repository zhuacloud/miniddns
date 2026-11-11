#!/usr/bin/env python3
"""Verify the release artifact manifest before publishing.

The release tarball must contain the runnable binary, the configuration
example, the install script, and server configuration examples (systemd and
OpenWrt), plus the CA snapshot, docs, license notices and checksums.

All output is English per CONTRIBUTING.md.
"""
import argparse
import hashlib
import os
import struct
import subprocess
import sys

REQUIRED_FILES = [
    "bin/miniddns",
    "conf/miniddns.conf.example",
    "conf/README.md",
    "install.sh",
    "systemd/miniddns.service",
    "systemd/miniddns.service.in",
    "systemd/miniddns.service.d/user-nonroot.conf",
    "openwrt/Makefile",
    "openwrt/files/miniddns.init",
    "examples/README.md",
    "examples/miniddns.conf.minimal.example",
    "examples/miniddns.conf.multi-instance.example",
    "ca/ca-certificates.crt",
    "ca/README",
    "doc/design.md",
    "THIRD_PARTY_NOTICES.md",
    "LICENSES/miniddns-MIT.txt",
    "LICENSES/THIRD_PARTY_NOTICES.md",
    "LICENSES/bearssl-MIT.txt",
    "LICENSES/jsmn-MIT.txt",
    "SHA256SUMS",
]

EXECUTABLE_FILES = [
    "bin/miniddns",
    "install.sh",
    "openwrt/files/miniddns.init",
]

FORBIDDEN_BASENAMES = ("miniddns.conf",)
FORBIDDEN_SUFFIXES = (".token",)
FORBIDDEN_PREFIXES = (".git",)
FORBIDDEN_DIRS = ("build",)


def is_static_elf(path):
    """True when the ELF image has no PT_INTERP program header."""
    try:
        with open(path, "rb") as f:
            data = f.read(65536)
        if data[:4] != b"\x7fELF":
            return False
        is64 = data[4] == 2
        endian = "<" if data[5] == 1 else ">"
        if is64:
            phoff = struct.unpack_from(endian + "Q", data, 32)[0]
            phentsize = struct.unpack_from(endian + "H", data, 54)[0]
            phnum = struct.unpack_from(endian + "H", data, 56)[0]
        else:
            phoff = struct.unpack_from(endian + "I", data, 28)[0]
            phentsize = struct.unpack_from(endian + "H", data, 42)[0]
            phnum = struct.unpack_from(endian + "H", data, 44)[0]
        if not phentsize or phnum > 4096:
            return False
        for i in range(phnum):
            off = phoff + i * phentsize
            if off + 4 > len(data):
                return False
            if struct.unpack_from(endian + "I", data, off)[0] == 3:  # PT_INTERP
                return False
        return True
    except (OSError, struct.error):
        return False


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser(description="Verify a miniddns dist artifact tree")
    ap.add_argument("--dist", required=True, help="path to the dist artifact root")
    ap.add_argument("--version", required=True, help="expected binary version")
    ap.add_argument("--skip-run", action="store_true", help="do not execute the binary")
    args = ap.parse_args()

    root = os.path.abspath(args.dist)
    problems = []
    checked = 0

    if not os.path.isdir(root):
        print("ERROR: dist root does not exist: %s" % root, file=sys.stderr)
        return 1

    for rel in REQUIRED_FILES:
        path = os.path.join(root, rel)
        if not os.path.isfile(path):
            problems.append("missing required file: %s" % rel)
            continue
        if os.path.getsize(path) == 0:
            problems.append("empty required file: %s" % rel)
        checked += 1

    for rel in EXECUTABLE_FILES:
        path = os.path.join(root, rel)
        if os.path.isfile(path) and not os.access(path, os.X_OK):
            problems.append("not executable: %s" % rel)

    for dirpath, dirnames, filenames in os.walk(root):
        for d in dirnames:
            if d in FORBIDDEN_DIRS:
                problems.append("forbidden directory: %s" % os.path.relpath(os.path.join(dirpath, d), root))
        for name in filenames:
            if name in FORBIDDEN_BASENAMES or name.endswith(FORBIDDEN_SUFFIXES) \
                    or name.startswith(FORBIDDEN_PREFIXES):
                problems.append("forbidden file: %s" % os.path.relpath(os.path.join(dirpath, name), root))

    binary = os.path.join(root, "bin/miniddns")
    if os.path.isfile(binary):
        if not is_static_elf(binary):
            problems.append("bin/miniddns is not a static ELF binary")
        if not args.skip_run:
            try:
                out = subprocess.check_output([binary, "--version"], text=True, timeout=15)
                first = out.splitlines()[0] if out.splitlines() else ""
                if first.strip() != "miniddns %s" % args.version:
                    problems.append("binary version mismatch: expected 'miniddns %s', got %r"
                                    % (args.version, first.strip()))
            except (OSError, subprocess.SubprocessError) as exc:
                problems.append("cannot run bin/miniddns --version: %s" % exc)

    sums_path = os.path.join(root, "SHA256SUMS")
    if os.path.isfile(sums_path):
        listed = {}
        with open(sums_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or "  " not in line:
                    continue
                digest, rel = line.split("  ", 1)
                rel = rel[2:] if rel.startswith("./") else rel
                listed[rel] = digest
        actual = set()
        for dirpath, _, filenames in os.walk(root):
            for name in filenames:
                rel = os.path.relpath(os.path.join(dirpath, name), root)
                if rel == "SHA256SUMS":
                    continue
                actual.add(rel)
        for rel in sorted(actual - set(listed)):
            problems.append("file missing from SHA256SUMS: %s" % rel)
        for rel in sorted(set(listed) - actual):
            problems.append("SHA256SUMS lists a missing file: %s" % rel)
        for rel, digest in listed.items():
            path = os.path.join(root, rel)
            if os.path.isfile(path) and sha256(path) != digest:
                problems.append("checksum mismatch: %s" % rel)
        checked += len(listed)

    print("Artifact root: %s" % root)
    print("Required files checked: %d" % len(REQUIRED_FILES))
    print("Checksums checked: %d" % max(0, checked - len(REQUIRED_FILES)))
    if problems:
        for p in problems:
            print("ERROR: %s" % p, file=sys.stderr)
        print("Artifact verification FAILED (%d problem(s))" % len(problems), file=sys.stderr)
        return 1
    print("Artifact verification OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
