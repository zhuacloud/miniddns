#!/usr/bin/env python3
"""Verify a miniddns release artifact tree before publishing.

Every platform/libc package must be a self-contained install prefix: the
runnable binary, configuration examples, install script and systemd/OpenWrt
service configuration examples all live INSIDE the directory that is packed
into the tarball. Nothing is uploaded as a loose release asset.

All output is English per CONTRIBUTING.md.
"""
import argparse
import hashlib
import os
import platform
import struct
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from verify_ca_bundle import check_bundle  # noqa: E402

REQUIRED_FILES = [
    "bin/miniddns",
    "README.md",
    "conf/miniddns.conf.example",
    "conf/README.md",
    "install.sh",
    "systemd/miniddns.service",
    "systemd/miniddns.service.in",
    "systemd/miniddns.service.d/user-nonroot.conf",
    "openwrt/Makefile",
    "openwrt/README.md",
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

# Allowed entries directly under the artifact root. This guards the directory
# structure so installation/configuration files never end up outside the
# tarball layout.
ALLOWED_TOP_LEVEL = {
    "bin", "conf", "examples", "install.sh", "README.md", "systemd",
    "openwrt", "ca", "doc", "LICENSES", "THIRD_PARTY_NOTICES.md",
    "SHA256SUMS",
}

EXECUTABLE_FILES = [
    "bin/miniddns",
    "install.sh",
    "openwrt/files/miniddns.init",
]

ARCH_ELF = {
    "x86": (1, 3),      # ELFCLASS32, EM_386
    "x64": (2, 62),     # ELFCLASS64, EM_X86_64
    "arm32": (1, 40),   # ELFCLASS32, EM_ARM
    "arm64": (2, 183),  # ELFCLASS64, EM_AARCH64
}
MUSL_STATIC_MAX = 500 * 1024

HOST_ARCH = {
    "x86_64": "x64", "amd64": "x64",
    "i386": "x86", "i486": "x86", "i586": "x86", "i686": "x86",
    "aarch64": "arm64", "arm64": "arm64",
    "armv7l": "arm32", "armv6l": "arm32", "arm": "arm32",
}


def has_interp(path):
    """True when the ELF image has a PT_INTERP program header (dynamic)."""
    try:
        with open(path, "rb") as f:
            data = f.read(65536)
        if data[:4] != b"\x7fELF":
            return None
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
            return None
        for i in range(phnum):
            off = phoff + i * phentsize
            if off + 4 > len(data):
                return None
            if struct.unpack_from(endian + "I", data, off)[0] == 3:  # PT_INTERP
                return True
        return False
    except (OSError, struct.error):
        return None


def elf_identity(path):
    """Return (elf_class, e_machine, e_type, little_endian) or None."""
    try:
        with open(path, "rb") as f:
            data = f.read(64)
        if data[:4] != b"\x7fELF" or len(data) < 20:
            return None
        elf_class = data[4]
        little = data[5] == 1
        endian = "<" if little else ">"
        e_type = struct.unpack_from(endian + "H", data, 16)[0]
        e_machine = struct.unpack_from(endian + "H", data, 18)[0]
        return elf_class, e_machine, e_type, little
    except (OSError, struct.error):
        return None


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
    ap.add_argument("--arch", default="x64", choices=["x86", "x64", "arm32", "arm64"])
    ap.add_argument("--libc", default="musl", choices=["musl", "glibc"])
    ap.add_argument("--skip-run", action="store_true", help="do not execute the binary")
    args = ap.parse_args()

    root = os.path.abspath(args.dist)
    problems = []
    checked = 0

    expected_id = "miniddns-%s-linux-%s-%s" % (args.version, args.arch, args.libc)
    if os.path.basename(root) != expected_id:
        problems.append("artifact directory name must be %s (got %s)"
                        % (expected_id, os.path.basename(root)))

    if not os.path.isdir(root):
        print("ERROR: dist root does not exist: %s" % root, file=sys.stderr)
        return 1

    for name in sorted(os.listdir(root)):
        if name not in ALLOWED_TOP_LEVEL:
            problems.append("unexpected top-level entry: %s" % name)

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

    binary = os.path.join(root, "bin/miniddns")
    if os.path.isfile(binary):
        interp = has_interp(binary)
        ident = elf_identity(binary)
        if interp is None or ident is None:
            problems.append("bin/miniddns is not a valid ELF binary")
        else:
            elf_class, e_machine, e_type, little = ident
            expected = ARCH_ELF.get(args.arch)
            if expected is None:
                problems.append("unknown --arch %s" % args.arch)
            elif (elf_class, e_machine) != expected:
                problems.append(
                    "ELF arch mismatch for %s: class=%d machine=%d (expected class=%d machine=%d)"
                    % (args.arch, elf_class, e_machine, expected[0], expected[1]))
            if not little:
                problems.append("ELF binary is not little-endian")
            if args.libc == "musl":
                if interp:
                    problems.append("musl build must be fully static (PT_INTERP present)")
                if e_type != 2:  # ET_EXEC
                    problems.append("musl static build must be ET_EXEC (got e_type=%d)" % e_type)
                size = os.path.getsize(binary)
                if size > MUSL_STATIC_MAX:
                    problems.append("musl static binary exceeds 500 KiB budget: %d bytes"
                                    % size)
            elif args.libc == "glibc" and not interp:
                problems.append("glibc build must be dynamically linked (no PT_INTERP)")

        host = HOST_ARCH.get(platform.machine().lower(), "")
        runnable = (not args.skip_run) and host == args.arch
        if runnable:
            try:
                out = subprocess.check_output([binary, "--version"], text=True, timeout=15)
                first = out.splitlines()[0] if out.splitlines() else ""
                if first.strip() != "miniddns %s" % args.version:
                    problems.append("binary version mismatch: expected 'miniddns %s', got %r"
                                    % (args.version, first.strip()))
            except (OSError, subprocess.SubprocessError) as exc:
                problems.append("cannot run bin/miniddns --version: %s" % exc)
        else:
            # Cross-architecture: the version string is still embedded literally.
            with open(binary, "rb") as f:
                blob = f.read()
            if args.version.encode() not in blob:
                problems.append("version string %r not found in cross-built binary"
                                % args.version)

    # CA fallback bundle must be plausible and match its provenance README.
    ca_bundle = os.path.join(root, "ca/ca-certificates.crt")
    ca_readme = os.path.join(root, "ca/README")
    if os.path.isfile(ca_bundle) and os.path.isfile(ca_readme):
        for p in check_bundle(ca_bundle, ca_readme, 100):
            problems.append("CA gate: %s" % p)

    # Artifact files must not be group/world writable.
    for dirpath, dirnames, filenames in os.walk(root):
        for name in dirnames + filenames:
            full = os.path.join(dirpath, name)
            try:
                mode = os.stat(full).st_mode
            except OSError:
                continue
            if mode & 0o022:
                problems.append("group/world writable artifact entry: %s"
                                % os.path.relpath(full, root))

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

    print("Artifact:  %s" % os.path.basename(root))
    print("Platform:  linux / %s / %s" % (args.arch, args.libc))
    print("Files:     %d required, %d checksums" % (len(REQUIRED_FILES), max(0, checked - len(REQUIRED_FILES))))
    if problems:
        for p in problems:
            print("ERROR: %s" % p, file=sys.stderr)
        print("Artifact verification FAILED (%d problem(s))" % len(problems), file=sys.stderr)
        return 1
    print("Artifact verification OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
