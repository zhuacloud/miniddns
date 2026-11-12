#!/usr/bin/env python3
"""Create a deterministic source tarball for OpenWrt PKG_SOURCE.

The tarball deliberately excludes openwrt/: that directory contains the
package recipe whose PKG_HASH points at this tarball, so including it would
create a circular hash dependency.  It includes everything needed to build
the binary (Makefile, src/, third_party/, conf/, docs/, systemd/, tests/).
"""
import argparse
import os
import subprocess
import sys
import tarfile


def tracked_files(root):
    try:
        out = subprocess.check_output(
            ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
            cwd=root, stderr=subprocess.PIPE)
    except (OSError, subprocess.CalledProcessError) as exc:
        raise SystemExit("ERROR: git ls-files failed: %s" % exc)
    return sorted(n for n in out.decode("utf-8", "surrogateescape").split("\0") if n)


def main():
    ap = argparse.ArgumentParser(description="Build miniddns source tarball")
    ap.add_argument("--version", required=True)
    ap.add_argument("--output", required=True)
    args = ap.parse_args()

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    output = os.path.abspath(args.output)
    os.makedirs(os.path.dirname(output), exist_ok=True)
    prefix = "miniddns-%s/" % args.version

    selected = []
    for rel in tracked_files(root):
        if rel == "openwrt" or rel.startswith("openwrt/"):
            continue
        full = os.path.join(root, rel)
        if not os.path.lexists(full):
            print("WARN: tracked file missing, skipped: %s" % rel, file=sys.stderr)
            continue
        selected.append((rel, full))

    with tarfile.open(output, "w:gz", format=tarfile.GNU_FORMAT) as tf:
        for rel, full in selected:
            ti = tarfile.TarInfo(prefix + rel)
            ti.mtime = 0
            ti.uid = ti.gid = 0
            ti.uname = ti.gname = ""
            if os.path.islink(full):
                ti.type = tarfile.SYMTYPE
                ti.linkname = os.readlink(full)
                ti.mode = 0o777
                tf.addfile(ti)
                continue
            st = os.stat(full)
            ti.size = st.st_size
            ti.mode = 0o755 if (st.st_mode & 0o111) else 0o644
            with open(full, "rb") as f:
                tf.addfile(ti, f)

    print(output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
