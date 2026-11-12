#!/usr/bin/env python3
"""Update openwrt/Makefile with a release version and source-tarball hash."""
import argparse
import re
import sys


def main():
    ap = argparse.ArgumentParser(description="Update OpenWrt package metadata")
    ap.add_argument("--file", default="openwrt/Makefile")
    ap.add_argument("--version", required=True)
    ap.add_argument("--hash", required=True)
    args = ap.parse_args()

    with open(args.file, encoding="utf-8") as f:
        text = f.read()

    text, n_version = re.subn(r"(?m)^PKG_VERSION\?=.*$",
                              "PKG_VERSION?=%s" % args.version, text)
    text, n_hash = re.subn(r"(?m)^PKG_HASH[?:]?=.*$",
                           "PKG_HASH:=%s" % args.hash, text)
    if n_version != 1 or n_hash != 1:
        print("ERROR: expected exactly one PKG_VERSION?= and one PKG_HASH?= line",
              file=sys.stderr)
        return 1

    with open(args.file, "w", encoding="utf-8") as f:
        f.write(text)
    print("updated %s: PKG_VERSION=%s PKG_HASH=%s" % (args.file, args.version, args.hash))
    return 0


if __name__ == "__main__":
    sys.exit(main())
