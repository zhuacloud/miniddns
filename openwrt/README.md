# OpenWrt package recipe

This directory is the OpenWrt source-feed recipe for miniddns. It is **not**
used to build the binary release tarballs and it cannot be built from a binary
artifact alone.

## Feed usage

1. Copy this directory to `package/miniddns/` in your OpenWrt feed.
2. Publish or point `PKG_SOURCE_URL` at the matching source tarball asset:
   `miniddns-<version>-src.tar.gz`.
3. Set `PKG_VERSION` and `PKG_HASH` to the release version and the sha256 of
   that source tarball. The release workflow does this automatically before
   tagging; for local feed testing you can override both on the command line.

```sh
make package/miniddns/compile \
  PKG_VERSION=0.0.1 \
  PKG_HASH=<sha256-of-miniddns-0.0.1-src.tar.gz>
```

The recipe builds with the SDK's musl toolchain (`TARGET_CC`), links statically,
and passes `NO_HOST_UAPI=1` so the build never mixes host kernel headers into
the target.

The source tarball is generated with:

```sh
make source-dist VERSION=0.0.1
```

It intentionally excludes `openwrt/` to avoid a circular dependency between the
recipe's `PKG_HASH` and the tarball it points at.
