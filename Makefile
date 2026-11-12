# miniddns — build (design.md §13.1, with -ffunction-sections for the 500 KB budget)
CC       ?= cc
CSTD     ?= -std=c99
WARN     ?= -Wall -Wextra -Wno-unused-parameter
HARDEN   ?= -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -fno-plt
OPT      ?= -O2
# Three DIFFERENT version namespaces (see docs/RELEASE_PROCESS.md section 1):
#   - design specification version: docs/design.md v1.2 + revisions 1.2.x
#   - software release version: X.Y.Z / X.Y.Z-rcN, injected by the release workflow
#   - local development build: 0.0.0-dev (default when VERSION is not given)
# Never use the design spec version as a software version.
VERSION  ?= 0.0.0-dev
DEV_VERSION := 0.0.0-dev
REPO     ?= zhuacloud/miniddns
# Release artifact identity: linux + arch (x86/x64/arm32/arm64) + libc (musl/glibc).
TARGET_ARCH ?= x64
LIBC        ?= musl
ZIG         ?= zig
ZIG_TARGET  ?=
ifeq ($(strip $(ZIG_TARGET)),)
BUILD_CC = $(CC)
STATIC_CC ?= $(shell command -v musl-gcc 2>/dev/null || echo $(CC))
else
BUILD_CC = $(ZIG) cc -target $(ZIG_TARGET)
STATIC_CC := $(BUILD_CC)
endif
ARTIFACT_ID = miniddns-$(VERSION)-linux-$(TARGET_ARCH)-$(LIBC)
DEFS     ?= -DBR_USE_URANDOM -D_GNU_SOURCE -D_DEFAULT_SOURCE
# The release version is injected through a generated header (build/version.h),
# never through a quoted -D macro: quoted defines lose their quotes when CFLAGS
# or DEFS is passed to a sub-make. Override with `make dist VERSION=0.0.1-rc1`.
DEFS     += -DMN_USE_GENERATED_VERSION=1
# Debian's musl-gcc uses -nostdinc and therefore hides the kernel UAPI headers
# (linux/if_addr.h, linux/rtnetlink.h, asm/types.h). Exposing /usr/include
# directly would mix glibc headers into a musl build, so stage only the UAPI
# trees in build/uapi and add that directory to the include path.
MACHINE  := $(shell cc -dumpmachine 2>/dev/null || echo x86_64-linux-gnu)
UAPI_DIR  = build/uapi
KERNEL_ASM = /usr/include/$(MACHINE)/asm
UAPI_STAMP = $(UAPI_DIR)/.stamp
INCBASE   = -Ithird_party/bearssl/inc -Ithird_party/bearssl/src -Ithird_party/jsmn -Isrc -Ibuild
ifeq ($(strip $(NO_HOST_UAPI)),1)
# Cross toolchains (OpenWrt SDK, Zig) provide target-correct UAPI headers.
INC       = $(INCBASE)
else ifeq ($(strip $(ZIG_TARGET)),)
INC       = $(INCBASE) -isystem $(UAPI_DIR)
else
INC       = $(INCBASE)
endif
SECTS     = -ffunction-sections -fdata-sections
CFLAGS   += $(CSTD) $(WARN) $(HARDEN) $(OPT) $(DEFS) $(INC) $(SECTS)
# BearSSL is upstream code; keep our own -Wall -Wextra clean while not failing on it.
# Hardening still applies: TLS/X.509 is the highest-risk attack surface.
CFLAGS_VENDOR += $(CSTD) $(OPT) $(DEFS) $(INC) $(SECTS) -w $(HARDEN)
LDFLAGS  += -pie -Wl,-z,relro,-z,now -Wl,--gc-sections

APP_SRC  := $(wildcard src/*.c)
BR_SRC   := $(shell find third_party/bearssl/src -name '*.c' | sort)
APP_OBJ  := $(patsubst src/%.c,build/src/%.o,$(APP_SRC))
BR_OBJ   := $(patsubst third_party/%.c,build/third_party/%.o,$(BR_SRC))
OBJ      := $(APP_OBJ) $(BR_OBJ)
DEP      := $(OBJ:.o=.d)

.DEFAULT_GOAL := all

.PHONY: all static doc test test-asan units verify-units ca-refresh install dist \
        clean spec-check check-config check-ca print-ip version version-check \
        changelog verify-artifacts source-dist openwrt-metadata soak

version:
	@echo $(VERSION)

version-check:
	@if [ "$(VERSION)" = "$(DEV_VERSION)" ]; then \
	  echo "OK: $(VERSION) is a local development build (not releasable). Pass VERSION=X.Y.Z to release."; \
	 else \
	  python3 scripts/gen_changelog.py --validate-only --version "$(VERSION)"; \
	 fi

changelog:
	@python3 scripts/gen_changelog.py --version "$(VERSION)" --repo "$(REPO)" \
	        --changelog CHANGELOG.md --notes build/RELEASE_NOTES.md

verify-artifacts:
	@python3 scripts/verify_release_artifacts.py --dist $(DIST) --version $(VERSION) \
	        --arch $(TARGET_ARCH) --libc $(LIBC)

all: build/miniddns

$(APP_OBJ): build/src/%.o: src/%.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -MMD -MP -c $< -o $@

$(BR_OBJ): build/third_party/%.o: third_party/%.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS_VENDOR) -MMD -MP -c $< -o $@

build/miniddns: $(OBJ)
	$(CC) $(OBJ) $(LDFLAGS) -o $@

-include $(DEP)

# Generated version header. FORCE + cmp means the timestamp only changes when
# VERSION actually changes, so unrelated builds stay incremental.
.PHONY: FORCE
FORCE:

build/version.h: FORCE
	@mkdir -p $(@D)
	@printf '#ifndef MN_GENERATED_VERSION_H\n#define MN_GENERATED_VERSION_H\n#define MN_VERSION "%s"\n#endif\n' "$(VERSION)" > $@.tmp
	@if ! cmp -s $@.tmp $@ 2>/dev/null; then mv $@.tmp $@; else rm -f $@.tmp; fi

$(UAPI_STAMP):
	@mkdir -p $(UAPI_DIR)
	@rm -rf $(UAPI_DIR)/linux $(UAPI_DIR)/asm $(UAPI_DIR)/asm-generic
	@if [ -d /usr/include/linux ]; then ln -sfn /usr/include/linux $(UAPI_DIR)/linux; fi
	@if [ -d /usr/include/asm-generic ]; then ln -sfn /usr/include/asm-generic $(UAPI_DIR)/asm-generic; fi
	@if [ -d "$(KERNEL_ASM)" ]; then ln -sfn "$(KERNEL_ASM)" $(UAPI_DIR)/asm; fi
	@touch $@

ifeq ($(strip $(NO_HOST_UAPI)),1)
$(APP_OBJ): build/version.h
else ifeq ($(strip $(ZIG_TARGET)),)
$(APP_OBJ): build/version.h $(UAPI_STAMP)
else
$(APP_OBJ): build/version.h
endif

# Static artifact (musl/embedded): -no-pie, stripped. Rebuild objects: make does
# not track flag changes, and -fPIE objects must not leak into a -no-pie link.
static:
	rm -rf build
	@if [ -z "$(ZIG_TARGET)" ] && [ "$(ALLOW_GLIBC_STATIC)" != "1" ] && \
	    ! "$(STATIC_CC)" -dumpmachine 2>/dev/null | grep -q musl; then \
	  echo "FATAL: static builds require a musl toolchain (§13.1)."; \
	  echo "       Use ZIG_TARGET=<target> or STATIC_CC=musl-gcc;"; \
	  echo "       set ALLOW_GLIBC_STATIC=1 only for local glibc-static experiments."; \
	  exit 1; \
	fi
	$(MAKE) CC="$(STATIC_CC)" OPT="$(OPT) -fno-pie" \
	        HARDEN="-fstack-protector-strong -D_FORTIFY_SOURCE=2 -fno-pie -fno-plt" \
	        DEFS="$(DEFS) -DMN_STATIC_BUILD=1" \
	        LDFLAGS="-static -s -no-pie -Wl,--gc-sections" build/miniddns

# ---- docs: docs/ is authoritative, doc/ is the in-artifact layout ----
PANDOC ?= pandoc
doc: FORCE
	@mkdir -p doc
	@cmp -s docs/design.md doc/design.md || cp docs/design.md doc/design.md
doc/design.md: docs/design.md
	@mkdir -p $(@D)
	cp $< $@
doc/design.html: docs/design.md
	@mkdir -p $(@D)
	@if command -v $(PANDOC) >/dev/null 2>&1; then \
	  $(PANDOC) -f gfm -t html5 -s --metadata title="miniddns design spec" $< -o $@ ; \
	else echo "WARN: pandoc unavailable, skipping doc/design.html"; fi

# ---- unit files (template is the source of truth) ----
PREFIX   ?= /opt/miniddns
BINDIR   ?= $(PREFIX)/bin
CONFDIR  ?= /etc/miniddns
DOCDIR   ?= $(PREFIX)/doc
SYSTEMD  ?= /etc/systemd/system

build/miniddns.service: systemd/miniddns.service.in
	@mkdir -p $(@D)
	sed -e 's|@BINDIR@|$(BINDIR)|g'   \
	    -e 's|@CONFDIR@|$(CONFDIR)|g' \
	    -e 's|@DOCDIR@|$(DOCDIR)|g'   \
	    $< > $@

units: build/miniddns.service
	cp build/miniddns.service systemd/miniddns.service

verify-units: build/miniddns.service
	diff -u build/miniddns.service systemd/miniddns.service

install: build/miniddns build/miniddns.service doc
	install -Dm0755 build/miniddns             $(DESTDIR)$(BINDIR)/miniddns
	install -Dm0644 ca/ca-certificates.crt     $(DESTDIR)$(PREFIX)/ca/ca-certificates.crt
	install -Dm0644 conf/miniddns.conf.example $(DESTDIR)$(PREFIX)/conf/miniddns.conf.example
	install -Dm0644 conf/README.md             $(DESTDIR)$(PREFIX)/conf/README.md
	@mkdir -p $(DESTDIR)$(PREFIX)/examples && cp -r examples/. $(DESTDIR)$(PREFIX)/examples/
	install -Dm0644 doc/design.md              $(DESTDIR)$(DOCDIR)/design.md
	@[ -f doc/design.html ] && install -Dm0644 doc/design.html $(DESTDIR)$(DOCDIR)/design.html || true
	install -Dm0644 THIRD_PARTY_NOTICES.md     $(DESTDIR)$(PREFIX)/THIRD_PARTY_NOTICES.md
	install -Dm0644 LICENSE                    $(DESTDIR)$(PREFIX)/LICENSES/miniddns-MIT.txt
	install -Dm0644 THIRD_PARTY_NOTICES.md     $(DESTDIR)$(PREFIX)/LICENSES/THIRD_PARTY_NOTICES.md
	install -Dm0644 third_party/bearssl/LICENSE.txt $(DESTDIR)$(PREFIX)/LICENSES/bearssl-MIT.txt
	install -Dm0644 third_party/jsmn/LICENSE        $(DESTDIR)$(PREFIX)/LICENSES/jsmn-MIT.txt
	install -Dm0644 build/miniddns.service     $(DESTDIR)$(SYSTEMD)/miniddns.service
	@# deliberately NOT installing the non-root drop-in (§12.3)
	@echo "next: write token -> miniddns --check-ca -> systemctl daemon-reload && systemctl enable --now miniddns"

# ---- CA snapshot ----
CA_SRC ?= /etc/ssl/certs/ca-certificates.crt
ca-refresh:
	install -Dm0644 $(CA_SRC) ca/ca-certificates.crt
	@printf 'CA bundle snapshot\n==================\ntaken_at      : %s\nsource        : %s\ncertificates  : %s\nsha256        : %s\n\nrefresh with: make ca-refresh\nverify with : miniddns --check-ca\nThis bundle is a FALLBACK. Prefer the system store when available.\n' \
	  "$$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$$(grep PRETTY_NAME /etc/os-release | cut -d= -f2-)" \
	  "$$(grep -c 'BEGIN CERTIFICATE' ca/ca-certificates.crt)" \
	  "$$(sha256sum ca/ca-certificates.crt | cut -d' ' -f1)" > ca/README
	@python3 scripts/verify_ca_bundle.py --bundle ca/ca-certificates.crt --readme ca/README --min-anchors 100

# ---- tests ----
test: all
	$(MAKE) -C tests run

test-asan:
	@set -e; \
	  trap 'rm -rf build; $(MAKE) all >/dev/null' EXIT; \
	  rm -rf build; \
	  $(MAKE) all CFLAGS="$(CFLAGS) -fsanitize=address,undefined -fno-omit-frame-pointer" \
	              LDFLAGS="-pie -Wl,--gc-sections -fsanitize=address,undefined"; \
	  $(MAKE) -C tests run ASAN=1

spec-check:
	@python3 tests/spec_check.py

check-config: all
	./build/miniddns --check-config --allow-non-root-owner -c conf/miniddns.conf.example

SOAK_SECONDS ?= 60
SOAK_INTERVAL ?= 2
soak: all
	$(MAKE) -C tests build/redirect.so
	python3 scripts/soak.py --seconds $(SOAK_SECONDS) --interval $(SOAK_INTERVAL)
check-ca: all
	./build/miniddns --check-ca --allow-non-root-owner
print-ip: all
	./build/miniddns --print-ip

# ---- dist ----
DIST := dist/$(ARTIFACT_ID)
# Build the binary for the requested platform/libc, then assemble a
# self-contained prefix directory. Everything an operator needs (binary,
# config examples, install script, systemd/OpenWrt service examples) lives
# inside $(DIST) and therefore inside the release tarball.
dist: verify-units doc
	rm -rf build $(DIST)
	@if [ "$(LIBC)" = "musl" ]; then \
	  $(MAKE) static; \
	 elif [ "$(LIBC)" = "glibc" ]; then \
	  $(MAKE) all CC="$(BUILD_CC)"; \
	 else \
	  echo "FATAL: LIBC must be musl or glibc"; exit 1; \
	 fi
	$(MAKE) ca-refresh
	install -Dm0755 build/miniddns $(DIST)/bin/miniddns
	install -Dm0644 conf/miniddns.conf.example $(DIST)/conf/miniddns.conf.example
	install -Dm0644 conf/README.md             $(DIST)/conf/README.md
	cp -r examples $(DIST)/examples
	install -Dm0644 ca/ca-certificates.crt  $(DIST)/ca/ca-certificates.crt
	install -Dm0644 ca/README               $(DIST)/ca/README
	cp -r systemd $(DIST)/systemd
	cp -r openwrt $(DIST)/openwrt
	install -Dm0644 doc/design.md           $(DIST)/doc/design.md
	@[ -f doc/design.html ] && install -Dm0644 doc/design.html $(DIST)/doc/design.html || true
	install -Dm0755 install.sh              $(DIST)/install.sh
	install -Dm0644 ARTIFACT_README.md      $(DIST)/README.md
	install -Dm0644 THIRD_PARTY_NOTICES.md  $(DIST)/THIRD_PARTY_NOTICES.md
	install -Dm0644 LICENSE                 $(DIST)/LICENSES/miniddns-MIT.txt
	install -Dm0644 THIRD_PARTY_NOTICES.md  $(DIST)/LICENSES/THIRD_PARTY_NOTICES.md
	install -Dm0644 third_party/bearssl/LICENSE.txt $(DIST)/LICENSES/bearssl-MIT.txt
	install -Dm0644 third_party/jsmn/LICENSE        $(DIST)/LICENSES/jsmn-MIT.txt
	@# deterministic artifact permissions: data 0644, directories 0755
	@find $(DIST)/examples $(DIST)/systemd -type f -exec chmod 0644 {} +
	@find $(DIST)/examples $(DIST)/systemd -type d -exec chmod 0755 {} +
	@find $(DIST)/openwrt -type f ! -path '*/files/miniddns.init' -exec chmod 0644 {} +
	@find $(DIST)/openwrt -type d -exec chmod 0755 {} +
	@chmod 0755 $(DIST)/openwrt/files/miniddns.init
	@cd $(DIST) && find . -type f ! -name 'SHA256SUMS*' | sort | xargs sha256sum > ../SHA256SUMS.tmp && mv ../SHA256SUMS.tmp SHA256SUMS
	@chmod 0644 $(DIST)/SHA256SUMS
	@! find $(DIST) \( -name 'miniddns.conf' -o -name '*.token' -o -name '.git*' \) | grep . \
	  || (echo "FATAL: artifact contains forbidden files"; exit 1)
	@test -s $(DIST)/LICENSES/bearssl-MIT.txt && test -s $(DIST)/LICENSES/jsmn-MIT.txt \
	  || (echo "FATAL: missing third-party license notices"; exit 1)
	@python3 scripts/verify_release_artifacts.py --dist $(DIST) --version $(VERSION) \
	        --arch $(TARGET_ARCH) --libc $(LIBC)
	@echo "dist ok: $(DIST)"

clean:
	rm -rf build dist

# ---- source tarball for OpenWrt feeds (excludes openwrt/ to avoid a
# circular hash: the recipe itself points at this tarball) ----
SRC_TARBALL := dist/miniddns-$(VERSION)-src.tar.gz
source-dist:
	@mkdir -p dist
	python3 scripts/make_source_tarball.py --version "$(VERSION)" --output "$(SRC_TARBALL)"
	@echo "source tarball: $(SRC_TARBALL)"

openwrt-metadata: source-dist
	python3 scripts/update_openwrt.py --file openwrt/Makefile \
	        --version "$(VERSION)" \
	        --hash "$$(sha256sum $(SRC_TARBALL) | cut -d' ' -f1)"
