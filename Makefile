# miniddns — build (design.md §13.1, with -ffunction-sections for the 500 KB budget)
CC       ?= cc
# Static artifacts are sized for musl; prefer a musl toolchain when present.
STATIC_CC ?= $(shell command -v musl-gcc 2>/dev/null || echo $(CC))
CSTD     ?= -std=c99
WARN     ?= -Wall -Wextra -Wno-unused-parameter
HARDEN   ?= -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -fno-plt
OPT      ?= -O2
VERSION  ?= 1.2.0
REPO     ?= zhuacloud/miniddns
DEFS     ?= -DBR_USE_URANDOM -D_GNU_SOURCE -D_DEFAULT_SOURCE
# The release version is injected through a generated header (build/version.h),
# never through a quoted -D macro: quoted defines lose their quotes when CFLAGS
# or DEFS is passed to a sub-make. Override with `make dist VERSION=0.0.1-rc1`.
DEFS     += -DMN_USE_GENERATED_VERSION=1
# Debian's musl-gcc uses -nostdinc and therefore hides the kernel UAPI headers
# (linux/if_addr.h, linux/rtnetlink.h, asm/types.h). Exposing /usr/include
# directly would mix glibc headers into a musl build, so stage only the UAPI
# trees in build/uapi and add that directory to the include path.
MACHINE  := $(shell $(CC) -dumpmachine 2>/dev/null || echo x86_64-linux-gnu)
UAPI_DIR  = build/uapi
KERNEL_ASM = /usr/include/$(MACHINE)/asm
UAPI_STAMP = $(UAPI_DIR)/.stamp
INC       = -Ithird_party/bearssl/inc -Ithird_party/bearssl/src -Ithird_party/jsmn -Isrc -Ibuild -isystem $(UAPI_DIR)
SECTS     = -ffunction-sections -fdata-sections
CFLAGS   += $(CSTD) $(WARN) $(HARDEN) $(OPT) $(DEFS) $(INC) $(SECTS)
# BearSSL is upstream code; keep our own -Wall -Wextra clean while not failing on it.
CFLAGS_VENDOR += $(CSTD) $(OPT) $(DEFS) $(INC) $(SECTS) -w
LDFLAGS  += -pie -Wl,-z,relro,-z,now -Wl,--gc-sections

ARCH     ?= $(shell uname -m)

APP_SRC  := $(wildcard src/*.c)
BR_SRC   := $(shell find third_party/bearssl/src -name '*.c' | sort)
APP_OBJ  := $(patsubst src/%.c,build/src/%.o,$(APP_SRC))
BR_OBJ   := $(patsubst third_party/%.c,build/third_party/%.o,$(BR_SRC))
OBJ      := $(APP_OBJ) $(BR_OBJ)
DEP      := $(OBJ:.o=.d)

.DEFAULT_GOAL := all

.PHONY: all static doc test test-asan units verify-units ca-refresh install dist \
        clean spec-check check-config check-ca print-ip version version-check \
        changelog verify-artifacts

version:
	@echo $(VERSION)

version-check:
	@python3 scripts/gen_changelog.py --validate-only --version "$(VERSION)"

changelog:
	@python3 scripts/gen_changelog.py --version "$(VERSION)" --repo "$(REPO)" \
	        --changelog CHANGELOG.md --notes build/RELEASE_NOTES.md

verify-artifacts:
	@python3 scripts/verify_release_artifacts.py --dist $(DIST) --version $(VERSION)

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

$(APP_OBJ): build/version.h $(UAPI_STAMP)

# Static artifact (musl/embedded): -no-pie, stripped. Rebuild objects: make does
# not track flag changes, and -fPIE objects must not leak into a -no-pie link.
static:
	rm -rf build
	@if ! command -v musl-gcc >/dev/null 2>&1; then \
	  echo "WARN: musl-gcc not found; a glibc -static binary exceeds the 500 KB budget (§13.2). Use STATIC_CC=<musl toolchain>."; \
	fi
	$(MAKE) CC="$(STATIC_CC)" OPT="$(OPT) -fno-pie" \
	        HARDEN="-fstack-protector-strong -D_FORTIFY_SOURCE=2 -fno-pie -fno-plt" \
	        DEFS="$(DEFS) -DMN_STATIC_BUILD=1" \
	        LDFLAGS="-static -s -no-pie -Wl,--gc-sections" build/miniddns

# ---- docs: docs/ is authoritative, doc/ is the in-artifact layout ----
PANDOC ?= pandoc
doc: doc/design.md
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

# ---- tests ----
test: all
	$(MAKE) -C tests run

test-asan:
	rm -rf build
	$(MAKE) all CFLAGS="$(CFLAGS) -fsanitize=address,undefined -fno-omit-frame-pointer" \
	            LDFLAGS="-pie -Wl,--gc-sections -fsanitize=address,undefined"
	$(MAKE) -C tests run ASAN=1

spec-check:
	@python3 tests/spec_check.py

check-config: all
	./build/miniddns --check-config -c conf/miniddns.conf.example
check-ca: all
	./build/miniddns --check-ca --allow-non-root-owner
print-ip: all
	./build/miniddns --print-ip

# ---- dist ----
DIST := dist/miniddns-$(VERSION)-$(ARCH)-musl
dist: verify-units doc
	$(MAKE) static
	rm -rf $(DIST)
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
	install -Dm0644 THIRD_PARTY_NOTICES.md  $(DIST)/THIRD_PARTY_NOTICES.md
	install -Dm0644 LICENSE                 $(DIST)/LICENSES/miniddns-MIT.txt
	install -Dm0644 THIRD_PARTY_NOTICES.md  $(DIST)/LICENSES/THIRD_PARTY_NOTICES.md
	install -Dm0644 third_party/bearssl/LICENSE.txt $(DIST)/LICENSES/bearssl-MIT.txt
	install -Dm0644 third_party/jsmn/LICENSE        $(DIST)/LICENSES/jsmn-MIT.txt
	@cd $(DIST) && find . -type f ! -name 'SHA256SUMS*' | sort | xargs sha256sum > ../SHA256SUMS.tmp && mv ../SHA256SUMS.tmp SHA256SUMS
	@! find $(DIST) \( -name 'miniddns.conf' -o -name '*.token' -o -name '.git*' \) | grep . \
	  || (echo "FATAL: artifact contains forbidden files"; exit 1)
	@test -s $(DIST)/LICENSES/bearssl-MIT.txt && test -s $(DIST)/LICENSES/jsmn-MIT.txt \
	  || (echo "FATAL: missing third-party license notices"; exit 1)
	@python3 scripts/verify_release_artifacts.py --dist $(DIST) --version $(VERSION)
	@echo "dist ok: $(DIST)"

clean:
	rm -rf build dist
