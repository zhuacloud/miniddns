include $(TOPDIR)/rules.mk

PKG_NAME:=miniddns
# Overridden by scripts/update_openwrt.py on release.  OpenWrt requires a
# numeric version; local development uses 0.0.0 (the binary still reports
# 0.0.0-dev unless VERSION is passed explicitly by Build/Compile).
PKG_VERSION?=0.0.0
PKG_RELEASE:=1
PKG_LICENSE:=MIT
PKG_LICENSE_FILES:=LICENSE

# The source tarball is produced by `make source-dist VERSION=x.y.z` and
# uploaded next to the binary artifacts.  It deliberately excludes openwrt/
# so this recipe's PKG_HASH does not depend on itself.
PKG_SOURCE:=miniddns-$(PKG_VERSION)-src.tar.gz
PKG_SOURCE_URL:=https://github.com/zhuacloud/miniddns/releases/download/$(PKG_VERSION)
PKG_HASH:=skip
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk

define Package/miniddns
  SECTION:=net
  CATEGORY:=Network
  TITLE:=极低资源占用的多提供商动态 DNS 守护进程
  URL:=https://github.com/zhuacloud/miniddns
  # /etc/ssl/certs/ca-certificates.crt comes from ca-bundle (§12.6)
  DEPENDS:=+ca-bundle
endef

define Package/miniddns/description
  Event-driven DDNS updater: rtnetlink edge trigger, BearSSL TLS, no state
  file, zero writes when the IP is unchanged.  Statically linked, no runtime
  dependencies beyond the system CA bundle.
endef

define Build/Prepare
	$(INSTALL_DIR) $(PKG_BUILD_DIR)
	tar -xzf $(DL_DIR)/$(PKG_SOURCE) -C $(PKG_BUILD_DIR) --strip-components=1
endef

define Build/Compile
	# musl SDK toolchain, -static, no libustream/libopenssl (§12.6).
	# NO_HOST_UAPI=1: use the SDK's target UAPI headers, never the host's.
	$(MAKE) -C $(PKG_BUILD_DIR) static \
		VERSION="$(PKG_VERSION)" \
		CC="$(TARGET_CC)" \
		STATIC_CC="$(TARGET_CC)" \
		NO_HOST_UAPI=1 \
		OPT="-Os -fno-pie" \
		LDFLAGS="-static -s -no-pie -Wl,--gc-sections"
endef

define Package/miniddns/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/build/miniddns $(1)/usr/bin/miniddns
	$(INSTALL_DIR) $(1)/usr/share/miniddns/conf
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/conf/miniddns.conf.example $(1)/usr/share/miniddns/conf/miniddns.conf.example
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/miniddns.init $(1)/etc/init.d/miniddns
	$(INSTALL_DIR) $(1)/usr/share/doc/miniddns
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/docs/design.md $(1)/usr/share/doc/miniddns/design.md
	$(INSTALL_DIR) $(1)/usr/share/licenses/miniddns
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/LICENSE $(1)/usr/share/licenses/miniddns/LICENSE
endef

define Package/miniddns/postinst
#!/bin/sh
# Failure is only logged; it must never block package installation (§12.6).
/usr/bin/miniddns --check-ca >/dev/null 2>&1 || \
  echo "miniddns: --check-ca failed; run it manually after configuring" >&2
exit 0
endef

$(eval $(call BuildPackage,miniddns))
