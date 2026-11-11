include $(TOPDIR)/rules.mk

PKG_NAME:=miniddns
PKG_VERSION:=1.2.0
PKG_RELEASE:=1
PKG_LICENSE:=MIT
PKG_LICENSE_FILES:=LICENSE

include $(INCLUDE_DIR)/package.mk

define Package/miniddns
  SECTION:=net
  CATEGORY:=Network
  TITLE:=极低资源占用的多提供商动态 DNS 守护进程
  URL:=https://example.invalid/miniddns
  # /etc/ssl/certs/ca-certificates.crt comes from ca-bundle (§12.6)
  DEPENDS:=+ca-bundle
endef

define Package/miniddns/description
  Event-driven DDNS updater: rtnetlink edge trigger, BearSSL TLS, no state
  file, zero writes when the IP is unchanged. Statically linked, no runtime
  dependencies beyond the system CA bundle.
endef

define Build/Prepare
	$(INSTALL_DIR) $(PKG_BUILD_DIR)
	$(CP) ./Makefile ./src ./third_party ./conf ./docs ./systemd ./openwrt ./LICENSE ./README.md $(PKG_BUILD_DIR)/
endef

define Build/Compile
	# musl SDK toolchain, -static, no libustream/libopenssl (§12.6)
	$(MAKE) -C $(PKG_BUILD_DIR) static \
		CC="$(TARGET_CC)" \
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
endef

define Package/miniddns/postinst
#!/bin/sh
# Failure is only logged; it must never block package installation (§12.6).
/usr/bin/miniddns --check-ca >/dev/null 2>&1 || \
  echo "miniddns: --check-ca failed; run it manually after configuring" >&2
exit 0
endef

$(eval $(call BuildPackage,miniddns))
