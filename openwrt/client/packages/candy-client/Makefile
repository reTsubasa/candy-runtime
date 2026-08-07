include $(TOPDIR)/rules.mk

PKG_NAME:=candy-client
PKG_VERSION:=0.4.0
# OpenWrt requires a package revision. This is internal metadata, not part of
# the Candy product version shown to users.
PKG_RELEASE:=15
CANDY_RUNTIME_BIN_DIR?=

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/candy-client
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Candy OpenWrt client runtime
  DEPENDS:=+libgcc +ca-bundle +uclient-fetch +jsonfilter +usign +kmod-tun +kmod-nft-tproxy +kmod-nf-tproxy
  USERID:=candy-sdwan=789:candy-sdwan=789
endef

define Package/candy-client/description
  Candy client Runtime launchers, privileged netd, lifecycle, network policy and signed Core management.
endef

define Package/candy-client/conffiles
/etc/config/candy
endef

define Build/Prepare
	rm -rf $(PKG_BUILD_DIR)
	mkdir -p $(PKG_BUILD_DIR)
	[ -n "$(CANDY_RUNTIME_BIN_DIR)" ] || { echo "CANDY_RUNTIME_BIN_DIR is required"; exit 1; }
	[ -x "$(CANDY_RUNTIME_BIN_DIR)/candy-netd" ] || { echo "missing Runtime binary: candy-netd"; exit 1; }
	cp "$(CANDY_RUNTIME_BIN_DIR)/candy-netd" "$(PKG_BUILD_DIR)/candy-netd"
endef

define Build/Compile
endef

define Package/candy-client/install
	$(INSTALL_DIR) $(1)/usr/bin/
	$(INSTALL_BIN) ./candy-client $(1)/usr/bin/candy-client
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/candy-netd $(1)/usr/bin/candy-netd
	$(INSTALL_BIN) ./candy-sdwan $(1)/usr/bin/candy-sdwan
	ln -sf candy-client $(1)/usr/bin/client-cli
	$(INSTALL_DIR) $(1)/usr/libexec
	$(INSTALL_BIN) ./candy-core-manager $(1)/usr/libexec/candy-core-manager
	$(INSTALL_BIN) ./candy-update-manager $(1)/usr/libexec/candy-update-manager
	$(INSTALL_BIN) ./candy-runtime-health-check $(1)/usr/libexec/candy-runtime-health-check
	$(SED) 's|^RUNTIME_VERSION=.*|RUNTIME_VERSION=$$$${CANDY_RUNTIME_VERSION:-$(PKG_VERSION)}|' $(1)/usr/libexec/candy-update-manager
	$(SED) 's|^RUNTIME_RELEASE=.*|RUNTIME_RELEASE=$$$${CANDY_RUNTIME_RELEASE:-$(PKG_RELEASE)}|' $(1)/usr/libexec/candy-update-manager
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./candy.init $(1)/etc/init.d/candy
	$(SED) 's|^CANDY_VERSION=.*|CANDY_VERSION=$$$${CANDY_VERSION:-$(PKG_VERSION)}|' $(1)/etc/init.d/candy
	$(SED) 's|^CANDY_RELEASE=.*|CANDY_RELEASE=$$$${CANDY_RELEASE:-$(PKG_RELEASE)}|' $(1)/etc/init.d/candy
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./candy.config $(1)/etc/config/candy
	$(INSTALL_DIR) $(1)/usr/share/candy/rulesets
	$(INSTALL_DATA) ./rulesets/cn-ip.cidr $(1)/usr/share/candy/rulesets/cn-ip.cidr
	$(INSTALL_DATA) ./rulesets/gfwlist.domains $(1)/usr/share/candy/rulesets/gfwlist.domains
	$(INSTALL_DATA) ./rulesets/PROVENANCE.md $(1)/usr/share/candy/rulesets/PROVENANCE.md
	$(INSTALL_DATA) ./rulesets/manifest.json $(1)/usr/share/candy/rulesets/manifest.json
	$(INSTALL_DATA) ./rulesets/SHA256SUMS $(1)/usr/share/candy/rulesets/SHA256SUMS
	$(INSTALL_DIR) $(1)/usr/share/candy/keys
	$(INSTALL_DATA) ./catalog-release.pub $(1)/usr/share/candy/keys/catalog-release.pub
endef

define Package/candy-client/postinst
#!/bin/sh
[ -n "$$IPKG_INSTROOT" ] && exit 0
if [ "$$(id -u candy-sdwan 2>/dev/null)" != "789" ]; then
	awk -F: '$$1 != "candy-sdwan" && $$3 == 789 { found=1 } END { exit !found }' /etc/passwd && exit 1
	awk -F: '$$1 != "candy-sdwan" && $$3 == 789 { found=1 } END { exit !found }' /etc/group && exit 1
	sed -i 's/^\(candy-sdwan:[^:]*:\)[0-9][0-9]*:[0-9][0-9]*:/\1789:789:/' /etc/passwd || exit 1
	sed -i 's/^\(candy-sdwan:[^:]*:\)[0-9][0-9]*:/\1789:/' /etc/group || exit 1
fi
if [ -f /etc/init.d/candy.apk-new ]; then
	cp /etc/init.d/candy.apk-new /etc/init.d/candy
	chmod 0755 /etc/init.d/candy
	rm -f /etc/init.d/candy.apk-new
fi
mkdir -p /var/lib/candy/epochs /var/lib/candy/policy-cache /var/lib/candy/grant-cache /var/lib/candy/update
	chown root:root /var/lib/candy
	chmod 0711 /var/lib/candy
	chmod 0700 /var/lib/candy/epochs /var/lib/candy/policy-cache /var/lib/candy/grant-cache /var/lib/candy/update
exit 0
endef

define Package/candy-client/prerm
#!/bin/sh
[ -n "$$IPKG_INSTROOT" ] && exit 0
if [ -x /etc/init.d/candy ]; then
	/etc/init.d/candy disable >/dev/null 2>&1 || true
	/etc/init.d/candy stop >/dev/null 2>&1 || exit 1
fi
# Identity, signed caches, netd journal, and epoch files are deliberately kept.
exit 0
endef

$(eval $(call BuildPackage,candy-client))
