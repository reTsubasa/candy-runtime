include $(TOPDIR)/rules.mk

PKG_NAME:=candy-client
PKG_VERSION:=0.4.0
# OpenWrt requires a package revision. This is internal metadata, not part of
# the Candy product version shown to users.
PKG_RELEASE:=80
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
	[ -x "$(CANDY_RUNTIME_BIN_DIR)/candy-sdwan-agent" ] || { echo "missing Runtime binary: candy-sdwan-agent"; exit 1; }
	[ -x "$(CANDY_RUNTIME_BIN_DIR)/candy-cloud-enroll" ] || { echo "missing Runtime binary: candy-cloud-enroll"; exit 1; }
	[ -x "$(CANDY_RUNTIME_BIN_DIR)/candy-cloud-sync" ] || { echo "missing Runtime binary: candy-cloud-sync"; exit 1; }
	[ -x "./candy-sdwan-runtime" ] || { echo "missing Runtime binary: candy-sdwan-runtime"; exit 1; }
	cp "$(CANDY_RUNTIME_BIN_DIR)/candy-netd" "$(PKG_BUILD_DIR)/candy-netd"
	cp "$(CANDY_RUNTIME_BIN_DIR)/candy-sdwan-agent" "$(PKG_BUILD_DIR)/candy-sdwan-agent"
	cp "$(CANDY_RUNTIME_BIN_DIR)/candy-cloud-enroll" "$(PKG_BUILD_DIR)/candy-cloud-enroll"
	cp "$(CANDY_RUNTIME_BIN_DIR)/candy-cloud-sync" "$(PKG_BUILD_DIR)/candy-cloud-sync"
	cp "./candy-sdwan-runtime" "$(PKG_BUILD_DIR)/candy-sdwan-runtime"
endef

define Build/Compile
endef

define Package/candy-client/install
	$(INSTALL_DIR) $(1)/usr/bin/
	$(INSTALL_BIN) ./candy-client $(1)/usr/bin/candy-client
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/candy-netd $(1)/usr/bin/candy-netd
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/candy-sdwan-agent $(1)/usr/bin/candy-sdwan-agent
	$(INSTALL_BIN) ./candy-sdwan $(1)/usr/bin/candy-sdwan
	ln -sf candy-client $(1)/usr/bin/client-cli
	$(INSTALL_DIR) $(1)/usr/libexec
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/candy-sdwan-runtime $(1)/usr/libexec/candy-sdwan-runtime
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/candy-cloud-enroll $(1)/usr/libexec/candy-cloud-enroll
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/candy-cloud-sync $(1)/usr/libexec/candy-cloud-sync
	$(INSTALL_BIN) ./candy-cloud-sync-loop $(1)/usr/libexec/candy-cloud-sync-loop
	$(INSTALL_BIN) ./candy-core-manager $(1)/usr/libexec/candy-core-manager
	$(INSTALL_BIN) ./candy-update-manager $(1)/usr/libexec/candy-update-manager
	$(INSTALL_BIN) ./candy-runtime-health-check $(1)/usr/libexec/candy-runtime-health-check
	$(SED) 's|^RUNTIME_VERSION=.*|RUNTIME_VERSION=$$$${CANDY_RUNTIME_VERSION:-$(PKG_VERSION)}|' $(1)/usr/libexec/candy-update-manager
	$(SED) 's|^RUNTIME_RELEASE=.*|RUNTIME_RELEASE=$$$${CANDY_RUNTIME_RELEASE:-$(PKG_RELEASE)}|' $(1)/usr/libexec/candy-update-manager
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./candy-cloud-sync.init $(1)/etc/init.d/candy-cloud-sync
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
	$(INSTALL_DATA) ./core-release.pub $(1)/usr/share/candy/keys/core-release.pub
	$(INSTALL_DIR) $(1)/usr/share/nftables.d/chain-pre/forward
	$(INSTALL_DATA) ./nftables/10-candy-sdwan.nft $(1)/usr/share/nftables.d/chain-pre/forward/10-candy-sdwan.nft
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
# Create runtime directories under /var/lib/candy (volatile paths are OK here).
mkdir -p /etc/candy/epochs /var/lib/candy/policy-cache /var/lib/candy/grant-cache /var/lib/candy/update
chown root:root /var/lib/candy
chmod 0711 /var/lib/candy
chmod 0700 /etc/candy/epochs /var/lib/candy/policy-cache /var/lib/candy/grant-cache /var/lib/candy/update
# Create persistent SD-WAN state directory under /etc/candy/.
# If legacy data exists at /var/lib/candy/sdwan (real directory, not symlink),
# migrate it to the persistent location and create a compat symlink.
if [ -d /var/lib/candy/sdwan ] && [ ! -L /var/lib/candy/sdwan ]; then
	if [ ! -d /etc/candy/sdwan ]; then
		mkdir -p /etc/candy
		mv /var/lib/candy/sdwan /etc/candy/sdwan || exit 1
		ln -s /etc/candy/sdwan /var/lib/candy/sdwan || exit 1
	fi
elif [ ! -e /var/lib/candy/sdwan ] && [ ! -L /var/lib/candy/sdwan ]; then
	mkdir -p /etc/candy/sdwan
	ln -s /etc/candy/sdwan /var/lib/candy/sdwan || exit 1
fi
# Create persistent epochs directory under /etc/candy/ and compat symlink.
# If legacy epoch data exists at /var/lib/candy/epochs (real directory, not symlink),
# migrate it to the persistent location.
if [ -d /var/lib/candy/epochs ] && [ ! -L /var/lib/candy/epochs ]; then
	if [ ! -d /etc/candy/epochs ]; then
		mkdir -p /etc/candy
		mv /var/lib/candy/epochs /etc/candy/epochs || exit 1
		ln -s /etc/candy/epochs /var/lib/candy/epochs || exit 1
	fi
elif [ ! -e /var/lib/candy/epochs ] && [ ! -L /var/lib/candy/epochs ]; then
	mkdir -p /etc/candy/epochs
	ln -s /etc/candy/epochs /var/lib/candy/epochs || exit 1
fi
# Migrate legacy instance-id if it exists at the old location.
if [ -f /var/lib/candy/instance-id ] && [ ! -L /var/lib/candy/instance-id ] && [ ! -e /etc/candy/instance-id ]; then
	mkdir -p /etc/candy
	cp -p /var/lib/candy/instance-id /etc/candy/instance-id || exit 1
	chown root:candy-sdwan /etc/candy/instance-id 2>/dev/null || true
	chmod 0640 /etc/candy/instance-id || true
fi
# Migrate legacy fault state if it exists at the old location.
if [ -f /var/lib/candy/runtime-fault.json ] && [ ! -L /var/lib/candy/runtime-fault.json ] && [ ! -e /etc/candy/runtime-fault.json ]; then
	mkdir -p /etc/candy
	cp -p /var/lib/candy/runtime-fault.json /etc/candy/runtime-fault.json || exit 1
	chmod 0600 /etc/candy/runtime-fault.json || true
fi
if [ -d /usr/lib/candy/cores ] && [ ! -L /usr/lib/candy/cores ]; then
	for core_dir in /usr/lib/candy/cores/*; do
		[ -d "$$core_dir" ] && [ ! -L "$$core_dir" ] || continue
		chmod 0755 "$$core_dir" || exit 1
	done
fi
# Apply permissions to the persistent SD-WAN state.
find /etc/candy/sdwan -xdev -type d -exec chmod 0700 {} \;
find /etc/candy/sdwan -xdev -type f -exec chmod 0600 {} \;
find /etc/candy/sdwan -xdev ! -type l -exec chown candy-sdwan:candy-sdwan {} \;
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
