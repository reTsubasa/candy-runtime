include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-candy
PKG_VERSION:=0.4.0
# Internal OpenWrt package revision; LuCI displays PKG_VERSION only.
PKG_RELEASE:=65

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/luci-app-candy
  SECTION:=luci
  CATEGORY:=LuCI
  SUBMENU:=3. Applications
  TITLE:=LuCI support for Candy client
  PKGARCH:=all
  DEPENDS:=+candy-client +luci-base +luci-compat
endef

define Package/luci-app-candy/description
  Web management for the Candy OpenWrt runtime and external Core bundles.
endef

define Build/Prepare
	$(INSTALL_DIR) $(PKG_BUILD_DIR)
	$(CP) $(CURDIR)/root $(PKG_BUILD_DIR)
	$(HOSTCC) $(HOST_CFLAGS) -o $(PKG_BUILD_DIR)/po2lmo \
		$(CURDIR)/tools/po2lmo/src/po2lmo.c \
		$(CURDIR)/tools/po2lmo/src/template_lmo.c
	$(foreach po,$(wildcard $(CURDIR)/po/zh-cn/*.po), \
		$(PKG_BUILD_DIR)/po2lmo $(po) $(PKG_BUILD_DIR)/$(patsubst %.po,%.lmo,$(notdir $(po)));)
endef

define Build/Compile
endef

define Package/luci-app-candy/install
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/i18n
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/*.zh-cn.lmo $(1)/usr/lib/lua/luci/i18n/
	$(CP) $(PKG_BUILD_DIR)/root/* $(1)/
endef

$(eval $(call BuildPackage,luci-app-candy))
