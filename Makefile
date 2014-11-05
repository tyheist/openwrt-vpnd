include $(TOPDIR)/rules.mk

PKG_NAME:=vpnd
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

define Package/vpnd
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=VPN
  DEPENDS:=+libuci +libubus +libubox
  TITLE:=vpn manage daemon
endef

TARGET_CFLAGS += \
	-I$(STAGING_DIR)/usr/include				 

CMAKE_OPTIONS +=\
	-DDEBUG=1				

define Build/Prepare
    mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Package/vpnd/install
    $(INSTALL_DIR) $(1)/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/vpnd $(1)/sbin/
endef

$(eval $(call BuildPackage,vpnd))
