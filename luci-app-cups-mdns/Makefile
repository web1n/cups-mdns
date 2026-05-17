#
# Copyright (C) 2026 web1n
#
# This is free software, licensed under the Apache License, Version 2.0 .
#

include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-cups-mdns
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

LUCI_TITLE:=CUPS mDNS AirPrint Service
LUCI_DEPENDS:=+luci-base +cups-mdns +cups-mdns-print
LUCI_PKGARCH:=all

PKG_LICENSE:=Apache-2.0
PKG_MAINTAINER:=web1n

include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage - OpenWrt buildroot signature