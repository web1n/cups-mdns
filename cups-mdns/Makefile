#
# Copyright (C) 2026 web1n
#
# This is free software, licensed under the Apache License, Version 2.0 .
#

ifndef TOPDIR
CC ?= gcc
CFLAGS ?= -Wall -Os -Isrc
LDFLAGS ?= -lcurl -lresolv
OUTDIR = out
SRCS = src/main.c src/dns.c src/mdns.c src/net.c src/txt.c src/ipp.c
TARGET = $(OUTDIR)/cups-mdns
SRCS_PRINT = src/print.c src/ipp.c src/txt.c
TARGET_PRINT = $(OUTDIR)/cups-mdns-print

.PHONY: all clean
all: $(TARGET) $(TARGET_PRINT)

$(OUTDIR):
	mkdir -p $(OUTDIR)

$(TARGET): $(SRCS) | $(OUTDIR)
	$(CC) $(CFLAGS) -o $@ $(SRCS) $(LDFLAGS)

$(TARGET_PRINT): $(SRCS_PRINT) | $(OUTDIR)
	$(CC) $(CFLAGS) -o $@ $(SRCS_PRINT) $(LDFLAGS)

clean:
	rm -rf $(OUTDIR)

else

include $(TOPDIR)/rules.mk

PKG_NAME:=cups-mdns
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

PKG_MAINTAINER:=web1n
PKG_LICENSE:=Apache-2.0
PKG_BUILD_FLAGS:=gc-sections

include $(INCLUDE_DIR)/package.mk

define Package/cups-mdns
	SECTION:=net
	CATEGORY:=Network
	SUBMENU:=Printing
	TITLE:=CUPS mDNS backend daemon
	DEPENDS:=+libcurl
endef

define Package/cups-mdns/description
	Background daemon that queries a remote CUPS server via IPP
	and advertises found printers via mDNS for
	printer discovery by Apple devices.
endef

define Package/cups-mdns-print
	SECTION:=net
	CATEGORY:=Network
	SUBMENU:=Printing
	TITLE:=CUPS Printer Query Tool
	DEPENDS:=+libcurl
endef

define Package/cups-mdns-print/description
	Simple command-line utility to query a CUPS server via IPP
	and display all available printers.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(TARGET_CC) $(TARGET_CFLAGS) -I$(PKG_BUILD_DIR)/src \
		-o $(PKG_BUILD_DIR)/cups-mdns \
		$(PKG_BUILD_DIR)/src/main.c \
		$(PKG_BUILD_DIR)/src/dns.c \
		$(PKG_BUILD_DIR)/src/mdns.c \
		$(PKG_BUILD_DIR)/src/net.c \
		$(PKG_BUILD_DIR)/src/txt.c \
		$(PKG_BUILD_DIR)/src/ipp.c \
		$(TARGET_LDFLAGS) -lcurl

	$(TARGET_CC) $(TARGET_CFLAGS) -I$(PKG_BUILD_DIR)/src \
		-o $(PKG_BUILD_DIR)/cups-mdns-print \
		$(PKG_BUILD_DIR)/src/print.c \
		$(PKG_BUILD_DIR)/src/ipp.c \
		$(PKG_BUILD_DIR)/src/txt.c \
		$(TARGET_LDFLAGS) -lcurl
endef

define Package/cups-mdns/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_DIR) $(1)/etc/config

	$(INSTALL_BIN) $(PKG_BUILD_DIR)/cups-mdns $(1)/usr/bin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/root/etc/init.d/cups-mdns $(1)/etc/init.d/
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/root/etc/config/cups-mdns $(1)/etc/config/
endef

define Package/cups-mdns-print/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/cups-mdns-print $(1)/usr/bin/
endef

$(eval $(call BuildPackage,cups-mdns))
$(eval $(call BuildPackage,cups-mdns-print))

endif
