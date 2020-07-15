# SPDX-License-Identifier: GPL-2.0-only
EXTRA_CFLAGS += -Werror -DCONFIG_MT76_LEDS
obj-m := mt76.o
obj-$(CONFIG_MT7603E) += mt7603/
obj-$(CONFIG_MT76_USB) += mt76-usb.o
obj-$(CONFIG_MT76_SDIO) += mt76-sdio.o

mt76-y := \
	mmio.o util.o trace.o dma.o mac80211.o debugfs.o eeprom.o \
	tx.o agg-rx.o mcu.o airtime.o

mt76-$(CONFIG_PCI) += pci.o
mt76-$(CONFIG_NL80211_TESTMODE) += testmode.o

mt76-usb-y := usb.o usb_trace.o
mt76-sdio-y := sdio.o

CFLAGS_trace.o := -I$(src)
CFLAGS_usb_trace.o := -I$(src)
