EXTRA_CFLAGS += -Werror -DCONFIG_MT76_LEDS

obj-m := mt76.o
obj-$(CONFIG_MT7603E) += mt7603/

mt76-y := \
	mmio.o util.o trace.o dma.o mac80211.o debugfs.o eeprom.o \
	tx.o agg-rx.o mcu.o airtime.o

mt76-$(CONFIG_PCI) += pci.o
