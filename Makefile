EXTRA_CFLAGS += -Werror

obj-m := mt76.o

obj-$(CONFIG_MT7603E) += mt7603/

mt76-y := \
	mmio.o util.o trace.o dma.o mac80211.o debugfs.o eeprom.o tx.o agg-rx.o
