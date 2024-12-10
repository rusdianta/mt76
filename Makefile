EXTRA_CFLAGS += -Werror -DCONFIG_MT76_LEDS

obj-m := mt76.o
obj-$(CONFIG_MT7603E) += mt7603/
obj-$(CONFIG_MT76_USB) += mt76-usb.o

mt76-y := \
	mmio.o util.o trace.o dma.o mac80211.o debugfs.o eeprom.o \
	tx.o agg-rx.o mcu.o

mt76-usb-y := usb.o usb_trace.o
