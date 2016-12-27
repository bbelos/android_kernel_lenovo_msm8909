#
# Makefile for the input core drivers.
#

# Each configuration option enables a list of files.
obj-$(CONFIG_TOUCHSCREEN_FTS)	+= ft5x36_ts.o
obj-$(CONFIG_TOUCHSCREEN_FTS)	+= ft5x36_ex.o
obj-$(CONFIG_TOUCHSCREEN_FTS)	+= ft5x36_ctl.o
extlibs :=$(PWD)/drivers/input/touchscreen/FT5626/ft_gesture_lib.a
ldflags-y+=--whole-archive $(extlibs) --no-whole-archive