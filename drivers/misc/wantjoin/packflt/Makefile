#
# Makefile - WantJoin information tech co.ltd driver.
# Copyright(c) 2015, WantJoin information tech co.ltd.
#

#ccflags-$(CONFIG_WANTJOIN_PACKFLT) += -I$(srctree) -D__BTREE2__ -D__DEBUG__ -D__DROP_ONDNSREQ__
ccflags-y += -I$(srctree) -D__BTREE2__ -D__ALLOW_DIRECT_IP__ -D__KERNEL_3_10__
#ccflags-$(CONFIG_WANTJOIN_PACKFLT) += -I$(srctree) -D__BTREE2__ -D__ALLOW_DIRECT_IP__ -D__KERNEL_3_10__
obj-$(CONFIG_WANTJOIN_PACKFLT)	+= packfilter.o
#packflt-y	:= btree2.o packflt.o
packfilter-objs	:= btree2.o packflt.o

