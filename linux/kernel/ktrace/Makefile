obj-m += probelkm.o
probelkm-objs := ktrace.o 

EXTRA_CFLAGS=-DLINUX -g
ifeq ($(shell uname -r|grep xen), 0)
EXTRA_CFLAGS += -DXEN
endif

ifeq ($(shell getconf LONG_BIT), 64)
EXTRA_CFLAGS += -D__64bit__
endif

MODULES_DIR := /lib/modules/$(shell uname -r)

KERNEL_DIR := ${MODULES_DIR}/build

all:
	make -C ${KERNEL_DIR} M=$(PWD);
clean:
	make -C ${KERNEL_DIR} M=$(PWD) $@;
