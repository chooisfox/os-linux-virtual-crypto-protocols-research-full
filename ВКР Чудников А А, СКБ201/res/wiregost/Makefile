MODULE_NAME := wiregost
OUT_DIR := build

ifneq ($(KERNELRELEASE),)

    VPATH := $(src)/..

    ccflags-y := -D'pr_fmt(fmt)=KBUILD_MODNAME ": " fmt' \
                 -I$(src)/.. -Ofast -march=native

    ifdef DEBUG
    ccflags-y += -DDEBUG
    endif

    $(MODULE_NAME)-y := main.o \
                        noise.o \
                        device.o \
                        peer.o \
                        timers.o \
                        queueing.o \
                        send.o \
                        receive.o \
                        socket.o \
                        peerlookup.o \
                        allowedips.o \
                        ratelimiter.o \
                        cookie.o \
                        netlink.o \
                        generated/netlink.o \
                        gost/gost_hmac.o \
                        gost/gost_streebog.o \
                        gost/gost_kuznyechik.o \
                        gost/gost_ec256.o

    KPP_VKO_BUILD_DIR := $(PWD)/lkm/ec256_vko/build
    KBUILD_EXTRA_SYMBOLS += $(KPP_VKO_BUILD_DIR)/Module.symvers


    obj-m := $(MODULE_NAME).o

else
    KDIR ?= /lib/modules/$(shell uname -r)/build
    PWD := $(shell pwd)

    BUILD_DIR := $(PWD)/$(OUT_DIR)

default:
	mkdir -p $(BUILD_DIR)
	cp Makefile $(BUILD_DIR)/
	$(MAKE) -C $(KDIR) M=$(BUILD_DIR) modules

clean:
	rm -rf $(BUILD_DIR)

install:
	$(MAKE) -C $(KDIR) M=$(BUILD_DIR) modules_install

endif
