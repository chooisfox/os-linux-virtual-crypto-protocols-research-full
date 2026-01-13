OUT_DIR := build
MOD_NAME := ec256_vko_generic

ifneq ($(KERNELRELEASE),)
    VPATH := $(src)/..

    obj-m += $(MOD_NAME).o

    $(MOD_NAME)-y := gost_vko.o \
                     gost_vko_selftest.o \
                     gost_vko_helper.o \
                     gost_curves.o \
                     gost_math.o


    ccflags-y := -D'pr_fmt(fmt)=KBUILD_MODNAME ": " fmt' \
                 -Ofast -march=native

else
    KDIR ?= /lib/modules/$(shell uname -r)/build
    PWD := $(shell pwd)
    BUILD_DIR := $(PWD)/$(OUT_DIR)
    KERNEL_INCLUDE_DIR := $(KDIR)/include/crypto

default:
	mkdir -p $(BUILD_DIR)
	mkdir -p $(BUILD_DIR)/crypto
	cp Makefile $(BUILD_DIR)/
	$(MAKE) -C $(KDIR) M=$(BUILD_DIR) modules

clean:
	rm -rf $(BUILD_DIR)

install:
	$(MAKE) -C $(KDIR) M=$(BUILD_DIR) modules_install

	depmod -a
endif
