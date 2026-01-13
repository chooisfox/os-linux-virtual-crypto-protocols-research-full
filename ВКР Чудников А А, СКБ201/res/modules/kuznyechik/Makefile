OUT_DIR := build

MOD_KUZ_GENERIC := kuznyechik_generic

ifneq ($(KERNELRELEASE),)

    VPATH := $(src)/..

    ccflags-y := -D'pr_fmt(fmt)=KBUILD_MODNAME ": " fmt' \
                 -I$(src)/.. \
                 -I$(src) \
                 -Duint8_t=u8 -Ofast -march=native

    ifeq ($(CONFIG_LTO_CLANG),y)
        ccflags-y += -flto=thin
    endif

    obj-m += $(MOD_KUZ_GENERIC).o
    $(MOD_KUZ_GENERIC)-y := kuznyechik.o


else
    KDIR ?= /lib/modules/$(shell uname -r)/build
    PWD := $(shell pwd)
    BUILD_DIR := $(PWD)/$(OUT_DIR)
    KERNEL_INCLUDE_DIR := $(KDIR)/include/crypto

default:
	mkdir -p $(BUILD_DIR)
	mkdir -p $(BUILD_DIR)/crypto
	cp Makefile $(BUILD_DIR)/
	cp crypto/kuznyechik.h $(BUILD_DIR)/crypto/
	$(MAKE) -C $(KDIR) M=$(BUILD_DIR) modules

clean:
	rm -rf $(BUILD_DIR)

install:
	$(MAKE) -C $(KDIR) M=$(BUILD_DIR) modules_install
	@echo "Installing header..."
	@if [ -w $(KERNEL_INCLUDE_DIR) ]; then \
		cp $(PWD)/crypto/kuznyechik.h $(KERNEL_INCLUDE_DIR)/; \
	fi
	depmod -a

endif
