ifeq ($(KERNELRELEASE),)

KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

.PHONY: build clean

build: build_ipt
	$(MAKE) -C "$(KERNELDIR)" "M=$(PWD)" modules

# TODO: Adequate gcc
build_ipt:
	gcc -shared -fpic -o libxt_FAKEROUTER.so libxt_FAKEROUTER.c

clean:
	rm -rf *.o *~ core .depend .*.cmd *.ko *.mod.c

else


obj-m := xt_FAKEROUTER.o

endif
