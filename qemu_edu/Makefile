PWD := $(shell pwd)
KDIR = ..

obj-m += qemu_edu.o
obj-m += my_qemu_edu.o
obj-m += benchmark-mmio_read.o
obj-m += benchmark-dma_map_single.o
obj-m += benchmark-dma_from_device.o
obj-m += benchmark-dma_to_device.o
obj-m += benchmark-crypto.o

all:
	make -C $(KDIR) M=$(PWD) modules
clean:
	make -C $(KDIR) M=$(PWD) clean

