PWD := $(shell pwd)
KDIR = ..

obj-m += qemu_edu.o

all:
	make -C $(KDIR) M=$(PWD) modules
clean:
	make -C $(KDIR) M=$(PWD) clean

