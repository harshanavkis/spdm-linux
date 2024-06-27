PWD := $(shell pwd)
KDIR = ..

obj-m += vsock_combined.o

all:
	make -C $(KDIR) M=$(PWD) modules
clean:
	make -C $(KDIR) M=$(PWD) clean

