PWD := $(shell pwd)
KDIR = ..

obj-m += vsock_client.o

all:
	make -C $(KDIR) M=$(PWD) modules
clean:
	make -C $(KDIR) M=$(PWD) clean

