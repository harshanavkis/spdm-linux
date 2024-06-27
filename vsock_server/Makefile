PWD := $(shell pwd)
KDIR = ..

obj-m += vsock_server.o

all:
	make -C $(KDIR) M=$(PWD) modules
clean:
	make -C $(KDIR) M=$(PWD) clean

