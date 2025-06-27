PWD := $(shell pwd)
KDIR = ..

obj-m += qemu_edu.o
obj-m += my_qemu_edu.o
obj-m += disagg_benchmark.o

all:
	make -C $(KDIR) M=$(PWD) modules
clean:
	make -C $(KDIR) M=$(PWD) clean

