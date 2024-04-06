obj-m += hello.o
obj-m += hello-2.o
obj-m += netfilter-example.o
obj-m += proc-example.o

PWD := $(CURDIR)

EXTRA_CFLAGS=-I/usr/include/arpa


all: build load 

build:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	sudo rmmod netfilter-example
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

load: build
	sudo insmod netfilter-example.ko
	