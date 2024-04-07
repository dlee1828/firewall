obj-m += firewall.o
# obj-m += proc-example.o

firewall-module-objs := firewall.o util.o

PWD := $(CURDIR)

EXTRA_CFLAGS=-I/usr/include/arpa

all: build load 

reset:
	make clean
	make
	sudo dmesg -w 


build:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	sudo rmmod firewall
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

load: build
	sudo insmod firewall.ko
	