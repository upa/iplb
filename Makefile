KERNELSRCDIR = /lib/modules/$(shell uname -r)/build
BUILD_DIR := $(shell pwd)
VERBOSE = 0
c_flags = -DDEBUG

CC = gcc -O0 -Wall

obj-m := iplb.o

iplb-objs := iplb_main.o patricia/patricia.o 

all:
	make -C $(KERNELSRCDIR) SUBDIRS=$(BUILD_DIR) KBUILD_VERBOSE=$(VERBOSE)  modules

#.c.o:
#	$(CC) -Iinclude -I$(INC) -c $< -o $@

clean:
	rm -f *.o
	rm -f *.ko
	rm -f *.mod.c
	rm -f *~
	rm modules.order
	rm Module.symvers
	rm patricia/patricia.o
