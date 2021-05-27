obj-m := antipatterns.o
antipatterns-y := bug.o infoleaks.o main.o taint.o

KDIR  := /lib/modules/$(shell uname -r)/build
PWD   := $(shell pwd)

default:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
