obj-m := antipatterns.o
antipatterns-y := bug.o fmtstring.o infoleaks.o main.o taint.o

KDIR  := /lib/modules/$(shell uname -r)/build
PWD   := $(shell pwd)

default:
	$(MAKE) -C $(KDIR) M=$(PWD) modules V=1

clean:
	rm *.o *.ko
