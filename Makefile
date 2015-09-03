ROOT		:= $(PWD)
CC			:= gcc

RUBYINC1 := /usr/lib64/ruby/1.8/x86_64-linux
RUBYINC2 := /usr/lib/ruby/1.8/x86_64-linux

ifneq ("$(wildcard $(RUBYINC1))", "")
   RUBYINC := $(RUBYINC1)
else ifneq ("$(wildcard $(RUBYINC2))", "")
   RUBYINC := $(RUBYINC2)
endif

RUBYLIB1  := ruby
RUBYLIB2  := ruby1.8
RUBYLIB2  := ruby2.0

ifneq ($(wildcard /usr/lib/lib$(RUBYLIB1).so),)
   RUBYLIB := -l$(RUBYLIB1)
else ifneq ($(wildcard /usr/lib/lib$(RUBYLIB2).so),)
   RUBYLIB := -l$(RUBYLIB2)
else ifneq ($(wildcard /usr/lib64/lib$(RUBYLIB1).so),)
   RUBYLIB := -L/usr/lib64 -l$(RUBYLIB1)
else ifneq ($(wildcard /usr/lib64/lib$(RUBYLIB2).so),)
   RUBYLIB := -L/usr/lib64 -l$(RUBYLIB2)
endif

CFLAGS	:= -DDEBUG -I $(ROOT)/include -I $(ROOT)/libnids-1.23/src/ -ggdb 
LDFLAGS	:= -ggdb -L$(ROOT)/libnids-1.23/src/ -lnids -lpcap -lnet 

CORE_OBJ	:= src/wireplay.o src/log.o src/msg.o 

all: libnids-1.23/src/libnids.a wireplay

wireplay: libnids-1.23/src/libnids.a $(CORE_OBJ) 
	$(CC) -o wireplay $(CORE_OBJ) $(LDFLAGS)

libnids-1.23/src/libnids.a:
	cd libnids-1.23 && ./configure --enable-shared --disable-libglib && make all 

.PHONY: clean
clean:
	-rm -rf wireplay
	-rm -rf src/*.o
	-rm -rf core core.*
	-rm -rf a.out

install:
	mkdir -p /opt/wireplay/bin
	cp wireplay /opt/wireplay/bin/
	cp -r pcap /opt/wireplay/
	cp -r hooks /opt/wireplay/

