ROOT		:= $(PWD)
CC			:= gcc

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

