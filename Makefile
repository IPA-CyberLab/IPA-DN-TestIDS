# Makefile

UNAME := $(shell uname)

OPTIONS_COMPILE_DEBUG=-D_DEBUG -DDEBUG -D_REENTRANT -DREENTRANT -D_THREAD_SAFE -D_THREADSAFE -DTHREAD_SAFE -DTHREADSAFE -D_FILE_OFFSET_BITS=64 -I./nativelib/nativelib_src/ -I/usr/local/opt/openssl/include -I /opt/local/include/ -g -fsigned-char

OPTIONS_LINK_DEBUG=-g -fsigned-char -lm -lpthread -lssl -lcrypto -lreadline -lncurses -lz

OPTIONS_COMPILE_RELEASE=-DNDEBUG -DVPN_SPEED -D_REENTRANT -DREENTRANT -D_THREAD_SAFE -D_THREADSAFE -DTHREAD_SAFE -DTHREADSAFE -D_FILE_OFFSET_BITS=64 -I./nativelib/nativelib_src/ -I/usr/local/opt/openssl/include -I /opt/local/include/ -O2 -fsigned-char

OPTIONS_LINK_RELEASE=-O2 -fsigned-char -lm -lpthread -lssl -lcrypto -lreadline -lncurses -lz

HEADERS_NATIVELIB=nativelib/nativelib_src/nativelib.h

OBJECTS_NATIVELIB=obj/obj/unix/nativelib.o

ifeq ($(UNAME),Darwin)
	OPTIONS_LINK_DEBUG += -lpcap -liconv
	OPTIONS_LINK_RELEASE += -lpcap -liconv
endif

ifeq ($(UNAME),Linux)
	OPTIONS_LINK_DEBUG += -ldl -lrt
	OPTIONS_LINK_RELEASE += -ldl -lrt
endif

ifeq ($(DEBUG),YES)
	OPTIONS_COMPILE=$(OPTIONS_COMPILE_DEBUG)
	OPTIONS_LINK=$(OPTIONS_LINK_DEBUG)
else
	OPTIONS_COMPILE=$(OPTIONS_COMPILE_RELEASE)
	OPTIONS_LINK=$(OPTIONS_LINK_RELEASE)
endif

HEADERS=$(wildcard *.h)
SRCS=$(wildcard *.c)
OBJS=$(addprefix obj/obj/unix/,$(patsubst %.c,%.o,$(SRCS)))


# Build Action
default:	build

build:	$(OBJECTS_NATIVELIB) bin/lowether

obj/obj/unix/nativelib.o: nativelib/nativelib_src/nativelib.c $(HEADERS_NATIVELIB)
	@mkdir -p obj/obj/unix/
	@mkdir -p bin/
	$(CC) $(OPTIONS_COMPILE) -c nativelib/nativelib_src/nativelib.c -o obj/obj/unix/nativelib.o

obj/obj/unix/%.o: %.c
	$(CC) $(OPTIONS_COMPILE) -c $< -o $@

bin/lowether: obj/obj/unix/nativelib.o $(HEADERS_NATIVELIB) $(OBJECTS_NATIVELIB) $(OBJS)
	$(CC) obj/obj/unix/nativelib.o $(OBJS) $(OPTIONS_LINK) -o bin/lowether

clean:
	-rm -f obj/obj/unix/*.o
	-rm -f bin/lowether

help:
	@echo "make [DEBUG=YES]"
	@echo "make install"
	@echo "make clean"


