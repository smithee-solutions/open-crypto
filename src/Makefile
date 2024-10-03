BUILD_LIBS=libeac-crypto_open-gcm.a
BUILD_DEST_ENCODE=../opt/openbadger

INCLUDES = -I../include -I/opt/openbadger/include -I/opt/crypto/include
CFLAGS= -c -g ${INCLUDES} -Wall -Werror
CC=clang

all: ${BUILD_LIBS} 

clean:
	rm -rf *.a *.o core a.out

package:	all
	mkdir -p ${BUILD_DEST_ENCODE}/lib
	cp libeac-crypto_open-gcm.a ${BUILD_DEST_ENCODE}/lib

libeac-crypto_open-gcm.a:	eac-crypto_open-gcm.o
	ar r libeac-crypto_open-gcm.a eac-crypto_open-gcm.o \
	  ../build/aes.o ../build/gcm.o

eac-crypto_open-gcm.o:	eac-crypto_open-gcm.c
	${CC} ${CFLAGS} eac-crypto_open-gcm.c

