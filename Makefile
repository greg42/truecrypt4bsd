.DEFAULT: all
.PHONY: clean

OBJS=ggate.o cipher.o hash.o crc32.o pbkdf2.o fileformat.o\
	  rmd160.o xts.o twofish.o sha1.o rijndael-alg-fst.o\
	  rijndael-api-fst.o sha2.o mac.o serpent.o whirlpool.o\
	  keyfile.o

CFLAGS = -std=c99 -Wall -pedantic -DLIBGEOM

all: ggateTruecrypt

clean:
	@-rm $(OBJS) *.core ggateTruecrypt > /dev/null 2>&1

.c.o: 
	$(CC) -o $@ -c $(CFLAGS) $<

ggateTruecrypt: ggateTruecrypt.c $(OBJS)
	$(CC) $(CFLAGS) -lutil -lgeom -o ggateTruecrypt ggateTruecrypt.c $(OBJS)

