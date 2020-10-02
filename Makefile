CC=gcc

cstore: main.o util.o store.o crypto.o algo-lib/aes.o algo-lib/sha256.o
	$(CC) main.o util.o store.o crypto.o algo-lib/aes.o algo-lib/sha256.o -o cstore

main.o: main.c

util.o: util.c util.h crypto.h

store.o: store.c store.h crypto.h algo-lib/sha256.h util.h

crypto.o: crypto.c crypto.h util.h algo-lib/aes.h algo-lib/sha256.h

aes.o: algo-lib/aes.c algo-lib/aes.h

sha256.o: algo-lib/sha256.c algo-lib/sha256.h

.PHONY: clean
make clean:
	rm -rf *.o */*.o *.test *-extracted cstore

all: clean main

test: cstore test.sh
	bash ./test.sh