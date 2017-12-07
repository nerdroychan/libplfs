CC=g++

.PHONY: install 

all: libplfs.so

install: libplfs.so
	cp libplfs.so /usr/local/lib/

libplfs.so : libplfs.cpp libplfs.h
	$(CC) -fPIC -shared -o libplfs.so libplfs.cpp -Wl,-R/usr/local/lib -L/usr/local/lib -lplfs -ldl -O3

test : test.cpp
	$(CC) -o test test.cpp -lplfs

clean :
	rm -f *.so *.o
