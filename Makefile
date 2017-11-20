# Compiler
CC=g++

stdplfs.so : stdplfs.cpp stdplfs.h
	$(CC) -fPIC -shared -o stdplfs.so stdplfs.cpp -Wl,-R/usr/local/lib -L/usr/local/lib -lplfs -ldl -O3

test : test.cpp
	$(CC) -o test test.cpp

clean :
	rm -f *.so *.o
