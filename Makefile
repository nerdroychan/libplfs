# Compiler
CC=g++

stdplfs.so : stdplfs.cpp
	$(CC) -fPIC -shared -o stdplfs.so stdplfs.cpp -g -Wl,-R/usr/local/lib -L/usr/local/lib -lplfs -ldl

test : test.cpp
	$(CC) -o test test.cpp

clean :
	rm -f *.so *.o