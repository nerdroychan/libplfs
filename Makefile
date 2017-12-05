CC=g++


libplfs.so : libplfs.cpp libplfs.h
	$(CC) -fPIC -shared -o libplfs.so libplfs.cpp -Wl,-R/usr/local/lib -L/usr/local/lib -lplfs -ldl -O3

test : test.cpp
	$(CC) -o test test.cpp

clean :
	rm -f *.so *.o
