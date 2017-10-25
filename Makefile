# Compiler
CC=g++

# PLFS dynamic library path
PLFS_LIB_PATH="/usr/local/lib/"

CCFLAGS=-std=c++11
PARAMS=-Wl,-R$(PLFS_LIB_PATH) -g -L$(PLFS_LIB_PATH) -lplfs

test : libplfs.cpp
	$(CC) $(CCFLAGS) -c libplfs.cpp -o libplfs.o
	$(CC) $(CCFLAGS) -o test libplfs.o $(PARAMS)
	rm libplfs.o

clean :
	rm -f *.so *.o test