#include "plfs.h"
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <map>
#include <string>
#include <iostream>
#include <unistd.h>
#include <vector>

#define _DEBUG // DEBUG INFO SWITCH
#define endl std::endl;
#define FAKE_FILE_DIR "/tmp/"

#ifndef _DEBUG
#define dstream cnull
#else
#define dstream std::cout
#endif

std::ostream cnull(0); // A temporary solution for /dev/null like stream

// <FAKE_FD, <PLFS_FD_POINTER, FILENAME_STR> >
std::map<int, std::pair<Plfs_fd*, char*> > global_fd_table;
// <HASHED_FILENAME, PLFS_FD_POINTER>
std::vector<std::pair<int, Plfs_fd*> > plfs_files;


/*
  Random fake filename generator
  https://stackoverflow.com/questions/440133/

  This function will return a new allocated string address which
  points to an random file on disk.
*/
bool _SEEDED = false;
char* gen_rand_filename() {
    if (!_SEEDED) { srand(time(0)); _SEEDED = true; }
    char* ret = (char*)malloc(sizeof(char)*18);
    char* _ret = ret + 5;
    for (int c; c=rand()%62, *(_ret++) = (c+"07="[(c+16)/26])*(_ret-ret<18););
    ret[17] = '\0';
    strncpy(ret, FAKE_FILE_DIR, strlen(FAKE_FILE_DIR));
    return ret;
}

/*
  String HASH function
  https://stackoverflow.com/questions/7666509/hash-function-for-string

  Since we would like to check if a specific file's status, we need to
  store the currently opened filenames in a list. The process needs hashing.
*/
int string_hash(const char *str) {
    int hash = 5381, c;
    while (c = *str++) hash = ((hash << 5) + hash) + c;
    return hash;
}

/*
  A prototype of open() w/o mode

  *** UNDER CONSTRUCTION ***
*/
int _open(const char *path, int oflags) {
    dstream << "Trying to open file " << path << endl;
    Plfs_fd* plfs_fd = NULL;
    plfs_error_t err = PLFS_EAGAIN;
    int ret;
    while (err == PLFS_EAGAIN) {
        err = plfs_open(&plfs_fd, path, oflags, getpid(), 0755, NULL);
    }
    if (err == PLFS_SUCCESS) {
        dstream << "Open PLFS file succeed! plfs_fd = " << plfs_fd << endl;
        char* fake_fd_filename = gen_rand_filename();
        int fake_fd = open(fake_fd_filename, O_CREAT, 0755);
        if (fake_fd >= 0) {
            dstream << "Open Fake file succeed! fake_fd = " << fake_fd << endl;
            global_fd_table[fake_fd] = std::make_pair(plfs_fd, fake_fd_filename);
            plfs_files.insert(plfs_files.begin(), std::make_pair(string_hash(path), plfs_fd));
        }
        else {
            ret = -1;
            free(fake_fd_filename);
        }
    }
    else {
        ret = -1;
    }
    return ret;
}

int _open(const char *path, int oflags, mode_t mode) {
    return 0;
}

int main() {
    const char* d = "/mnt/PLFS";
    int a = is_plfs_path(d);
    printf("%d\n",a);

    plfs_error_t plfs_error = plfs_chmod("/mnt/PLFS/1", 0x0);

    _open("/mnt/PLFS/1", O_RDWR);
    _open("test", O_RDWR);
    _open("test", O_RDWR);
    return 0;
}