#include "plfs.h"
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <map>
#include <string>
#include <iostream>
#include <unistd.h>
#include <vector>

#define DEBUG // DEBUG INFO SWITCH
#define endl std::endl
#define cout std::cout
#define FAKE_FILE_DIR "/tmp/PLFS_"

#ifndef DEBUG
#define dstream cnull
#else
#define dstream cout
#endif



// TODO LIST:
// 1. resolve absolute path and relative path
// 2. Offset issue

std::ostream cnull(0); // A temporary solution for /dev/null like stream

struct Plfs_file {
    unsigned long hashed_plfs_path;
    Plfs_fd* plfs_fd;
    int ref_num;
};

struct Fd_map {
    int fake_fd;
    char* fake_path;
    int oflags;
    Plfs_file* plfs_file;
};

std::map<int, Fd_map*> global_fd_table;
std::map<unsigned long, Plfs_file*> hashed_plfs_files;

void print_tables() {
    dstream << endl << "!! PRINT GLOBAL FD TABLE !!" << endl;
    for (std::map<int, Fd_map*>::const_iterator i=global_fd_table.begin(); i!=global_fd_table.end(); i++) {
        int key = i->first;
        Fd_map* value = i->second;
        dstream << "fake_fd: " << key << endl;
        dstream << " -> fake_path: " << value->fake_path;
        dstream << " oflags: " << value->oflags;
        dstream << " plfs_file: " << value->plfs_file << endl;
    }
    dstream << "!! PRINT PLFS FILE LIST !!" << endl;
    for (std::map<unsigned long, Plfs_file*>::const_iterator i=hashed_plfs_files.begin(); i!=hashed_plfs_files.end(); i++) {
        int key = i->first;
        Plfs_file* value = i->second;
        dstream << "hashed plfs path: " << key << endl;
        dstream << " -> plfs_fd: " << value->plfs_fd;
        dstream << "  ref_num: " << value->ref_num << endl;
    }
    dstream << "END" << endl << endl;
}

/*
  Random fake filename generator
  From stackoverflow question 440133

  This function will return a new allocated string address which
  points to an random file on disk.
*/

bool _SEEDED = false;
char* gen_rand_path() {
    if (!_SEEDED) { srand(time(0)); _SEEDED = true; }
    char* ret = (char*)malloc(sizeof(char)*23);
    char* _ret = ret + 10;
    for (int c; c=rand()%62, *(_ret++) = (c+"07="[(c+16)/26])*(_ret-ret<23););
    ret[22] = '\0';
    strncpy(ret, FAKE_FILE_DIR, strlen(FAKE_FILE_DIR));
    return ret;
}


/*
  String HASH function
  From stackoverflow question 7666509

  Since we would like to check if a specific file's status, we need to
  store the currently opened filenames in a list. The process needs hashing.
*/

unsigned long string_hash(const char *str) {
    unsigned long hash = 5381, c;
    while (c = *str++) hash = ((hash << 5) + hash) + c;
    return hash;
}


/*
  A prototype of open() w/ mode

  *** UNDER CONSTRUCTION ***
*/

int _open(const char *path, int oflags, mode_t mode) {
    dstream << "Trying to open file " << path << " ";
    Plfs_fd* plfs_fd = NULL;
    unsigned long hashed_plfs_path = string_hash(path);
    dstream << hashed_plfs_path << endl;
    bool first_open = true;
    if (hashed_plfs_files.count(hashed_plfs_path) != 0) {
        plfs_fd = hashed_plfs_files[hashed_plfs_path]->plfs_fd; // Not the first time to open the file
        dstream << "- Not first time opening; current ref_num " << hashed_plfs_files[hashed_plfs_path]->ref_num << endl;
        first_open = false;
    }

    plfs_error_t err = PLFS_EAGAIN;
    int ret;
    while (err == PLFS_EAGAIN) {
        err = plfs_open(&plfs_fd, path, oflags, getpid(), mode, NULL);
    }
    if (err == PLFS_SUCCESS) {
        dstream << "- Open PLFS file succeed! plfs_fd = " << plfs_fd << endl;
        char* fake_path = gen_rand_path();
        int fake_fd = open(fake_path, O_CREAT, mode);
        if (fake_fd >= 0) {
            dstream << "- Open Fake file succeed! fake_fd = " << fake_fd << " " << fake_path << endl;
            Fd_map* fd_map = (Fd_map*)malloc(sizeof(struct Fd_map));
            fd_map->fake_fd = fake_fd;
            fd_map->fake_path = fake_path;
            fd_map->oflags = oflags;
            if (first_open) {
                fd_map->plfs_file = (Plfs_file*)malloc(sizeof(struct Plfs_file));
                fd_map->plfs_file->hashed_plfs_path = hashed_plfs_path;
                fd_map->plfs_file->plfs_fd = plfs_fd;
                fd_map->plfs_file->ref_num = 1;
                hashed_plfs_files[hashed_plfs_path] = fd_map->plfs_file;
            }
            else {
                fd_map->plfs_file = hashed_plfs_files[hashed_plfs_path];
                fd_map->plfs_file->ref_num += 1;
            }
            global_fd_table[fake_fd] = fd_map;
            ret = fake_fd;
        }
        else {
            int t_ref = 0;
            dstream << "- Fake file open/create failed, it returns" << fake_fd << endl;
            plfs_close(plfs_fd, getpid(), getuid(), oflags, NULL, &t_ref);
            ret = -1;
            free(fake_path);
        }
    }
    else {
        dstream << "- PLFS file open failed, err = " << err << endl;
        ret = -1;
    }
    dstream << "- open() returns " << ret << endl;
    return ret;
}


int _open(const char *path, int oflags) {
    return _open(path, oflags, 0600);
}


int _close(int fd) {
    if (fd == 0 || fd == 1 || fd == 2) {
        return close(fd);
    }
    dstream << "Trying to close file. fake_fd = " << fd << endl;
    int ret;
    if (global_fd_table.count(fd) == 0) {
        dstream << "- Invalid file descriptor, return" << endl;
        ret = -1;
    }
    else {
        dstream << "- File descriptor found in global fd table" << endl;
        Fd_map* fd_map = global_fd_table[fd];
        Plfs_fd* plfs_fd = fd_map->plfs_file->plfs_fd;
        int fake_fd = fd_map->fake_fd;
        char* fake_path = fd_map->fake_path;
        int oflags = fd_map->oflags;
        Plfs_file* plfs_file = fd_map->plfs_file;
        plfs_error_t err = PLFS_EAGAIN;
        while (err == PLFS_EAGAIN) {
            err = plfs_close(plfs_fd, getpid(), getuid(), oflags, NULL, &(plfs_file->ref_num));
        }
        if (err != PLFS_SUCCESS) {
            dstream << "- Close PLFS file failed, err = " << err << endl;
            ret = -1;
        }
        else {
            dstream << "- Close PLFS file succeed!" << endl;
            ret = close(fake_fd);
            if (ret == 0) {
                dstream << "- Close fake file succeed!" << endl;
                ret = unlink(fake_path);
                if (ret == 0) {
                    dstream << "- Unlink fake file succeed!" << endl;
                    free(fake_path);
                    free(global_fd_table[fd]);
                    global_fd_table.erase(fd);
                    if (plfs_file->ref_num == 0) {
                        dstream << "- Ref = 0, delete the PLFS file" << endl;
                        hashed_plfs_files.erase(plfs_file->hashed_plfs_path);
                        free(plfs_file);
                    }
                }
                else {
                    dstream  << "- Unlink fake file failed, it returns " << ret << endl;
                }
            }
            else {
                dstream << "- Close fake file failed, it returns " << ret << endl;
            }
        }
    }
    dstream << "close() returns " << ret << endl;
    return ret;
}





// plfs_error_t plfs_read( Plfs_fd *, char *buf, size_t size, off_t offset, ssize_t *bytes_read );

ssize_t _read(int fd, void *buf, size_t nbytes) {
    dstream << "Trying to read file. fake_fd = " << fd << endl;
    ssize_t ret;
    if (global_fd_table.count(fd) == 0) {
        dstream << "- Invalid file descriptor, return" << endl;
        ret = 0;
    }
    else {
        dstream << "- File descriptor found in global fd table" << endl;
        Fd_map* fd_map = global_fd_table[fd];
        Plfs_file* plfs_file = fd_map->plfs_file;
        off_t offset = lseek(fd, 0, SEEK_CUR);
        plfs_error_t err = PLFS_EAGAIN;
        while (err == PLFS_EAGAIN) {
            err = plfs_read(plfs_file->plfs_fd, (char*)buf, nbytes, offset, &ret);
        }
        if (err == PLFS_SUCCESS) {
            lseek(fd, offset+ret, SEEK_SET);
            dstream << "- File read succeed, read " << ret << "bytes" << endl;
        }
        else {
            dstream << "- PLFS read failed, it returns " << err;
        }
    }
    return ret;
}

// plfs_error_t plfs_write( Plfs_fd *, const char *, size_t, off_t, pid_t, ssize_t *bytes_written );


ssize_t write(int fd, const void *buf, size_t nbytes) {
    return 0;
}


int main() {
    int a = _open("/mnt/PLFS/test", O_RDWR);
    int b = _open("/mnt/PLFS/test", O_RDWR);
    int c = _open("/mnt/PLFS/test", O_RDWR);
    int d = _open("/mnt/PLFS/test2", O_RDONLY);

    char buf[128];
    dstream << _read(a, buf, 4) << endl;
    dstream << buf << endl;
    dstream << _read(a, buf, 4) << endl;
    dstream << buf << endl;
    dstream << _read(b, buf, 4) << endl;
    dstream << buf << endl;
    

    return 0;
}